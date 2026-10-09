//! One-line summaries of Exif data: camera, lens, exposure, date, position.

use crate::cx::Cx;

use super::maker::Note;
use super::render::{dms, exposure_time, fnumber, position, trim};
use super::{Ifd, Num, Tiff, ascii_of, camera_of, first_value, open_maker, read_ifd, values_of};

/// What a photo's metadata says about how it was taken.
#[derive(Default)]
pub struct Shot {
    camera: Option<String>,
    /// Shortest and longest focal length of the lens, in mm.
    lens: Option<(f64, f64)>,
    focal: Option<f64>,
    fnumber: Option<f64>,
    exposure: Option<f64>,
    iso: Option<u64>,
    date: Option<String>,
    position: Option<(f64, f64)>,
}

impl Shot {
    /// "Canon EOS R5, 24-105mm at 50mm, f/4, 1/250 s, ISO 200,
    /// 2024-05-01 12:00, 48.85823° N, 2.29450° E".
    pub fn describe(&self, camera: bool) -> String {
        let mut parts = Vec::new();
        if camera && let Some(c) = &self.camera {
            parts.push(c.clone());
        }
        let mm = |v: f64| format!("{}mm", trim(v, 1));
        match (self.lens, self.focal) {
            (Some((min, max)), Some(f)) if max - min >= 0.5 => {
                parts.push(format!("{}-{} at {}", trim(min, 1), mm(max), mm(f)));
            }
            (Some((min, max)), None) if max - min >= 0.5 => {
                parts.push(format!("{}-{}", trim(min, 1), mm(max)));
            }
            (_, Some(f)) => parts.push(mm(f)),
            (Some((min, _)), None) => parts.push(mm(min)),
            (None, None) => {}
        }
        if let Some(f) = self.fnumber {
            parts.push(fnumber(f));
        }
        if let Some(t) = self.exposure {
            parts.push(exposure_time(t));
        }
        if let Some(iso) = self.iso {
            parts.push(format!("ISO {iso}"));
        }
        if let Some(d) = &self.date {
            parts.push(d.clone());
        }
        if let Some((lat, lon)) = self.position {
            parts.push(position(lat, lon));
        }
        parts.join(", ")
    }
}

/// "2024:05:01 12:00:00" → "2024-05-01 12:00".
fn date(text: &str) -> Option<String> {
    let text = text.trim();
    let (day, time) = text.split_once(' ').unwrap_or((text, ""));
    if day.len() != 10 || day.starts_with("0000") || day.chars().all(|c| c == ' ' || c == ':') {
        return None;
    }
    let day = day.replace(':', "-");
    let time = time.get(..5).unwrap_or(time);
    Some(if time.is_empty() {
        day
    } else {
        format!("{day} {time}")
    })
}

/// The value of `tag` in the first of `ifds` that has it.
async fn pick(cx: &Cx, t: Tiff, ifds: &[Option<&Ifd>], tag: u16) -> Option<Num> {
    for ifd in ifds.iter().flatten() {
        if let Some(v) = first_value(cx, t, ifd, tag).await {
            return Some(v);
        }
    }
    None
}

/// The IFD a pointer tag of `ifd` leads to.
async fn follow(cx: &Cx, t: Tiff, ifd: &Ifd, tag: u16) -> Option<Ifd> {
    let offset = first_value(cx, t, ifd, tag).await?.as_u64()?;
    read_ifd(cx, t, offset).await.ok()
}

pub async fn shot(cx: &Cx, t: Tiff, ifd0: &Ifd) -> Shot {
    let exif = follow(cx, t, ifd0, 0x8769).await;
    let ifds = [exif.as_ref(), Some(ifd0)];
    let real = |v: Option<Num>| v.and_then(Num::f64).filter(|x| *x > 0.0);
    let mut shot = Shot {
        camera: camera_of(cx, ifd0).await,
        ..Shot::default()
    };
    shot.focal = real(pick(cx, t, &ifds, 0x920a).await);
    shot.fnumber = match real(pick(cx, t, &ifds, 0x829d).await) {
        Some(f) => Some(f),
        None => real(pick(cx, t, &ifds, 0x9202).await).map(|apex| 2f64.powf(apex / 2.0)),
    };
    shot.exposure = match real(pick(cx, t, &ifds, 0x829a).await) {
        Some(e) => Some(e),
        None => pick(cx, t, &ifds, 0x9201)
            .await
            .and_then(Num::f64)
            .map(|apex| 2f64.powf(-apex)),
    };
    shot.iso = pick(cx, t, &ifds, 0x8827)
        .await
        .and_then(Num::as_u64)
        .filter(|&v| v > 0);
    for (ifd, tag) in [(exif.as_ref(), 0x9003), (Some(ifd0), 0x0132)] {
        if shot.date.is_none()
            && let Some(e) = ifd.and_then(|i| i.find(tag))
            && let Some(text) = ascii_of(cx, e, 32).await
        {
            shot.date = date(&text);
        }
    }
    for (ifd, tag) in [(exif.as_ref(), 0xa432), (Some(ifd0), 0xc630)] {
        if shot.lens.is_none()
            && let Some(e) = ifd.and_then(|i| i.find(tag))
        {
            let v = values_of(cx, t, e, 2).await;
            if let Some(min) = v.first().and_then(|n| n.f64()).filter(|x| *x > 0.0) {
                let max = v.get(1).and_then(|n| n.f64()).unwrap_or(min);
                shot.lens = Some((min, max));
            }
        }
    }
    if shot.lens.is_none()
        && let Some(exif) = &exif
    {
        shot.lens = maker_lens(cx, t, exif).await;
    }
    if let Some(gps) = follow(cx, t, ifd0, 0x8825).await {
        shot.position = coordinates(cx, t, &gps).await;
    }
    shot
}

/// The lens's focal range from the maker note, for makers that record it
/// there rather than in LensSpecification.
async fn maker_lens(cx: &Cx, t: Tiff, exif: &Ifd) -> Option<(f64, f64)> {
    let e = exif.find(0x927c)?;
    let (layout, mt, offset) = open_maker(cx, t, e).await?;
    let ifd = read_ifd(cx, mt, offset).await.ok()?;
    let range = |min: f64, max: f64| (min > 0.0 && max >= min).then_some((min, max));
    match layout.note {
        Note::Canon => {
            let settings = ifd.find(0x0001)?;
            let v = values_of(cx, mt, settings, 26).await;
            let max = v.get(23)?.f64()?;
            let min = v.get(24)?.f64()?;
            let units = v
                .get(25)
                .and_then(|n| n.f64())
                .filter(|u| *u > 0.0)
                .unwrap_or(1.0);
            range(min / units, max / units)
        }
        Note::Nikon => {
            let lens = ifd.find(0x0084)?;
            let v = values_of(cx, mt, lens, 2).await;
            range(v.first()?.f64()?, v.get(1)?.f64()?)
        }
        Note::Fujifilm => {
            let min = first_value(cx, mt, &ifd, 0x1404).await?.f64()?;
            let max = first_value(cx, mt, &ifd, 0x1405).await?.f64()?;
            range(min, max)
        }
        _ => None,
    }
}

/// Latitude and longitude from a GPS IFD.
async fn coordinates(cx: &Cx, t: Tiff, gps: &Ifd) -> Option<(f64, f64)> {
    let part = |value: u16, reference: u16| async move {
        let e = gps.find(value)?;
        let v = values_of(cx, t, e, 3).await;
        let r = match gps.find(reference) {
            Some(r) => cx.read_avail(r.data.sub(0, 1)).await.ok()?.first().copied(),
            None => None,
        };
        Some(dms(&v, r)?.0)
    };
    Some((part(0x02, 0x01).await?, part(0x04, 0x03).await?))
}

/// "48.85823° N, 2.29450° E, 35 m, 2024:05:01 12:34:56 UTC".
pub async fn gps(cx: &Cx, t: Tiff, gps: &Ifd) -> Option<String> {
    let mut parts = Vec::new();
    if let Some((lat, lon)) = coordinates(cx, t, gps).await {
        parts.push(position(lat, lon));
    }
    if let Some(alt) = first_value(cx, t, gps, 0x06).await.and_then(Num::f64) {
        let below = matches!(
            first_value(cx, t, gps, 0x05).await.and_then(Num::as_u64),
            Some(1 | 3)
        );
        parts.push(format!(
            "{}{} m",
            if below { "-" } else { "" },
            trim(alt, 1)
        ));
    }
    let day = match gps.find(0x1d) {
        Some(e) => ascii_of(cx, e, 16).await,
        None => None,
    };
    let time = match gps.find(0x07) {
        Some(e) => {
            let v = values_of(cx, t, e, 3).await;
            let get = |i: usize| v.get(i).and_then(|n| n.f64());
            match (get(0), get(1), get(2)) {
                (Some(h), Some(m), Some(s)) => Some(format!(
                    "{:0>2}:{:0>2}:{:0>2}",
                    trim(h, 0),
                    trim(m, 0),
                    trim(s.floor(), 0)
                )),
                _ => None,
            }
        }
        None => None,
    };
    match (day, time) {
        (Some(d), Some(clock)) => parts.push(format!("{} {clock} UTC", d.replace(':', "-"))),
        (Some(d), None) => parts.push(d.replace(':', "-")),
        (None, Some(clock)) => parts.push(format!("{clock} UTC")),
        (None, None) => {}
    }
    (!parts.is_empty()).then(|| parts.join(", "))
}

/// "50mm, f/4, 1/250 s, ISO 200, 2024-05-01 12:00" for an Exif IFD.
pub async fn exif_ifd(cx: &Cx, t: Tiff, exif: &Ifd) -> Option<String> {
    let ifds = [Some(exif)];
    let real = |v: Option<Num>| v.and_then(Num::f64).filter(|x| *x > 0.0);
    let mut shot = Shot {
        focal: real(pick(cx, t, &ifds, 0x920a).await),
        fnumber: real(pick(cx, t, &ifds, 0x829d).await),
        exposure: real(pick(cx, t, &ifds, 0x829a).await),
        iso: pick(cx, t, &ifds, 0x8827)
            .await
            .and_then(Num::as_u64)
            .filter(|&v| v > 0),
        ..Shot::default()
    };
    if let Some(e) = exif.find(0x9003)
        && let Some(text) = ascii_of(cx, e, 32).await
    {
        shot.date = date(&text);
    }
    let text = shot.describe(false);
    (!text.is_empty()).then_some(text)
}
