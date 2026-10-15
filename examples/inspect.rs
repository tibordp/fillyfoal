//! Inspect a file from the command line.
//!
//! ```text
//! cargo run --example inspect -- FILE [--depth N] [--page N] [--path 3.0.1] [--chunk BYTES] [--as FORMAT] [--progress]
//! ```
//!
//! `--path` selects a node by child indices (expanding along the way);
//! `--depth` and `--page` control how much of its subtree is expanded.
//! `--as` dissects the file as the named format ("inspect as") instead of
//! identifying it.
//! `--progress` prints how far the expansion being driven has got to
//! stderr while it runs (at most twice a second), with the streams it is
//! waiting on being decoded.
//! The last line reports how much of the file was actually read.

use std::error::Error;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::time::{Duration, Instant};

use fillyfoal::sync::Driver;
use fillyfoal::{Activity, Limits, NodeId, Session, Span, formats, render};

struct Options {
    file: String,
    depth: usize,
    page: u64,
    path: Vec<usize>,
    chunk: u64,
    format: Option<&'static formats::Format>,
    progress: bool,
}

fn parse_args() -> Result<Options, Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let mut options = Options {
        file: String::new(),
        depth: 1,
        page: 50,
        path: Vec::new(),
        chunk: 4096,
        format: None,
        progress: false,
    };
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "--depth" => options.depth = value()?.parse()?,
            "--page" => options.page = value()?.parse()?,
            "--chunk" => options.chunk = value()?.parse()?,
            "--progress" => options.progress = true,
            "--as" => {
                let name = value()?;
                options.format =
                    Some(formats::by_name(&name).ok_or_else(|| format!("unknown format {name}"))?);
            }
            "--path" => {
                options.path = value()?
                    .split('.')
                    .map(str::parse)
                    .collect::<Result<_, _>>()?
            }
            _ if options.file.is_empty() => options.file = arg,
            _ => return Err(format!("unexpected argument {arg}").into()),
        }
    }
    if options.file.is_empty() {
        return Err(
            "usage: inspect FILE [--depth N] [--page N] [--path 3.0.1] [--chunk BYTES] [--as FORMAT] [--progress]".into(),
        );
    }
    Ok(options)
}

/// Counts what the host actually reads, to make laziness visible.
struct Counting {
    file: File,
    bytes: u64,
    reads: u64,
}

impl Read for Counting {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.file.read(buf)?;
        self.bytes = self.bytes.saturating_add(n as u64);
        self.reads = self.reads.saturating_add(1);
        Ok(n)
    }
}

impl Seek for Counting {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.file.seek(pos)
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let options = parse_args()?;
    let file = File::open(&options.file)?;
    let len = file.metadata()?.len();

    let started = Instant::now();
    let mut session = Session::new(Limits {
        chunk_size: options.chunk,
        ..Limits::default()
    });
    let (source, root) = match options.format {
        Some(format) => {
            let root = session.open_as(options.file.clone(), len, format);
            let source = session
                .node(root)
                .and_then(|n| n.span)
                .map(|s| s.source)
                .ok_or("no source")?;
            (source, root)
        }
        None => {
            let source = session.add_source(len);
            let root = session.add_root(formats::root(
                options.file.clone(),
                Span::new(source, 0, len),
            ));
            (source, root)
        }
    };
    let mut driver = Driver::new();
    driver.add(
        source,
        Counting {
            file,
            bytes: 0,
            reads: 0,
        },
    );

    let mut host = Host {
        driver,
        meter: options.progress.then(Meter::new),
    };
    let mut focus = root;
    for &index in &options.path {
        session.expand(focus, index.saturating_add(1) as u64);
        host.run(&mut session, focus)?;
        let children = session.children(focus).ok_or("node vanished")?;
        focus = *children
            .ids
            .get(index)
            .ok_or_else(|| format!("no child {index} (have {})", children.ids.len()))?;
    }
    explore(&mut session, &mut host, focus, options.depth, options.page)?;

    print!("{}", render::tree(&session, focus));
    let elapsed = started.elapsed();
    if let Some((_, counting)) = host.driver.sources().first() {
        eprintln!(
            "read {} of {} bytes in {} requests, {:.1} ms",
            counting.bytes,
            len,
            counting.reads,
            elapsed.as_secs_f64() * 1000.0
        );
    }
    Ok(())
}

/// Drives the session, showing progress if asked to.
struct Host {
    driver: Driver<Counting>,
    meter: Option<Meter>,
}

impl Host {
    /// Polls until idle; `id` is the node whose expansion is being waited
    /// for.
    fn run(&mut self, session: &mut Session, id: NodeId) -> io::Result<()> {
        while !self.driver.step(session)? {
            if let Some(meter) = &mut self.meter {
                meter.show(session, id);
            }
        }
        Ok(())
    }
}

/// Prints progress to stderr, at most every [`Meter::EVERY`].
struct Meter {
    started: Instant,
    last: Option<Instant>,
}

impl Meter {
    const EVERY: Duration = Duration::from_millis(500);

    fn new() -> Self {
        Meter {
            started: Instant::now(),
            last: None,
        }
    }

    fn show(&mut self, session: &Session, id: NodeId) {
        let now = Instant::now();
        if self
            .last
            .is_some_and(|t| now.duration_since(t) < Self::EVERY)
        {
            return;
        }
        self.last = Some(now);
        let Some(activity) = session.activity(id) else {
            return;
        };
        let name = session.node(id).map_or("?", |n| &n.name);
        eprintln!(
            "[{:6.1}s] {name}: {}",
            now.duration_since(self.started).as_secs_f64(),
            describe(&activity)
        );
    }
}

/// One line: the estimate, then where it comes from.
fn describe(activity: &Activity) -> String {
    let mut line = match activity.estimate() {
        Some((done, total)) => format!("{} ({done} of {total})", percent(done, total)),
        None => "no estimate".to_owned(),
    };
    if let Some((done, total)) = activity.reported {
        line.push_str(&format!("; reported {done}/{total}"));
    }
    for d in &activity.decoding {
        let len = d.len.map_or_else(|| "?".to_owned(), |l| l.to_string());
        let unsure = if d.encoded_len_known { "" } else { "<=" };
        line.push_str(&format!(
            "; {} #{}: in {}/{unsure}{}, out {} -> {} of {len}",
            d.codec,
            d.source.index(),
            d.consumed,
            d.encoded_len,
            d.front,
            d.target,
        ));
    }
    if activity.decoding.is_empty()
        && let Some(r) = &activity.reading
    {
        line.push_str(&format!("; read #{} to {}", r.source.index(), r.end));
    }
    if let Some(wait) = activity.wait {
        line.push_str(&format!(" [{wait:?}]"));
    }
    line
}

fn percent(done: u64, total: u64) -> String {
    if total == 0 {
        return "100%".to_owned();
    }
    format!("{:.1}%", done as f64 * 100.0 / total as f64)
}

fn explore(
    session: &mut Session,
    host: &mut Host,
    id: NodeId,
    depth: usize,
    page: u64,
) -> io::Result<()> {
    if depth == 0 {
        return Ok(());
    }
    session.expand(id, page);
    host.run(session, id)?;
    let children: Vec<NodeId> = session
        .children(id)
        .map(|c| c.ids.to_vec())
        .unwrap_or_default();
    for child in children {
        explore(session, host, child, depth.saturating_sub(1), page)?;
    }
    Ok(())
}
