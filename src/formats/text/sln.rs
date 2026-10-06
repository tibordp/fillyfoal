//! Visual Studio solution files: header, projects (with their kind from the
//! project type GUID) and global sections.

use crate::cx::Cx;
use crate::error::Result;
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;

use super::encoding::prepare;
use super::piece::Piece;
use super::scan::Lines;
use super::{plural, probe, text_node};

pub static FORMAT: Format = Format {
    name: "vs-solution",
    title: "Visual Studio solution",
    extensions: &["sln"],
    mime: "text/plain",
    probe: Probe::Custom(|h| {
        let head = probe::head(h);
        let top = head.get(..head.len().min(512)).unwrap_or_default();
        probe::contains(
            top,
            b"Microsoft Visual Studio Solution File, Format Version",
        )
    }),
    dissect: crate::expander!(dissect: Input),
};

/// Project kinds by type GUID.
fn project_kind(guid: &str) -> &'static str {
    match guid.to_ascii_uppercase().trim_matches(['{', '}']) {
        "FAE04EC0-301F-11D3-BF4B-00C04F79EFBC" => "C#",
        "9A19103F-16F7-4668-BE54-9A1E7A4F7556" => "C# (SDK)",
        "8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942" => "C++",
        "F184B08F-C81C-45F6-A57F-5ABD9991F28F" => "VB.NET",
        "778DAE3C-4631-46EA-AA77-85C1314464D9" => "VB.NET (SDK)",
        "F2A71F9B-5D33-465A-A702-920D77279786" => "F#",
        "6EC3EE1D-3C4E-46DD-8F32-0CC8E7565705" => "F# (SDK)",
        "2150E333-8FDC-42A3-9474-1A3956D46DE8" => "Solution folder",
        "E24C65DC-7377-472B-9ABA-BC803B73C61A" => "Web site",
        "888888A0-9F3D-457C-B088-3A5042F75D52" => "Python",
        "54435603-DBB4-11D2-8724-00A0C9A8B90C" => "Setup",
        "930C7802-8A8C-48F9-8165-68863BCCD9DD" => "WiX",
        "13B669BE-BB05-4DDF-9536-439F39A36129" => "MSBuild",
        "A9ACE9BB-CECE-4E62-9AA4-C7E7C5BD2124" => "Database",
        _ => "project",
    }
}

/// Quoted strings in `piece`.
fn quoted(p: Piece<'_>) -> Vec<Piece<'_>> {
    p.split(b'"').skip(1).step_by(2).collect()
}

#[derive(Clone, Debug)]
struct Block {
    span: Span,
}

async fn block(cx: Cx, b: Block) -> Result<()> {
    let mut lines = Lines::new(&cx, b.span);
    let mut first = true;
    while let Some(line) = lines.next().await? {
        let t = line.piece().trim();
        if first {
            first = false;
            if t.starts_with(b"Project(") {
                let q = quoted(t);
                let names = ["Type", "Name", "Path", "GUID"];
                for (name, value) in names.iter().zip(q.iter()) {
                    let mut node = text_node(*name, value.span(), &value.text());
                    if *name == "Type" {
                        node = node.summary(project_kind(&value.text()));
                    }
                    cx.push(node).await;
                }
            }
            continue;
        }
        if t.is_empty() || t.starts_with(b"End") {
            continue;
        }
        let node = match t.split_once(b'=') {
            Some((k, v)) => text_node(k.trim().text(), v.trim().span(), &v.trim().text()),
            None => text_node("Line", t.span(), &t.text()),
        };
        cx.push(node).await;
    }
    Ok(())
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let span = prepared.span;
    let mut lines = Lines::new(&cx, span);
    let mut projects = 0u64;
    let mut version = None;
    // (start, name, summary, end keyword)
    let mut open: Option<(u64, String, String, &'static [u8])> = None;
    while let Some(line) = lines.next().await? {
        let t = line.piece().trim();
        if let Some((start, name, summary, end)) = &open {
            if t.starts_with(end) && !t.starts_with(b"EndProjectSection") {
                let s = span.sub(*start, line.next.saturating_sub(*start));
                let mut node = Node::new(name.clone())
                    .span(s)
                    .lazy(block, Block { span: s });
                if !summary.is_empty() {
                    node = node.summary(summary.clone());
                }
                cx.push(node).await;
                open = None;
            }
            continue;
        }
        if t.starts_with(b"Project(") {
            let q = quoted(t);
            let kind = q
                .first()
                .map(|g| project_kind(&g.text()))
                .unwrap_or("project");
            let name = q.get(1).map_or_else(|| "Project".to_owned(), Piece::text);
            let path = q.get(2).map(Piece::text).unwrap_or_default();
            projects = projects.saturating_add(1);
            open = Some((line.start, name, format!("{kind}: {path}"), b"EndProject"));
        } else if let Some(rest) = t.strip_prefix(b"GlobalSection(") {
            let name = rest.split_once(b')').map_or(rest, |(n, _)| n).text();
            open = Some((
                line.start,
                format!("GlobalSection {name}"),
                String::new(),
                b"EndGlobalSection",
            ));
        } else if t.is_empty() || t.bytes() == b"Global" || t.bytes() == b"EndGlobal" {
            continue;
        } else if let Some((k, v)) = t.split_once(b'=') {
            if k.trim().bytes() == b"VisualStudioVersion" {
                version = Some(v.trim().text());
            }
            cx.push(text_node(
                k.trim().text(),
                v.trim().span(),
                &v.trim().text(),
            ))
            .await;
        } else {
            cx.push(text_node("Header", t.span(), &t.text())).await;
        }
    }
    let mut summary = format!(
        "Visual Studio solution, {}",
        plural(projects, "project", "projects")
    );
    if let Some(v) = version {
        summary = format!("{summary} (Visual Studio {v})");
    }
    cx.annotate(summary);
    Ok(())
}
