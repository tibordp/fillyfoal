//! Inspect a file from the command line.
//!
//! ```text
//! cargo run --example inspect -- FILE [--depth N] [--page N] [--path 3.0.1] [--chunk BYTES]
//! ```
//!
//! `--path` selects a node by child indices (expanding along the way);
//! `--depth` and `--page` control how much of its subtree is expanded.
//! The last line reports how much of the file was actually read.

use std::error::Error;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::time::Instant;

use fillyfoal::sync::Driver;
use fillyfoal::{Limits, NodeId, Session, Span, formats, render};

struct Options {
    file: String,
    depth: usize,
    page: u64,
    path: Vec<usize>,
    chunk: u64,
}

fn parse_args() -> Result<Options, Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let mut options = Options {
        file: String::new(),
        depth: 1,
        page: 50,
        path: Vec::new(),
        chunk: 4096,
    };
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "--depth" => options.depth = value()?.parse()?,
            "--page" => options.page = value()?.parse()?,
            "--chunk" => options.chunk = value()?.parse()?,
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
            "usage: inspect FILE [--depth N] [--page N] [--path 3.0.1] [--chunk BYTES]".into(),
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
    let source = session.add_source(len);
    let root = session.add_root(formats::root(options.file.clone(), Span::new(source, 0, len)));
    let mut driver = Driver::new();
    driver.add(
        source,
        Counting {
            file,
            bytes: 0,
            reads: 0,
        },
    );

    let mut focus = root;
    for &index in &options.path {
        session.expand(focus, index.saturating_add(1) as u64);
        driver.run(&mut session)?;
        let children = session.children(focus).ok_or("node vanished")?;
        focus = *children
            .ids
            .get(index)
            .ok_or_else(|| format!("no child {index} (have {})", children.ids.len()))?;
    }
    explore(&mut session, &mut driver, focus, options.depth, options.page)?;

    print!("{}", render::tree(&session, focus));
    let elapsed = started.elapsed();
    if let Some((_, counting)) = driver.sources().first() {
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

fn explore(
    session: &mut Session,
    driver: &mut Driver<Counting>,
    id: NodeId,
    depth: usize,
    page: u64,
) -> io::Result<()> {
    if depth == 0 {
        return Ok(());
    }
    session.expand(id, page);
    driver.run(session)?;
    let children: Vec<NodeId> = session
        .children(id)
        .map(|c| c.ids.to_vec())
        .unwrap_or_default();
    for child in children {
        explore(session, driver, child, depth.saturating_sub(1), page)?;
    }
    Ok(())
}
