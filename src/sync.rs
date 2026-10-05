//! A blocking adapter: answers byte requests from `Read + Seek` sources.
//!
//! This is the only module that performs I/O, and it only uses the public
//! session API, so it could equally live in a separate crate.

use std::io::{self, Read, Seek, SeekFrom};

use crate::bytes::{to_u64, to_usize};
use crate::session::{Progress, Session};
use crate::span::SourceId;

pub struct Driver<R> {
    sources: Vec<(SourceId, R)>,
    /// Work units per poll. Smaller values return control to the caller more
    /// often; this driver simply polls again.
    pub budget: u64,
}

impl<R: Read + Seek> Default for Driver<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: Read + Seek> Driver<R> {
    pub fn new() -> Self {
        Driver {
            sources: Vec::new(),
            budget: 10_000,
        }
    }

    pub fn add(&mut self, source: SourceId, reader: R) {
        self.sources.push((source, reader));
    }

    pub fn sources(&self) -> &[(SourceId, R)] {
        &self.sources
    }

    /// Polls until the session is idle, reading whatever it asks for.
    pub fn run(&mut self, session: &mut Session) -> io::Result<()> {
        loop {
            match session.poll(self.budget) {
                Progress::Idle => return Ok(()),
                Progress::Yielded => {}
                Progress::NeedBytes(requests) => {
                    for req in requests {
                        let Some((_, reader)) =
                            self.sources.iter_mut().find(|(s, _)| *s == req.source)
                        else {
                            return Err(io::Error::new(
                                io::ErrorKind::NotFound,
                                format!("no reader for source {}", req.source.index()),
                            ));
                        };
                        reader.seek(SeekFrom::Start(req.offset))?;
                        let mut buf = vec![0; to_usize(req.len)];
                        let n = read_full(reader, &mut buf)?;
                        buf.truncate(n);
                        session.supply(req.source, req.offset, &buf);
                        if to_u64(n) < req.len {
                            session
                                .set_source_len(req.source, req.offset.saturating_add(to_u64(n)));
                        }
                    }
                }
            }
        }
    }
}

fn read_full(reader: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while let Some(rest) = buf.get_mut(filled..) {
        if rest.is_empty() {
            break;
        }
        match reader.read(rest) {
            Ok(0) => break,
            Ok(n) => filled = filled.saturating_add(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}
