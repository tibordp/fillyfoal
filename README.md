# fillyfoal

Lazy, sans-I/O structural dissection of files — Wireshark-style dissectors,
but for files. Built for the F3 viewer of an orthodox file manager: open a
file and get a tree of typed fields with byte spans instead of a hex dump;
expand deeper to pay for more work.

- **Sans-I/O core:** the host supplies bytes on request; no executor, no
  threads, no file handles. A blocking adapter is in `sync`.
- **Lazy and paged:** nothing below an unexpanded node is read or decoded;
  collections are enumerated in pages.
- **Byte provenance:** every field has a span; decompressed and fragmented
  data live in derived sources that map back to the file.
- **Partial results:** truncated or malformed input keeps whatever structure
  was decoded, with diagnostics where things went wrong.
- **Composable:** archives, containers and resources hand embedded content to
  format detection, recursively.
- **100% safe Rust, no runtime dependencies,** hostile-input hardened (no
  panics, bounded memory and work), tested by snapshot plus truncation and
  mutation sweeps over every fixture.

About 1,500 formats are recognised, from executables, archives, disk
images and filesystems to media, documents, databases, game assets, ROMs,
scientific data, forensic artifacts and logs.

```sh
cargo run --example inspect -- path/to/file --depth 2
cargo run --example formats          # list supported formats
```

See `DESIGN.md` for the architecture and `docs/DISSECTORS.md` for how to
write a dissector.
