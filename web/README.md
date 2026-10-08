# fillyfoal in the browser

A web app for looking inside files: fillyfoal compiled to WebAssembly, with a
tree of fields on one side and the bytes they came from on the other. It is
entirely local. The page hands the file to a worker, and the worker reads only
the byte ranges the dissectors ask for, with `Blob.slice()`, so a disk image of
several gigabytes opens as quickly as a small PNG.

## Layout

- `wasm/`: the bindings (`fillyfoal-wasm`), a thin `wasm-bindgen` layer over
  `Session`. Nodes go out as JSON under small integer keys, and the session is
  driven one budgeted step at a time. It is its own Cargo workspace, so the
  library itself stays free of `wasm-bindgen` and `serde`.
- `src/worker.ts`: owns the dissections. It drives expansions, answers
  `NeedBytes` from the `Blob`, and between time slices lets other requests in,
  so a stop or a click on another node never waits behind a long expansion.
  This is the browser's counterpart of newt's `viewer/dissect.rs`.
- `src/Explorer.tsx`: the tree, hex pane, details, Dissect As, passwords,
  go to offset, and so on.

## Building

You need `wasm-pack`, the `wasm32-unknown-unknown` target and Node.

```bash
npm install
npm run wasm    # builds wasm/ into src/wasm-pkg (a few minutes: fat LTO)
npm run dev     # or: npm run build, then serve dist/ from anywhere
```

`dist/` is a static site with relative URLs. It needs no server-side
anything, but it must be served over HTTP(S), because module workers do not
load from `file://`.

Every push to `main` publishes it to
[tibordp.github.io/fillyfoal](https://tibordp.github.io/fillyfoal/)
(`.github/workflows/pages.yml`).

For development, `?url=<path>` opens a file fetched from the given URL, for
example `/.samples/bundle.zip` when the file is in the gitignored
`web/.samples/` folder.
