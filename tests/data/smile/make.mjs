// Smile fixtures, written by smile-js (https://github.com/ngyewch/smile-js),
// a JavaScript Smile encoder. (pysmile, the Python binding, is Python 2
// only and no longer installs.)
//
//     npm install smile-js@0.10.1   # in a scratch directory
//     node tests/data/smile/make.mjs <scratch>/node_modules/smile-js/dist/smile-js.js
//
// `shared.sml`: shared property names and shared string values enabled,
// with records that repeat keys and values (back-references).
// `plain.sml`: no sharing, binary data 7-bit encoded (no raw binary).

import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const lib = await import(pathToFileURL(process.argv[2]).href);
const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, "..", "..", "fixtures", "external", "smile");

const people = ["Ada", "Grace", "Linus", "Margaret", "Ada", "Grace"].map((name, i) => ({
  name,
  team: i % 2 ? "compilers" : "kernels",
  id: i,
}));

const sample = {
  name: "fillyfoal",
  version: 3,
  small: -7,
  int32: 123456,
  negative: -2000000000,
  int64: 9007199254740991,
  big: 2n ** 80n,
  pi: 3.141592653589793,
  enabled: true,
  disabled: false,
  nothing: null,
  empty: "",
  unicode: "snow ☃ and \u{1f600}",
  long: "a string value longer than sixty-four bytes, so it is sent as long text",
  "long unicode": "☃".repeat(30),
  blob: new Uint8Array([0, 1, 2, 98, 105, 110, 97, 114, 121, 255]),
  tags: ["a", "b", 3],
  nested: { deep: { deeper: [true, false, null] }, empty: {} },
  people,
};

writeFileSync(
  join(out, "shared.sml"),
  lib.encode(sample, { sharedPropertyName: true, sharedStringValue: true, rawBinary: false }),
);
writeFileSync(
  join(out, "plain.sml"),
  lib.encode(sample, { sharedPropertyName: false, sharedStringValue: false, rawBinary: false }),
);
