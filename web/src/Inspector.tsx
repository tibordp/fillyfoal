import { useState } from "react";

import { hexOffset } from "./format";

/// The bytes at the hex cursor read as the common scalar types.
export function Inspector({
  offset,
  bytes,
  selection,
}: {
  offset: number;
  bytes: Uint8Array;
  selection: number;
}) {
  const [little, setLittle] = useState(true);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const has = (n: number) => bytes.length >= n;
  const rows: [string, string | null][] = [
    ["u8 / i8", has(1) ? `${view.getUint8(0)} / ${view.getInt8(0)}` : null],
    ["u16 / i16", has(2) ? `${view.getUint16(0, little)} / ${view.getInt16(0, little)}` : null],
    ["u32", has(4) ? view.getUint32(0, little).toLocaleString() : null],
    ["i32", has(4) ? view.getInt32(0, little).toLocaleString() : null],
    ["u64", has(8) ? view.getBigUint64(0, little).toLocaleString() : null],
    ["f32", has(4) ? formatFloat(view.getFloat32(0, little)) : null],
    ["f64", has(8) ? formatFloat(view.getFloat64(0, little)) : null],
    ["Unix time", has(4) ? unixTime(view.getUint32(0, little)) : null],
    ["Binary", has(1) ? view.getUint8(0).toString(2).padStart(8, "0") : null],
  ];
  return (
    <section className="inspector" aria-label="Data at the cursor">
      <div className="inspector-head">
        <span>
          At <span className="mono">{hexOffset(offset)}</span>
          {selection > 1 && <span className="muted"> · {selection.toLocaleString()} bytes selected</span>}
        </span>
        <div className="segmented" role="group" aria-label="Byte order">
          <button type="button" aria-pressed={little} onClick={() => setLittle(true)}>
            LE
          </button>
          <button type="button" aria-pressed={!little} onClick={() => setLittle(false)}>
            BE
          </button>
        </div>
      </div>
      <dl className="inspector-grid">
        {rows.map(([label, value]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd className="mono">{value ?? "—"}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

function formatFloat(f: number) {
  if (!Number.isFinite(f)) return String(f);
  const abs = Math.abs(f);
  return abs !== 0 && (abs < 1e-6 || abs >= 1e15) ? f.toExponential(6) : String(Number(f.toPrecision(9)));
}

function unixTime(seconds: number) {
  // Only plausible dates; anything else is just a number.
  if (seconds < 315_532_800 || seconds > 4_102_444_800) return null;
  return new Date(seconds * 1000).toISOString().replace("T", " ").replace(".000Z", " UTC");
}
