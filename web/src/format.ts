import type { FieldNode, Span } from "./types";

export const HEX_BYTES_PER_ROW = 16;

/// Hues fields cycle through when their bytes are coloured, on the landing
/// page's poster and in the hex pane.
export const HUES = [75, 190, 305, 20, 250, 140, 45, 340];

export const CHUNK_SIZE = 64 * 1024;
/// Stay under the browsers' limit on an element's height.
export const MAX_SCROLL_HEIGHT = 15_000_000;

export const hex = (n: number) => `0x${n.toString(16).toUpperCase()}`;

export const hexOffset = (offset: number, width = 8) =>
  offset.toString(16).padStart(width, "0").toUpperCase();

const HEX_BYTES = Array.from({ length: 256 }, (_, b) =>
  b.toString(16).padStart(2, "0").toUpperCase(),
);
export const hexByte = (b: number) => HEX_BYTES[b];

export const printable = (b: number) =>
  b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : "·";

export const spanText = (span: Span) =>
  `${hex(span.offset)} + ${hex(span.len)}`;

/// The field as one line: `Name: value — summary`.
export function nodeLine(node: FieldNode): string {
  let line = node.name;
  if (node.value) line += `: ${node.value.text}`;
  if (node.summary) line += ` — ${node.summary}`;
  return line;
}

export function inSpan(span: Span | null, source: number, offset: number) {
  return (
    !!span &&
    span.source === source &&
    offset >= span.offset &&
    offset < span.offset + span.len
  );
}

const UNITS = ["bytes", "KiB", "MiB", "GiB", "TiB"];

export function formatSize(n: number): string {
  if (n < 1024) return `${n.toLocaleString()} ${n === 1 ? "byte" : "bytes"}`;
  let unit = 0;
  let v = n;
  while (v >= 1024 && unit < UNITS.length - 1) {
    v /= 1024;
    unit++;
  }
  return `${v < 10 ? v.toFixed(2) : v < 100 ? v.toFixed(1) : v.toFixed(0)} ${UNITS[unit]}`;
}

export type CopyFormat = "hex" | "text" | "base64" | "c";

export function formatBytes(bytes: Uint8Array, format: CopyFormat): string {
  switch (format) {
    case "hex":
      return Array.from(bytes, hexByte).join(" ");
    case "text":
      return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    case "base64": {
      let s = "";
      for (let i = 0; i < bytes.length; i += 0x8000) {
        s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
      }
      return btoa(s);
    }
    case "c": {
      const lines = [];
      for (let i = 0; i < bytes.length; i += 12) {
        lines.push(
          "  " +
            Array.from(
              bytes.subarray(i, i + 12),
              (b) => `0x${b.toString(16).padStart(2, "0")}`,
            ).join(", "),
        );
      }
      return `{\n${lines.join(",\n")}\n}`;
    }
  }
}

export const isMac =
  typeof navigator !== "undefined" &&
  /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);

export const mod = isMac ? "⌘" : "Ctrl+";
