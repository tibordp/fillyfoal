import { useEffect, useMemo, useRef, useState } from "react";

import { client } from "./client";
import type { Format } from "./types";

/// What Dissect As chooses the format of: the file, or a file within it.
export type PickerTarget = {
  /// Its name, whose extension suggests formats.
  name: string;
  /// The chosen format's name; null while it's identified.
  current: string | null;
};

const IDENTIFY = "(identify)";
const EXACT = 1000;

/// A subsequence match of `query` in `text`, scored by how early and how
/// contiguous it is; the matched positions for highlighting.
function fuzzy(query: string, text: string) {
  const q = query.toLowerCase();
  const t = text.toLowerCase();
  const plain = t.indexOf(q);
  if (plain >= 0) {
    const positions = Array.from({ length: q.length }, (_, i) => plain + i);
    const wordStart = plain === 0 || /\W/.test(t[plain - 1]);
    return { score: 500 - plain + (wordStart ? 200 : 0), positions };
  }
  const positions: number[] = [];
  let from = 0;
  for (const c of q) {
    const at = t.indexOf(c, from);
    if (at < 0) return null;
    positions.push(at);
    from = at + 1;
  }
  const spread = positions[positions.length - 1] - positions[0];
  return { score: 100 - spread, positions };
}

function rank(format: Format, filter: string) {
  const query = filter.toLowerCase().replace(/^\./, "");
  if (
    format.name === query ||
    format.extensions.some((e) => e.toLowerCase() === query)
  ) {
    return { score: EXACT, positions: [] };
  }
  const title = fuzzy(filter, format.title);
  const name = fuzzy(filter, format.name);
  if (!title && !name) return null;
  return {
    score: Math.max(title?.score ?? 0, name?.score ?? 0),
    positions: title?.positions ?? [],
  };
}

function Highlight({ text, positions }: { text: string; positions: number[] }) {
  if (positions.length === 0) return <>{text}</>;
  const set = new Set(positions);
  return (
    <>
      {Array.from(text, (c, i) =>
        set.has(i) ? (
          <mark key={i}>{c}</mark>
        ) : (
          <span key={i}>{c}</span>
        ),
      )}
    </>
  );
}

/// Pick the format a file (or a file within it) is dissected as: those
/// listing its extension first, then every other, filtered as you type.
export function FormatPicker({
  target,
  onPick,
  onClose,
}: {
  target: PickerTarget;
  onPick: (format: string | null) => void;
  onClose: () => void;
}) {
  const [formats, setFormats] = useState<Format[] | null>(null);
  const [filter, setFilter] = useState("");
  const [selected, setSelected] = useState(target.current ?? IDENTIFY);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let cancelled = false;
    client.call("formats", { name: target.name }).then((list) => {
      if (!cancelled) setFormats(list);
    });
    return () => {
      cancelled = true;
    };
  }, [target.name]);

  type Entry = { value: string; format: Format | null; positions: number[]; group?: string };

  const entries: Entry[] = useMemo(() => {
    if (!formats) return [];
    if (!filter) {
      const suggested = formats.filter((f) => f.suggested);
      return [
        { value: IDENTIFY, format: null, positions: [] },
        ...suggested.map((format, i) => ({
          value: format.name,
          format,
          positions: [],
          group: i === 0 ? "Matching the extension" : undefined,
        })),
        ...formats
          .filter((f) => !f.suggested)
          .map((format, i) => ({
            value: format.name,
            format,
            positions: [],
            group: i === 0 ? "All formats" : undefined,
          })),
      ];
    }
    return formats
      .map((format) => ({ format, r: rank(format, filter) }))
      .filter((m) => m.r !== null)
      .sort(
        (a, b) =>
          b.r!.score - a.r!.score ||
          Number(b.format.suggested) - Number(a.format.suggested),
      )
      .map(({ format, r }) => ({
        value: format.name,
        format,
        positions: r!.positions,
      }));
  }, [formats, filter]);

  // A filter that drops the selected entry selects the best match.
  useEffect(() => {
    if (filter && entries.length > 0) setSelected(entries[0].value);
  }, [filter, entries]);

  useEffect(() => {
    listRef.current
      ?.querySelector(`[data-value="${CSS.escape(selected)}"]`)
      ?.scrollIntoView({ block: "nearest" });
  }, [selected, entries]);

  const index = entries.findIndex((e) => e.value === selected);
  const move = (by: number) => {
    if (entries.length === 0) return;
    const next = Math.max(0, Math.min(entries.length - 1, index + by));
    setSelected(entries[next].value);
  };

  const pick = (value: string) => onPick(value === IDENTIFY ? null : value);

  return (
    <div className="overlay" onPointerDown={onClose}>
      <div
        className="palette"
        role="dialog"
        aria-label="Dissect as"
        onPointerDown={(e) => e.stopPropagation()}
      >
        <input
          className="palette-input"
          autoFocus
          value={filter}
          spellCheck={false}
          autoComplete="off"
          placeholder={`Dissect “${target.name}” as… (name or extension)`}
          onChange={(e) => setFilter(e.target.value)}
          onKeyDown={(e) => {
            switch (e.key) {
              case "ArrowDown":
                move(1);
                break;
              case "ArrowUp":
                move(-1);
                break;
              case "PageDown":
                move(10);
                break;
              case "PageUp":
                move(-10);
                break;
              case "Enter":
                if (index >= 0) pick(entries[index].value);
                break;
              case "Escape":
                onClose();
                break;
              default:
                return;
            }
            e.preventDefault();
            e.stopPropagation();
          }}
        />
        <div className="palette-list" ref={listRef} role="listbox">
          {formats === null && <div className="palette-empty">Loading formats…</div>}
          {formats !== null && entries.length === 0 && (
            <div className="palette-empty">No formats found</div>
          )}
          {entries.map((entry) => (
            <div key={entry.value}>
              {entry.group && <div className="palette-group">{entry.group}</div>}
              <div
                className="palette-item"
                role="option"
                data-value={entry.value}
                aria-selected={entry.value === selected}
                onPointerMove={() => setSelected(entry.value)}
                onClick={() => pick(entry.value)}
              >
                <span className="palette-check">
                  {(entry.format?.name ?? null) === target.current ||
                  (entry.value === IDENTIFY && target.current === null)
                    ? "✓"
                    : ""}
                </span>
                <span className="palette-title">
                  {entry.format ? (
                    <Highlight text={entry.format.title} positions={entry.positions} />
                  ) : (
                    "Identify automatically"
                  )}
                </span>
                {entry.format && (
                  <span className="palette-meta">
                    {entry.format.extensions.length > 0
                      ? entry.format.extensions.slice(0, 6).map((e) => `.${e}`).join(" ")
                      : entry.format.name}
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
        <div className="palette-footer">
          <span><kbd>↑</kbd><kbd>↓</kbd> choose</span>
          <span><kbd>Enter</kbd> dissect</span>
          <span><kbd>Esc</kbd> cancel</span>
          {formats && <span className="palette-count">{formats.length.toLocaleString()} formats</span>}
        </div>
      </div>
    </div>
  );
}
