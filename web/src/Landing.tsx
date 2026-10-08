import { useEffect, useMemo, useState } from "react";

import { client } from "./client";
import { HUES, formatSize, hex, hexByte, hexOffset, printable } from "./format";
import type { FieldNode, Page } from "./types";

/// A 16×14 foal in four colours: what the landing page takes apart.
const FOAL_PNG =
  "iVBORw0KGgoAAAANSUhEUgAAABAAAAAOAgMAAABbQXQZAAAADFBMVEUAAACwajo7JBr07uCH158jAAAAAXRSTlMAQObYZgAAAAp0RVh0VGl0bGUAZm9hbO94DyoAAAA0SURBVHjaY2CAACYQwekAJFQDgMT0EKBQiAhQCMhTDQUSU0GEKIgQYQASggwuUEKJoYMBAM0uBuWeekbaAAAAAElFTkSuQmCC";
const FOAL = Uint8Array.from(atob(FOAL_PNG), (c) => c.charCodeAt(0));
export const foalFile = () => new File([FOAL], "foal.png", { type: "image/png" });

type Leaf = {
  node: FieldNode;
  /// Names from the top-level structure down.
  path: string[];
  group: number;
  /// Its place among its group's leaves, for alternating shades.
  index: number;
  start: number;
  end: number;
};

type Group = { node: FieldNode; hue: number };

/// The file's fields down to the leaves that have bytes of the file, a
/// few levels deep.
async function dissect(file: File) {
  const opened = await client.call("open", { file, name: file.name, choices: [] });
  const { session, fileSource } = opened;
  const children = (node: number): Promise<Page> =>
    client.call("children", { session, node, atLeast: 200 });
  const root = await children(opened.page.parent.key);
  const groups: Group[] = root.nodes.map((node, i) => ({ node, hue: HUES[i % HUES.length] }));
  const leaves: Leaf[] = [];
  const inFile = (n: FieldNode) => !!n.span && n.span.source === fileSource && n.span.len > 0;
  const collect = async (n: FieldNode, path: string[], group: number, depth: number) => {
    let kids: FieldNode[] = [];
    if (n.children.state !== "leaf" && depth < 3) {
      kids = (await children(n.key)).nodes.filter(inFile);
    }
    if (kids.length === 0) {
      if (inFile(n)) {
        const index = leaves.filter((l) => l.group === group).length;
        leaves.push({
          node: n,
          path,
          group,
          index,
          start: n.span!.offset,
          end: n.span!.offset + n.span!.len,
        });
      }
      return;
    }
    for (const k of kids) await collect(k, [...path, k.name], group, depth + 1);
  };
  for (const [i, g] of groups.entries()) await collect(g.node, [g.node.name], i, 1);
  void client.call("close", { session });
  return { root: root.parent, groups, leaves };
}

export function Landing({
  ready,
  formatCount,
  error,
  onOpen,
  onOpenFile,
  onTrySelf,
}: {
  ready: boolean;
  formatCount: number | null;
  error: string | null;
  onOpen: () => void;
  onOpenFile: (file: File) => void;
  onTrySelf: () => void;
}) {
  const [dissected, setDissected] = useState<Awaited<ReturnType<typeof dissect>> | null>(null);
  const [hovered, setHovered] = useState<number | null>(null);
  const [tour, setTour] = useState(0);
  const touring = hovered === null;
  const imageUrl = useMemo(() => URL.createObjectURL(new Blob([FOAL], { type: "image/png" })), []);

  useEffect(() => {
    let cancelled = false;
    dissect(foalFile()).then(
      (d) => !cancelled && setDissected(d),
      (e) => console.error("fillyfoal: couldn't dissect the foal", e),
    );
    return () => {
      cancelled = true;
    };
  }, []);

  // Without a pointer on it, the poster walks through the fields itself.
  useEffect(() => {
    if (!dissected || !touring) return;
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const t = setInterval(() => setTour((i) => (i + 1) % dissected.leaves.length), 1800);
    return () => clearInterval(t);
  }, [dissected, touring]);

  const leaves = dissected?.leaves ?? [];
  const groups = dissected?.groups ?? [];
  const leafAt = useMemo(() => {
    const at = new Int16Array(FOAL.length).fill(-1);
    leaves.forEach((l, i) => at.fill(i, l.start, l.end));
    return at;
  }, [leaves]);
  const active = leaves.length ? (hovered ?? tour) : null;
  const leaf = active !== null ? leaves[active] : null;

  return (
    <main className="lp">
      <header className="lp-top">
        <span className="lp-mark">fillyfoal</span>
        <nav className="lp-top-links">
          <button type="button" className="lp-link" onClick={onTrySelf} disabled={!ready}>
            Look inside this page's engine
          </button>
          <button type="button" className="lp-button" onClick={onOpen}>
            Open a file
          </button>
        </nav>
      </header>

      <section className="lp-hero">
        <div className="lp-hero-text">
          <h1>Every file has a structure.</h1>
          <p>
            fillyfoal takes files apart into fields, each one tied to the bytes it came from. Below
            are the 168 bytes of a small PNG, dissected just now in this tab by the same code that
            will take apart yours.
          </p>
        </div>
        <figure className="lp-figure">
          <img src={imageUrl} alt="A pixel-art foal" width={16} height={14} />
          <figcaption>
            foal.png
            <br />
            16 × 14, four colours
          </figcaption>
        </figure>
      </section>

      <section className="lp-poster" aria-label="The bytes of foal.png, annotated">
        <div className="lp-hex" onPointerLeave={() => setHovered(null)}>
          {Array.from({ length: Math.ceil(FOAL.length / 16) }, (_, row) => (
            <div className="lp-row" key={row}>
              <span className="lp-off">{hexOffset(row * 16, 4)}</span>
              {Array.from({ length: 16 }, (_, col) => {
                const offset = row * 16 + col;
                if (offset >= FOAL.length) return <span key={col} className="lp-byte lp-empty" />;
                const i = leafAt[offset];
                const l = i >= 0 ? leaves[i] : undefined;
                const g = l ? groups[l.group] : undefined;
                const first = l && offset === l.start;
                const last = l && offset === l.end - 1;
                return (
                  <span
                    key={col}
                    className="lp-byte"
                    data-on={i === active || undefined}
                    data-alt={l ? l.index % 2 === 1 || undefined : undefined}
                    data-first={first || col === 0 || undefined}
                    data-last={last || col === 15 || undefined}
                    style={g ? ({ "--h": g.hue } as React.CSSProperties) : undefined}
                    onPointerEnter={() => i >= 0 && setHovered(i)}
                    onClick={() => onOpenFile(foalFile())}
                  >
                    {hexByte(FOAL[offset])}
                  </span>
                );
              })}
              <span className="lp-ascii">
                {Array.from(FOAL.subarray(row * 16, row * 16 + 16), (b, col) => {
                  const i = leafAt[row * 16 + col];
                  const l = i >= 0 ? leaves[i] : undefined;
                  return (
                    <span
                      key={col}
                      data-on={(l && i === active) || undefined}
                      data-np={b < 0x20 || b > 0x7e || undefined}
                      style={l ? ({ "--h": groups[l.group].hue } as React.CSSProperties) : undefined}
                      onPointerEnter={() => i >= 0 && setHovered(i)}
                    >
                      {printable(b)}
                    </span>
                  );
                })}
              </span>
            </div>
          ))}
        </div>

        <aside className="lp-readout" aria-live="polite">
          {leaf ? (
            <>
              <div className="lp-path">
                {leaf.path.map((p, i) => (
                  <span key={i}>{p}</span>
                ))}
              </div>
              <div
                className="lp-value"
                style={{ "--h": groups[leaf.group].hue } as React.CSSProperties}
              >
                {leaf.node.value?.text ?? leaf.node.summary ?? <BytesPreview leaf={leaf} />}
              </div>
              {leaf.node.value && leaf.node.summary && (
                <p className="lp-summary">{leaf.node.summary}</p>
              )}
              <p className="lp-where">
                {hex(leaf.start)}–{hex(leaf.end - 1)} · {formatSize(leaf.end - leaf.start)}
              </p>
              {leaf.node.description && <p className="lp-desc">{leaf.node.description}</p>}
            </>
          ) : (
            <p className="lp-waiting">
              {ready ? "Taking it apart…" : "Loading the dissector. It's about 6.5 MB, once."}
            </p>
          )}
          <button type="button" className="lp-link lp-explore" onClick={() => onOpenFile(foalFile())}>
            Explore foal.png
          </button>
        </aside>

        <ol className="lp-legend">
          {groups.map((g, i) => (
            <li
              key={g.node.key}
              style={{ "--h": g.hue } as React.CSSProperties}
              data-on={leaf?.group === i || undefined}
              onPointerEnter={() => {
                const first = leaves.findIndex((l) => l.group === i);
                if (first >= 0) setHovered(first);
              }}
              onPointerLeave={() => setHovered(null)}
            >
              <span className="lp-swatch" />
              {g.node.name}
              {g.node.summary && <span className="lp-legend-sub">{g.node.summary}</span>}
            </li>
          ))}
        </ol>
      </section>

      <DropCall onOpen={onOpen} error={error} />

      <footer className="lp-foot">
        <p>
          <strong>{formatCount ? formatCount.toLocaleString() : "About 1,500"} formats</strong>:
          executables, archives, disk images and filesystems, audio and video, images, documents,
          databases, fonts, game assets, ROMs, scientific data, and a long tail you've probably never
          heard of. Compressed and encrypted content is followed all the way down: a PNG in a zip in
          a disk image is just another field.
        </p>
        <p className="lp-status">
          <span className="lp-dot" data-ready={ready || undefined} />
          Status: just horsing around. Something is better than nothing, but some dissectors are
          incomplete and some are plain wrong.
        </p>
      </footer>
    </main>
  );
}

/// A field with no value of its own, as its bytes.
function BytesPreview({ leaf }: { leaf: Leaf }) {
  const shown = Array.from(FOAL.subarray(leaf.start, Math.min(leaf.end, leaf.start + 6)), hexByte);
  return (
    <span className="lp-value-bytes">
      {shown.join(" ")}
      {leaf.end - leaf.start > shown.length && " …"}
    </span>
  );
}

function DropCall({ onOpen, error }: { onOpen: () => void; error: string | null }) {
  return (
    <section className="lp-drop">
      <h2>Now one of yours.</h2>
      <p>
        Drop it anywhere on this page, or{" "}
        <button type="button" className="lp-link" onClick={onOpen}>
          choose a file
        </button>
        . It is read where it lies, a slice at a time, and only behind the fields you open. There is
        no server, so nothing is uploaded, and a disk image of many gigabytes opens as quickly as
        this foal.
      </p>
      {error && <p className="lp-error">{error}</p>}
    </section>
  );
}
