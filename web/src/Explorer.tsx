import React, {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import { CancelledError, client } from "./client";
import {
  CHUNK_SIZE,
  HEX_BYTES_PER_ROW,
  MAX_SCROLL_HEIGHT,
  formatBytes,
  formatSize,
  hex,
  hexByte,
  hexOffset,
  inSpan,
  mod,
  nodeLine,
  printable,
  spanText,
  type CopyFormat,
} from "./format";
import { FormatPicker, type PickerTarget } from "./FormatPicker";
import { useAfterGrace, useHeight, useStored } from "./hooks";
import { ContextMenu, type MenuItem } from "./Menu";
import { Inspector } from "./Inspector";
import type {
  Choice,
  Content,
  Diagnostic,
  DiagnosticKind,
  FieldNode,
  Page,
  ProgressEvent,
  Secret,
  SourceInfo,
  Span,
} from "./types";

/// Children asked for at a time.
const PAGE = 200;
const TREE_ROW = 26;
const HEX_ROW = 20;
const OVERSCAN = 6;
/// Chunks of bytes kept per byte space.
const CACHED_CHUNKS = 64;
/// Largest download of a decoded stream.
const MAX_DOWNLOAD = 256 * 1024 * 1024;

/// A line of the tree: a node, or the "more children" line under one.
type Row =
  | { kind: "node"; key: number; depth: number }
  | { kind: "more"; parent: number; depth: number };

/// Tree selection: a node's key, or `-(parent + 1)` for a "more" line.
const moreId = (parent: number) => -(parent + 1);
const rowId = (row: Row) => (row.kind === "node" ? row.key : moreId(row.parent));

type Zone = "tree" | "hex";
type Range = { anchor: number; head: number };

const DIAG_LABELS: Record<DiagnosticKind, string> = {
  truncated: "Truncated",
  malformed: "Malformed",
  unsupported: "Unsupported",
  limit: "Limit",
  warning: "Warning",
  note: "Note",
};

const DIAG_RANK: Record<DiagnosticKind, number> = {
  malformed: 0,
  truncated: 1,
  unsupported: 2,
  limit: 3,
  warning: 4,
  note: 5,
};

class ChunkCache {
  private map = new Map<number, Uint8Array>();
  get(key: number) {
    const v = this.map.get(key);
    if (v) {
      this.map.delete(key);
      this.map.set(key, v);
    }
    return v;
  }
  peek(key: number) {
    return this.map.get(key);
  }
  has(key: number) {
    return this.map.has(key);
  }
  set(key: number, v: Uint8Array) {
    this.map.delete(key);
    this.map.set(key, v);
    while (this.map.size > CACHED_CHUNKS) {
      this.map.delete(this.map.keys().next().value!);
    }
  }
}

const errorText = (e: unknown) => (e instanceof Error ? e.message : String(e));

export type ExplorerProps = {
  file: File;
  onOpen: () => void;
  onClose: () => void;
};

export function Explorer({ file, onOpen, onClose }: ExplorerProps) {
  // --- The tree ---

  const [session, setSession] = useState<number | null>(null);
  const [fileSource, setFileSource] = useState(0);
  const [rootKey, setRootKey] = useState<number | null>(null);
  const [nodes, setNodes] = useState<Map<number, FieldNode>>(new Map());
  const [children, setChildren] = useState<Map<number, number[]>>(new Map());
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const [selected, setSelected] = useState<number | null>(null);
  // Nodes whose children are being produced, with how many requests are
  // producing them: a node loaded twice at once is loading until both end.
  const [loading, setLoading] = useState<Map<number, number>>(new Map());
  const loadCounts = useRef(new Map<number, number>());
  const [progress, setProgress] = useState<Map<number, ProgressEvent>>(new Map());
  // Requests not about one node: finding a field, Dissect As's target.
  const [working, setWorking] = useState(0);
  // Byte reads of decoded streams in flight.
  const [reading, setReading] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [zone, setZone] = useState<Zone>("tree");
  const [bytesOpen, setBytesOpen] = useStored("fillyfoal.bytesOpen", true);
  const [pickerTarget, setPickerTarget] = useState<(PickerTarget & { key: number }) | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [secret, setSecret] = useState<{ request: Secret; retry: () => void } | null>(null);
  const [menu, setMenu] = useState<{ x: number; y: number } | null>(null);
  const [menuContent, setMenuContent] = useState<Content | null | "pending">(null);
  const [goToOpen, setGoToOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [choices, setChoices] = useState<Choice[]>([]);
  const loadChildrenRef = useRef<(key: number, atLeast: number) => void>(() => {});

  const notify = useCallback((text: string) => setToast(text), []);
  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 2600);
    return () => clearTimeout(t);
  }, [toast]);

  const merge = useCallback((page: Page) => {
    setNodes((prev) => {
      const next = new Map(prev);
      next.set(page.parent.key, page.parent);
      for (const n of page.nodes) next.set(n.key, n);
      return next;
    });
    setChildren((prev) =>
      new Map(prev).set(
        page.parent.key,
        page.nodes.map((n) => n.key),
      ),
    );
  }, []);

  useEffect(() => {
    setSession(null);
    setRootKey(null);
    setNodes(new Map());
    setChildren(new Map());
    setExpanded(new Set());
    setSelected(null);
    setError(null);
    setSecret(null);
    setPickerTarget(null);
    loadCounts.current = new Map();
    setLoading(new Map());
    setProgress(new Map());
    let cancelled = false;
    let opened: number | null = null;
    (async () => {
      try {
        const r = await client.call("open", {
          file,
          name: file.name,
          choices: [],
        });
        if (cancelled) {
          void client.call("close", { session: r.session });
          return;
        }
        opened = r.session;
        const root = r.page.parent;
        setNodes(new Map([[root.key, root]]));
        setFileSource(r.fileSource);
        setSession(r.session);
        setRootKey(root.key);
        setExpanded(new Set([root.key]));
        setSelected(root.key);
      } catch (e) {
        if (!cancelled) setError(errorText(e));
      }
    })();
    return () => {
      cancelled = true;
      if (opened !== null) void client.call("close", { session: opened });
    };
  }, [file]);

  const parentOf = useMemo(() => {
    const map = new Map<number, number>();
    for (const [parent, kids] of children) {
      for (const k of kids) map.set(k, parent);
    }
    return map;
  }, [children]);

  // The filter's text while its box is open; an invalid pattern filters
  // nothing.
  const [filter, setFilter] = useState<string | null>(null);
  const filterRef = useRef<HTMLInputElement>(null);
  const pattern = useMemo(() => {
    if (!filter) return null;
    try {
      return new RegExp(filter, "i");
    } catch {
      return null;
    }
  }, [filter]);

  const { rows, matches } = useMemo(() => {
    let matches = 0;
    if (rootKey === null) return { rows: [] as Row[], matches };
    // The rows of `key`'s subtree, as far as it is expanded: under a
    // filter, the nodes that match and the way down to them. Collapsed
    // nodes are matched by their own line only.
    const walk = (key: number, depth: number, out: Row[]): boolean => {
      const node = nodes.get(key);
      const own = !pattern || (!!node && pattern.test(nodeLine(node)));
      if (pattern && own) matches++;
      const at = out.length;
      out.push({ kind: "node", key, depth });
      let any = false;
      if (expanded.has(key)) {
        for (const k of children.get(key) ?? []) {
          if (walk(k, depth + 1, out)) any = true;
        }
        const state = node?.children.state;
        if ((state === "more" || state === "stopped") && (own || any)) {
          out.push({ kind: "more", parent: key, depth: depth + 1 });
        }
      }
      if (!own && !any && depth > 0) {
        out.length = at;
        return false;
      }
      return true;
    };
    const out: Row[] = [];
    walk(rootKey, 0, out);
    return { rows: out, matches };
  }, [rootKey, expanded, children, nodes, pattern]);

  const selectedIndex = rows.findIndex((r) => rowId(r) === selected);

  // A pattern the selected line doesn't match selects the first match.
  useEffect(() => {
    if (!pattern) return;
    const matching = (r: Row | undefined) => {
      const n = r?.kind === "node" ? nodes.get(r.key) : undefined;
      return !!n && pattern.test(nodeLine(n));
    };
    if (matching(rows[selectedIndex])) return;
    const first = rows.find(matching);
    if (first) setSelected(rowId(first));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pattern]);

  const node = selected !== null && selected >= 0 ? (nodes.get(selected) ?? null) : null;

  const forgetProgress = useCallback(
    (key: number) =>
      setProgress((prev) => {
        if (!prev.has(key)) return prev;
        const next = new Map(prev);
        next.delete(key);
        return next;
      }),
    [],
  );
  const startLoading = useCallback(
    (key: number) => {
      const counts = loadCounts.current;
      const running = counts.get(key) ?? 0;
      if (running === 0) forgetProgress(key);
      counts.set(key, running + 1);
      setLoading(new Map(counts));
    },
    [forgetProgress],
  );
  const endLoading = useCallback(
    (key: number) => {
      const counts = loadCounts.current;
      const left = (counts.get(key) ?? 1) - 1;
      if (left > 0) {
        counts.set(key, left);
      } else {
        counts.delete(key);
        forgetProgress(key);
      }
      setLoading(new Map(counts));
    },
    [forgetProgress],
  );

  const loadChildren = useCallback(
    async (key: number, atLeast: number): Promise<Page | undefined> => {
      if (session === null) return;
      startLoading(key);
      try {
        const page = await client.call("children", { session, node: key, atLeast });
        merge(page);
        if (page.secret) {
          setSecret({
            request: page.secret,
            retry: () => loadChildrenRef.current(key, atLeast),
          });
        }
        return page;
      } catch (e) {
        if (!(e instanceof CancelledError)) setError(errorText(e));
      } finally {
        endLoading(key);
      }
    },
    [session, merge, startLoading, endLoading],
  );
  loadChildrenRef.current = loadChildren;

  // The root's children, once the dissection is open.
  useEffect(() => {
    if (session !== null && rootKey !== null) void loadChildren(rootKey, PAGE);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session]);

  useEffect(() => {
    if (session === null) return;
    return client.onProgress((p) => {
      if (p.session !== session) return;
      setProgress((prev) => new Map(prev).set(p.node, p));
    });
  }, [session]);

  const busy = loading.size > 0 || working > 0 || reading > 0;
  const showBusy = useAfterGrace(busy);
  const busyText = (() => {
    if (loading.size > 0) {
      const keys = [...loading.keys()];
      const measured = keys.filter((k) => progress.has(k));
      const key = measured.length
        ? measured.reduce((a, b) =>
            percentOf(progress.get(a)!) >= percentOf(progress.get(b)!) ? a : b,
          )
        : keys[0];
      const name = nodes.get(key)?.name ?? "";
      const done = progress.get(key);
      const more = keys.length > 1 ? ` and ${keys.length - 1} more` : "";
      return `Loading “${name}”${done ? ` ${percentOf(done)}%` : "…"}${more}`;
    }
    if (reading > 0) return "Decoding…";
    if (working > 0) return "Working…";
    return null;
  })();
  const busyPercent = (() => {
    for (const k of loading.keys()) {
      const p = progress.get(k);
      if (p) return percentOf(p);
    }
    return null;
  })();

  /// Stop what the dissection is doing: one node's work, or everything.
  const stop = useCallback(
    (key: number | null) => {
      if (session !== null) void client.call("stop", { session, node: key });
    },
    [session],
  );

  const expand = useCallback(
    async (key: number) => {
      const n = nodes.get(key);
      if (!n || n.children.state === "leaf") return;
      setExpanded((prev) => new Set(prev).add(key));
      if (!children.has(key) || n.children.state === "locked") {
        await loadChildren(key, Math.max(PAGE, n.children.loaded));
      }
    },
    [nodes, children, loadChildren],
  );

  const collapse = useCallback(
    (key: number) => {
      if (loading.has(key)) stop(key);
      setExpanded((prev) => {
        const next = new Set(prev);
        next.delete(key);
        return next;
      });
    },
    [loading, stop],
  );

  const loadMore = useCallback(
    (parent: number) => loadChildren(parent, (children.get(parent)?.length ?? 0) + PAGE),
    [children, loadChildren],
  );

  const activate = useCallback(
    (row: Row) => {
      if (row.kind === "more") void loadMore(row.parent);
      else if (nodes.get(row.key)?.children.state === "locked") void expand(row.key);
      else if (expanded.has(row.key)) collapse(row.key);
      else void expand(row.key);
    },
    [nodes, expanded, collapse, expand, loadMore],
  );

  /// Expand `key` and what's below it, a few levels deep (and at most a few
  /// hundred nodes a level).
  const expandAll = useCallback(
    async (key: number) => {
      let level = [nodes.get(key)].filter((n): n is FieldNode => !!n);
      for (let depth = 0; depth < 4 && level.length > 0; depth++) {
        const next: FieldNode[] = [];
        for (const n of level) {
          if (n.children.state === "leaf" || n.children.state === "locked") continue;
          setExpanded((prev) => new Set(prev).add(n.key));
          const page = await loadChildren(n.key, Math.max(PAGE, n.children.loaded));
          if (page) next.push(...page.nodes);
        }
        level = next.slice(0, 300);
      }
    },
    [nodes, loadChildren],
  );

  // --- The hex pane: the byte space the selected field lives in ---

  const rootNode = rootKey !== null ? nodes.get(rootKey) : undefined;
  const span = node?.span ?? null;
  const source = span?.source ?? fileSource;
  const [sources, setSources] = useState<Map<number, SourceInfo>>(new Map());
  const sourceInfo = sources.get(source);
  const sourceLen =
    source === fileSource ? file.size : (sourceInfo?.len ?? span?.len ?? 0);
  const lenKnown = source === fileSource || (sourceInfo?.len_known ?? true);

  /// Ask again for the sources whose length was only a bound: decoding may
  /// have reached their end since.
  const refreshUnknownLengths = useCallback(
    () =>
      setSources((prev) => {
        const unknown = [...prev].filter(([, info]) => !info.len_known);
        if (unknown.length === 0) return prev;
        const next = new Map(prev);
        for (const [s] of unknown) next.delete(s);
        return next;
      }),
    [],
  );
  useEffect(() => {
    if (loading.size === 0) refreshUnknownLengths();
  }, [loading.size, refreshUnknownLengths]);

  /// The size of `s`, unless it runs to the end of a stream whose length
  /// isn't known yet.
  const sizeOf = (s: Span) => {
    const info = s.source === fileSource ? undefined : sources.get(s.source);
    return info && !info.len_known && s.offset + s.len >= info.len
      ? "size unknown"
      : formatSize(s.len);
  };

  useEffect(() => {
    if (session === null || sources.has(source)) return;
    let cancelled = false;
    client
      .call("source", { session, source })
      .then((info) => {
        if (!cancelled) setSources((prev) => new Map(prev).set(source, info));
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [session, source, sources]);

  const caches = useRef(new Map<number, ChunkCache>());
  useEffect(() => {
    caches.current = new Map();
  }, [file]);
  const cacheFor = (s: number) => {
    let cache = caches.current.get(s);
    if (!cache) {
      cache = new ChunkCache();
      caches.current.set(s, cache);
    }
    return cache;
  };
  const [, bump] = useState(0);

  const [cursor, setCursor] = useState(0);
  const [range, setRange] = useState<Range | null>(null);
  // Whether a new selection moves the hex cursor to it: not when the
  // selection came from the hex pane itself.
  const followSelection = useRef(true);

  const hexRef = useRef<HTMLDivElement>(null);
  const [hexTop, setHexTop] = useState(0);
  const hexHeight = useHeight(hexRef, [bytesOpen]);
  const hexRows = Math.ceil(sourceLen / HEX_BYTES_PER_ROW);
  const hexNatural = hexRows * HEX_ROW;
  const hexScale = hexNatural > MAX_SCROLL_HEIGHT ? hexNatural / MAX_SCROLL_HEIGHT : 1;
  const hexVisible = Math.max(1, Math.floor(hexHeight / HEX_ROW));
  const hexFirst = Math.max(0, hexTop - OVERSCAN);
  const hexLast = Math.min(hexRows, hexTop + hexVisible + OVERSCAN);
  const offsetWidth = Math.max(8, Math.ceil(Math.log2(Math.max(sourceLen, 2)) / 4));

  const scrollHexTo = useCallback(
    (row: number, center: boolean) => {
      const el = hexRef.current;
      const top = Math.max(0, center ? row - Math.floor(hexVisible / 3) : row);
      if (el) el.scrollTop = (top * HEX_ROW) / hexScale;
      setHexTop(top);
    },
    [hexVisible, hexScale],
  );

  const revealByte = useCallback(
    (offset: number) => {
      const row = Math.floor(offset / HEX_BYTES_PER_ROW);
      if (row < hexTop) scrollHexTo(row, false);
      else if (row >= hexTop + hexVisible) scrollHexTo(row - hexVisible + 1, false);
    },
    [hexTop, hexVisible, scrollHexTo],
  );

  // The pane shrinks when the inspector opens under it; the cursor stays
  // in view.
  useEffect(() => {
    if (zone === "hex") revealByte(cursor);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hexVisible]);

  useEffect(() => {
    if (!followSelection.current) {
      followSelection.current = true;
      return;
    }
    if (!span) return;
    setCursor(span.offset);
    setRange(null);
    const row = Math.floor(span.offset / HEX_BYTES_PER_ROW);
    const endRow = Math.floor((span.offset + Math.max(span.len, 1) - 1) / HEX_BYTES_PER_ROW);
    if (row < hexTop || endRow >= hexTop + hexVisible) {
      // The whole field if it fits, else its start a little way down.
      const fits = endRow - row < hexVisible - 2;
      scrollHexTo(fits && row >= hexTop ? endRow - hexVisible + 2 : row, !fits || row < hexTop);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected]);

  // Load the chunks on screen.
  const firstChunk = Math.floor((hexFirst * HEX_BYTES_PER_ROW) / CHUNK_SIZE);
  const lastChunk = Math.floor((hexLast * HEX_BYTES_PER_ROW) / CHUNK_SIZE);
  useEffect(() => {
    if (session === null || sourceLen === 0 || !bytesOpen) return;
    let cancelled = false;
    (async () => {
      const cache = cacheFor(source);
      let loaded = false;
      for (let ci = firstChunk; ci <= lastChunk && !cancelled; ci++) {
        if (cache.has(ci)) continue;
        const offset = ci * CHUNK_SIZE;
        if (offset >= sourceLen) break;
        const decoded = source !== fileSource;
        if (decoded) setReading((n) => n + 1);
        try {
          const bytes = decoded
            ? await client.call("read", { session, source, offset, len: CHUNK_SIZE })
            : new Uint8Array(await file.slice(offset, offset + CHUNK_SIZE).arrayBuffer());
          cache.set(ci, bytes);
          loaded = true;
          // A short read is the end of the stream.
          if (decoded && bytes.length < CHUNK_SIZE) refreshUnknownLengths();
        } catch (e) {
          if (!(e instanceof CancelledError)) console.error("fillyfoal: failed to load bytes", e);
          break;
        } finally {
          if (decoded) setReading((n) => n - 1);
        }
      }
      if (loaded && !cancelled) bump((n) => n + 1);
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session, source, firstChunk, lastChunk, sourceLen, bytesOpen]);

  const byteAt = (offset: number): number | undefined => {
    const ci = Math.floor(offset / CHUNK_SIZE);
    const chunk = caches.current.get(source)?.peek(ci);
    if (!chunk) return undefined;
    return chunk[offset - ci * CHUNK_SIZE];
  };

  // --- Tree scrolling ---

  const treeRef = useRef<HTMLDivElement>(null);
  const [treeTop, setTreeTop] = useState(0);
  const treeHeight = useHeight(treeRef);
  const treeVisible = Math.max(1, Math.floor(treeHeight / TREE_ROW));
  const treeFirst = Math.max(0, Math.floor(treeTop / TREE_ROW) - OVERSCAN);
  const treeLast = Math.min(rows.length, Math.ceil((treeTop + treeHeight) / TREE_ROW) + OVERSCAN);

  // Keep the selected line in view.
  useLayoutEffect(() => {
    const el = treeRef.current;
    if (!el || selectedIndex < 0) return;
    const top = selectedIndex * TREE_ROW;
    if (top < el.scrollTop) el.scrollTop = top;
    else if (top + TREE_ROW > el.scrollTop + el.clientHeight) {
      el.scrollTop = top + TREE_ROW - el.clientHeight;
    }
    // Rendered for the new position now, not after the scroll event.
    setTreeTop(el.scrollTop);
  }, [selectedIndex]);

  // --- Focus ---

  const focusZone = useCallback(
    (z: Zone) => {
      setZone(z);
      if (z === "hex") setBytesOpen(true);
      requestAnimationFrame(() => (z === "tree" ? treeRef : hexRef).current?.focus());
    },
    [setBytesOpen],
  );

  const toggleBytes = () => {
    if (bytesOpen && zone === "hex") focusZone("tree");
    setBytesOpen(!bytesOpen);
  };

  // A hidden pane loses its scroll position, so it's restored when it shows.
  useLayoutEffect(() => {
    const el = hexRef.current;
    if (!bytesOpen || !el) return;
    el.scrollTop = (hexTop * HEX_ROW) / hexScale;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bytesOpen]);

  useEffect(() => {
    if (session !== null && !secret) treeRef.current?.focus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session]);

  // --- Locating the field at a byte ---

  const locate = useCallback(
    async (src: number, offset: number, fromHex: boolean) => {
      if (session === null) return;
      setWorking((n) => n + 1);
      try {
        const r = await client.call("locate", { session, source: src, offset });
        const target = r.path[r.path.length - 1];
        const found = r.pages
          .flatMap((p) => [p.parent, ...p.nodes])
          .find((n) => n.key === target);
        // A byte clicked that no field of its stream holds leaves the
        // selection, and with it the stream, where it is.
        if (fromHex && found?.span?.source !== src) return;
        // The field found may be one the filter hides.
        setFilter(null);
        for (const page of r.pages) merge(page);
        setExpanded((prev) => {
          const next = new Set(prev);
          for (const k of r.path.slice(0, -1)) next.add(k);
          return next;
        });
        if (fromHex && target !== selected) followSelection.current = false;
        setSelected(target);
        if (r.secret) {
          setSecret({
            request: r.secret,
            retry: () => locateRef.current(src, offset, fromHex),
          });
        }
      } catch (e) {
        if (!(e instanceof CancelledError)) setError(errorText(e));
      } finally {
        setWorking((n) => n - 1);
      }
    },
    [session, merge, selected],
  );
  const locateRef = useRef(locate);
  locateRef.current = locate;

  const answerSecret = async (password: string | null) => {
    const pending = secret;
    if (!pending || session === null) return;
    setSecret(null);
    focusZone(zone);
    await client.call("answerSecret", { session, index: pending.request.index, password });
    pending.retry();
  };

  const goToOffset = (value: string) => {
    const text = value.trim();
    const offset = /^\d+$/.test(text) && !/^0\d/.test(text) && text.length < 4
      ? parseInt(text, 10)
      : parseInt(text.replace(/^0x/i, ""), 16);
    if (isNaN(offset) || offset < 0 || offset >= sourceLen) {
      notify(`Offset out of range (0–${hex(Math.max(0, sourceLen - 1))})`);
      return;
    }
    setCursor(offset);
    setRange(null);
    scrollHexTo(Math.floor(offset / HEX_BYTES_PER_ROW), true);
    void locate(source, offset, true);
  };

  const followTarget = useCallback(() => {
    const target = node?.target;
    if (!target) return false;
    void locate(target.source, target.offset, false);
  }, [node, locate]);

  // --- Copying and saving ---

  const readSpan = useCallback(
    async (s: Span, limit: number) => {
      if (session === null) throw new Error("not open");
      if (s.source === fileSource) {
        return new Uint8Array(await file.slice(s.offset, s.offset + s.len).arrayBuffer());
      }
      if (s.len > limit) throw new Error(`${formatSize(s.len)} is more than can be read at once`);
      setReading((n) => n + 1);
      try {
        return await client.call("read", { session, ...s });
      } finally {
        setReading((n) => n - 1);
      }
    },
    [session, fileSource, file],
  );

  const copyText = (text: string, what = "Copied") => {
    navigator.clipboard.writeText(text).then(
      () => notify(what),
      () => notify("Couldn't copy to the clipboard"),
    );
  };

  const copyBytes = async (s: Span | null, format: CopyFormat) => {
    if (!s || s.len === 0) return false;
    if (s.len > 16 * 1024 * 1024) {
      notify("Too many bytes to copy; download them instead");
      return;
    }
    try {
      const bytes = await readSpan(s, 16 * 1024 * 1024);
      copyText(formatBytes(bytes, format), `Copied ${formatSize(bytes.length)}`);
    } catch (e) {
      if (!(e instanceof CancelledError)) notify(errorText(e));
    }
  };

  const downloadName = (n: FieldNode | null) => {
    const base = (n?.name ?? "bytes").replace(/[\\/:*?"<>|]+/g, "_").slice(0, 80);
    return /\.\w{1,8}$/.test(base) ? base : `${base}.bin`;
  };

  const downloadBytes = async (s: Span | null, name: string) => {
    if (!s || s.len === 0) return false;
    try {
      const blob =
        s.source === fileSource
          ? file.slice(s.offset, s.offset + s.len)
          : new Blob([(await readSpan(s, MAX_DOWNLOAD)) as BlobPart]);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = name;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
    } catch (e) {
      if (!(e instanceof CancelledError)) notify(errorText(e));
    }
  };

  /// The content a node stands for, to save: an archive member's data
  /// rather than its headers.
  const contentSpan = async (): Promise<{ span: Span; name: string } | null> => {
    const content = await selectedContent();
    if (content?.node.span) return { span: content.node.span, name: content.name };
    return null;
  };

  const hexSelection = (): Span | null => {
    if (!range) return null;
    const start = Math.min(range.anchor, range.head);
    const end = Math.max(range.anchor, range.head);
    return { source, offset: start, len: end - start + 1 };
  };

  const copy = () => {
    if (zone === "hex" && range) return void copyBytes(hexSelection(), "hex");
    if (!node) return false;
    copyText(nodeLine(node));
  };
  const copyValue = () => {
    if (!node) return false;
    copyText(node.value?.text ?? node.summary ?? node.name);
  };

  /// The selected line and what's shown below it, as the tree shows them,
  /// in fillyfoal's tree text: collapsed nodes collapsed, each line's bytes
  /// after it, problems below.
  const treeText = (): string | null => {
    if (selectedIndex < 0) return null;
    const base = rows[selectedIndex].depth;
    const lines: string[] = [];
    for (let i = selectedIndex; i < rows.length; i++) {
      const row = rows[i];
      if (i > selectedIndex && row.depth <= base) break;
      const indent = "  ".repeat(row.depth - base);
      if (row.kind === "more") {
        const shown = children.get(row.parent)?.length ?? 0;
        const total = nodes.get(row.parent)?.children.count;
        const of = total ? ` of ${total.at_least ? "at least " : ""}${total.n}` : "";
        lines.push(`${indent}  … (${shown} shown${of})`);
        continue;
      }
      const n = nodes.get(row.key);
      if (!n) continue;
      const marker = n.children.state === "leaf" ? "  " : expanded.has(row.key) ? "▾ " : "▸ ";
      const bytes = n.span ? `  [0x${n.span.offset.toString(16)}+0x${n.span.len.toString(16)}]` : "";
      lines.push(`${indent}${marker}${nodeLine(n)}${bytes}`);
      for (const d of n.diagnostics) lines.push(`${indent}    ! ${d.message}`);
    }
    return lines.join("\n") + "\n";
  };
  const copyTree = () => {
    const text = treeText();
    if (text === null) return false;
    copyText(text, "Copied the tree");
  };

  /// Save what's selected: the hex selection, else the file the selected
  /// field stands for (an archive member's content), else its bytes.
  const saveSelected = async () => {
    if (zone === "hex" && range) {
      const base = node ? downloadName(node).replace(/\.[^.]*$/, "") : "bytes";
      void downloadBytes(hexSelection(), `${base}-${selStart.toString(16)}.bin`);
      return;
    }
    const c = await contentSpan();
    if (c) void downloadBytes(c.span, c.name.split("/").pop() ?? c.name);
    else if (span) void downloadBytes(span, downloadName(node));
  };

  // --- Dissect As ---

  /// What Dissect As would choose the format of for the selected line; null
  /// when it holds no file, undefined when that couldn't be found out.
  const selectedContent = async () => {
    if (session === null || selected === null) return undefined;
    const key = selected < 0 ? -selected - 1 : selected;
    setWorking((n) => n + 1);
    try {
      return await client.call("contentOf", { session, node: key });
    } catch (e) {
      if (!(e instanceof CancelledError)) setError(errorText(e));
      return undefined;
    } finally {
      setWorking((n) => n - 1);
    }
  };

  const showDissectAs = (content: Content) => {
    const { node: target, name } = content;
    setNodes((prev) => new Map(prev).set(target.key, target));
    const interpretation = target.interpretation;
    setPickerTarget({
      key: target.key,
      name,
      current: interpretation?.forced ? (interpretation.format?.name ?? null) : null,
    });
  };

  const openDissectAs = async () => {
    const content = await selectedContent();
    if (content === null) {
      notify("Dissect As applies to a file: the file itself, an archive member, decompressed or embedded data");
    } else if (content) {
      showDissectAs(content);
    }
  };

  const descendants = (key: number): number[] =>
    (children.get(key) ?? []).flatMap((k) => [k, ...descendants(k)]);

  const pickFormat = async (picked: string | null) => {
    const target = pickerTarget;
    setPickerTarget(null);
    focusZone("tree");
    if (!target || session === null || picked === target.current) return;
    const gone = descendants(target.key);
    startLoading(target.key);
    try {
      const { located: r, choices } = await client.call("reinterpret", {
        session,
        node: target.key,
        format: picked,
      });
      setChoices(choices);
      setChildren((prev) => {
        const next = new Map(prev);
        for (const k of gone) next.delete(k);
        return next;
      });
      setExpanded((prev) => {
        const next = new Set(prev);
        for (const k of gone) next.delete(k);
        for (const k of r.path) next.add(k);
        return next;
      });
      for (const page of r.pages) merge(page);
      setSelected(target.key);
      if (r.secret) {
        setSecret({
          request: r.secret,
          retry: () => loadChildrenRef.current(target.key, PAGE),
        });
      }
    } catch (e) {
      if (!(e instanceof CancelledError)) setError(errorText(e));
    } finally {
      endLoading(target.key);
    }
  };

  // --- Keys ---

  const selectRow = (index: number) => {
    const row = rows[Math.max(0, Math.min(index, rows.length - 1))];
    if (row) setSelected(rowId(row));
  };

  const onTreeKey = (e: React.KeyboardEvent) => {
    const row = rows[selectedIndex];
    switch (e.key) {
      case "ArrowDown":
        selectRow(selectedIndex + 1);
        break;
      case "ArrowUp":
        selectRow(selectedIndex - 1);
        break;
      case "PageDown":
        selectRow(selectedIndex + treeVisible - 1);
        break;
      case "PageUp":
        selectRow(selectedIndex - treeVisible + 1);
        break;
      case "Home":
        selectRow(0);
        break;
      case "End":
        selectRow(rows.length - 1);
        break;
      case "ArrowRight":
        if (!row || row.kind !== "node") return;
        if (!expanded.has(row.key)) void expand(row.key);
        else if (rows[selectedIndex + 1]?.depth > row.depth) selectRow(selectedIndex + 1);
        break;
      case "ArrowLeft":
        if (!row) return;
        if (row.kind === "node" && expanded.has(row.key)) collapse(row.key);
        else {
          const parent = row.kind === "more" ? row.parent : parentOf.get(row.key);
          if (parent !== undefined) setSelected(parent);
        }
        break;
      case "*":
        if (row?.kind === "node") void expandAll(row.key);
        break;
      case "Enter":
      case " ":
        if (!row || e.metaKey || e.ctrlKey) return;
        activate(row);
        break;
      case "Tab":
        if (e.shiftKey || !bytesOpen) return;
        focusZone("hex");
        break;
      case "Escape":
        if (filter === null) return;
        setFilter(null);
        break;
      default:
        return;
    }
    e.preventDefault();
    e.stopPropagation();
  };

  const moveCursor = (to: number, extend: boolean) => {
    const offset = Math.max(0, Math.min(to, sourceLen - 1));
    setRange((prev) => (extend ? { anchor: prev?.anchor ?? cursor, head: offset } : null));
    setCursor(offset);
    revealByte(offset);
  };

  const onHexKey = (e: React.KeyboardEvent) => {
    const extend = e.shiftKey;
    switch (e.key) {
      case "ArrowRight":
        moveCursor(cursor + 1, extend);
        break;
      case "ArrowLeft":
        moveCursor(cursor - 1, extend);
        break;
      case "ArrowDown":
        moveCursor(cursor + HEX_BYTES_PER_ROW, extend);
        break;
      case "ArrowUp":
        moveCursor(cursor - HEX_BYTES_PER_ROW, extend);
        break;
      case "PageDown":
        moveCursor(cursor + HEX_BYTES_PER_ROW * (hexVisible - 1), extend);
        break;
      case "PageUp":
        moveCursor(cursor - HEX_BYTES_PER_ROW * (hexVisible - 1), extend);
        break;
      case "Home":
        moveCursor(e.metaKey || e.ctrlKey ? 0 : cursor - (cursor % HEX_BYTES_PER_ROW), extend);
        break;
      case "End":
        moveCursor(
          e.metaKey || e.ctrlKey
            ? sourceLen - 1
            : cursor - (cursor % HEX_BYTES_PER_ROW) + HEX_BYTES_PER_ROW - 1,
          extend,
        );
        break;
      case "Enter":
        if (e.metaKey || e.ctrlKey) return;
        void locate(source, cursor, true);
        break;
      case "Escape":
        if (!range) return;
        setRange(null);
        break;
      case "Tab":
        focusZone("tree");
        break;
      default:
        return;
    }
    e.preventDefault();
    e.stopPropagation();
  };

  // Shortcuts anywhere in the explorer, unless typing in a box.
  const keysRef = useRef<(e: KeyboardEvent) => void>(() => {});
  keysRef.current = (e: KeyboardEvent) => {
    if (e.defaultPrevented) return;
    const typing =
      e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement;
    const cmd = e.metaKey || e.ctrlKey;
    if (pickerTarget || menu) return;
    if (e.key === "Escape") {
      if (helpOpen) setHelpOpen(false);
      else if (busy) stop(null);
      else if (goToOpen) setGoToOpen(false);
      else return;
      e.preventDefault();
      return;
    }
    if (cmd && e.key.toLowerCase() === "f") {
      setFilter((f) => f ?? "");
      requestAnimationFrame(() => filterRef.current?.focus());
    } else if (cmd && e.key.toLowerCase() === "g") {
      setGoToOpen(true);
    } else if (cmd && e.key.toLowerCase() === "o") {
      onOpen();
    } else if (cmd && e.key.toLowerCase() === "s") {
      void saveSelected();
    } else if (cmd && e.key.toLowerCase() === "c" && !typing) {
      // Text selected on the page (the details) copies as usual.
      if (window.getSelection()?.toString()) return;
      if (e.shiftKey) copyValue();
      else copy();
    } else if (cmd && e.key.toLowerCase() === "a" && !typing) {
      if (!span || span.len === 0) return;
      setRange({ anchor: span.offset, head: span.offset + span.len - 1 });
      focusZone("hex");
    } else if (typing || cmd || e.altKey) {
      return;
    } else if (e.key === "/") {
      setFilter((f) => f ?? "");
      requestAnimationFrame(() => filterRef.current?.focus());
    } else if (e.key === "g") {
      setGoToOpen(true);
    } else if (e.key === "d") {
      void openDissectAs();
    } else if (e.key === "b") {
      toggleBytes();
    } else if (e.key === "t") {
      followTarget();
    } else if (e.key === "s") {
      void saveSelected();
    } else if (e.key === "?") {
      setHelpOpen((h) => !h);
    } else {
      return;
    }
    e.preventDefault();
  };
  useEffect(() => {
    const listener = (e: KeyboardEvent) => keysRef.current(e);
    window.addEventListener("keydown", listener);
    return () => window.removeEventListener("keydown", listener);
  }, []);

  // --- Mouse in the hex pane ---

  const dragging = useRef(false);
  /// The byte under the pointer, or with `nearest`, between lines, columns
  /// or past a line's end (and outside the pane, while dragging) the
  /// nearest one: on the nearest line drawn, the nearest byte along it.
  const byteFromEvent = (e: { clientX: number; clientY: number }, nearest = false) => {
    const el = document.elementFromPoint(e.clientX, e.clientY);
    if (el instanceof HTMLElement && el.dataset.offset !== undefined) {
      return parseInt(el.dataset.offset, 10);
    }
    if (!nearest) return undefined;
    const closest = (els: Iterable<HTMLElement>, gap: (r: DOMRect) => number) => {
      let best: HTMLElement | undefined;
      let bestGap = Infinity;
      for (const candidate of els) {
        const d = gap(candidate.getBoundingClientRect());
        if (d < bestGap) [best, bestGap] = [candidate, d];
      }
      return best;
    };
    const outside = (at: number, from: number, to: number) =>
      at < from ? from - at : at > to ? at - to : 0;
    const lines = hexRef.current?.querySelectorAll<HTMLElement>(".hex-line") ?? [];
    const line = closest(lines, (r) => outside(e.clientY, r.top, r.bottom));
    const byte = line
      ? closest(line.querySelectorAll<HTMLElement>(".hex-bytes [data-offset]"), (r) =>
          outside(e.clientX, r.left, r.right),
        )
      : undefined;
    return byte ? parseInt(byte.dataset.offset!, 10) : undefined;
  };
  const onHexPointerDown = (e: React.PointerEvent<HTMLElement>) => {
    if (e.button !== 0) return;
    // A press on the scrollbar is the scrollbar's.
    const pane = e.currentTarget;
    const box = pane.getBoundingClientRect();
    if (
      e.clientX >= box.left + pane.clientLeft + pane.clientWidth ||
      e.clientY >= box.top + pane.clientTop + pane.clientHeight
    ) {
      return;
    }
    const offset = byteFromEvent(e, true);
    if (offset === undefined) return;
    e.preventDefault();
    setZone("hex");
    hexRef.current?.focus();
    if (e.shiftKey) {
      setRange((prev) => ({ anchor: prev?.anchor ?? cursor, head: offset }));
    } else {
      setRange(null);
      void locate(source, offset, true);
    }
    setCursor(offset);
    dragging.current = true;
  };
  useEffect(() => {
    const move = (e: PointerEvent) => {
      if (!dragging.current) return;
      const offset = byteFromEvent(e, true);
      if (offset === undefined) return;
      setRange((prev) => ({ anchor: prev?.anchor ?? offset, head: offset }));
      setCursor(offset);
    };
    const up = () => {
      dragging.current = false;
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
    return () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
    };
  }, []);

  // --- Context menu ---

  const openMenu = (e: React.MouseEvent) => {
    e.preventDefault();
    setMenu({ x: e.clientX, y: e.clientY });
    setMenuContent("pending");
    void selectedContent().then((c) => setMenuContent(c ?? null));
  };

  const menuItems: MenuItem[] = [
    { label: "Copy line", shortcut: `${mod}C`, disabled: !node, onSelect: copy },
    { label: "Copy value", shortcut: `⇧${mod}C`, disabled: !node, onSelect: copyValue },
    { label: "Copy tree", disabled: !node, onSelect: copyTree },
    "separator",
    {
      label: "Copy bytes as hex",
      disabled: !span || span.len === 0,
      onSelect: () => void copyBytes(span, "hex"),
    },
    {
      label: "Copy bytes as text",
      disabled: !span || span.len === 0,
      onSelect: () => void copyBytes(span, "text"),
    },
    {
      label: "Copy bytes as Base64",
      disabled: !span || span.len === 0,
      onSelect: () => void copyBytes(span, "base64"),
    },
    {
      label: "Copy bytes as C array",
      disabled: !span || span.len === 0,
      onSelect: () => void copyBytes(span, "c"),
    },
    {
      label:
        menuContent && menuContent !== "pending" && menuContent.node.span
          ? `Save “${menuContent.name.split("/").pop()}”`
          : "Save bytes",
      shortcut: "S",
      disabled:
        menuContent === "pending" ||
        !((menuContent && menuContent.node.span) || (span && span.len > 0)),
      onSelect: () => {
        if (menuContent && menuContent !== "pending" && menuContent.node.span) {
          void downloadBytes(menuContent.node.span, menuContent.name.split("/").pop() ?? "content");
        } else void downloadBytes(span, downloadName(node));
      },
    },
    "separator",
    { label: "Go to target", shortcut: "T", disabled: !node?.target, onSelect: followTarget },
    { label: "Go to offset…", shortcut: "G", onSelect: () => setGoToOpen(true) },
    {
      label: "Expand below",
      shortcut: "*",
      disabled: !node || node.children.state === "leaf",
      onSelect: () => node && void expandAll(node.key),
    },
    "separator",
    {
      label:
        menuContent && menuContent !== "pending"
          ? `Dissect “${menuContent.name.split("/").pop()}” as…`
          : "Dissect as…",
      shortcut: "D",
      disabled: !menuContent || menuContent === "pending",
      onSelect: () => {
        if (menuContent && menuContent !== "pending") showDissectAs(menuContent);
      },
    },
    { label: "Bytes panel", shortcut: "B", checked: bytesOpen, onSelect: toggleBytes },
  ];

  // --- Rendering ---

  const selStart = range ? Math.min(range.anchor, range.head) : -1;
  const selEnd = range ? Math.max(range.anchor, range.head) : -2;
  const target = node?.target ?? null;

  /// How a byte is highlighted: in the hex selection, in the selected
  /// field's bytes, or not at all.
  const highlight = (offset: number) =>
    offset >= selStart && offset <= selEnd ? "sel" : inSpan(span, source, offset) ? "on" : null;

  /// A byte's class. A highlight is one band: the space around a byte is
  /// painted only towards a neighbour on the line highlighted alike.
  const byteClass = (offset: number, ascii: boolean) => {
    const kind = highlight(offset);
    let c = "b";
    if (kind === "sel") c += zone === "hex" ? " b-sel" : " b-sel-inactive";
    else if (kind === "on") c += " b-on";
    else if (inSpan(target, source, offset)) c += " b-target";
    if (kind && !ascii) {
      const col = offset % HEX_BYTES_PER_ROW;
      if (col === 0 || highlight(offset - 1) !== kind) c += " b-start";
      if (col === HEX_BYTES_PER_ROW - 1 || highlight(offset + 1) !== kind) c += " b-end";
    }
    if (offset === cursor && !ascii) c += zone === "hex" ? " b-cursor" : " b-cursor-inactive";
    return c;
  };

  const treeRows = rows.slice(treeFirst, treeLast).map((row, i) => {
    const index = treeFirst + i;
    const id = rowId(row);
    const isSelected = id === selected;
    const style = { top: index * TREE_ROW, paddingLeft: 8 + row.depth * 18 };
    const cls = `row${isSelected ? (zone === "tree" ? " row-sel" : " row-sel-inactive") : ""}`;
    const guides = Array.from({ length: row.depth }, (_, d) => (
      <span key={d} className="guide" style={{ left: 8 + d * 18 + 8 }} />
    ));
    if (row.kind === "more") {
      const parent = nodes.get(row.parent);
      const shown = children.get(row.parent)?.length ?? 0;
      const total = parent?.children.count;
      const isBusy = loading.has(row.parent);
      return (
        <div
          key={`m${row.parent}`}
          className={`${cls} row-more`}
          style={style}
          onClick={() => {
            setSelected(id);
            treeRef.current?.focus();
          }}
          onDoubleClick={() => activate(row)}
        >
          {guides}
          <span className="chevron">{isBusy && <Spinner />}</span>
          <button
            type="button"
            tabIndex={-1}
            className="more-button"
            onClick={() => void loadMore(row.parent)}
            disabled={isBusy}
          >
            {isBusy ? "Loading…" : parent?.children.state === "stopped" ? "Stopped — continue" : `Show ${PAGE} more`}
          </button>
          <span className="summary">
            {shown.toLocaleString()} of{" "}
            {total ? `${total.at_least ? "at least " : ""}${total.n.toLocaleString()}` : "?"} shown
          </span>
        </div>
      );
    }
    const n = nodes.get(row.key);
    if (!n) return null;
    const expandable = n.children.state !== "leaf";
    const isOpen = expanded.has(row.key);
    const diags = n.diagnostics.concat(n.children.error ? [n.children.error] : []);
    const worst = diags.reduce<Diagnostic | null>(
      (w, d) => (!w || DIAG_RANK[d.kind] < DIAG_RANK[w.kind] ? d : w),
      null,
    );
    return (
      <div
        key={row.key}
        className={cls}
        style={style}
        onPointerDown={(e) => {
          if (e.button === 2) setSelected(id);
        }}
        onClick={() => {
          setSelected(id);
          setZone("tree");
          treeRef.current?.focus();
        }}
        onDoubleClick={() => expandable && activate(row)}
        role="treeitem"
        aria-level={row.depth + 1}
        aria-expanded={expandable ? isOpen : undefined}
        aria-selected={isSelected}
      >
        {guides}
        <span
          className="chevron"
          data-open={isOpen || undefined}
          onClick={(e) => {
            e.stopPropagation();
            setSelected(id);
            if (expandable) activate(row);
          }}
        >
          {loading.has(row.key) ? (
            <AfterGrace before={expandable && <Chevron />}>
              <Spinner />
            </AfterGrace>
          ) : (
            expandable && <Chevron />
          )}
        </span>
        <span className="name">{n.name}</span>
        {n.interpretation &&
          (n.interpretation.forced ? (
            <span className="badge badge-forced" title={`Dissected as ${n.interpretation.format?.title}, chosen with Dissect As`}>
              as {n.interpretation.format?.title}
            </span>
          ) : (
            <span className="badge" title={n.interpretation.format?.title ?? "Not recognised"}>
              {n.interpretation.format?.name ?? "?"}
            </span>
          ))}
        {n.value && (
          <>
            <span className="colon">:</span>
            <span className="value" data-kind={n.value.kind}>
              {n.value.text}
            </span>
            {(n.value.kind === "enum" || n.value.kind === "flags") && n.value.raw && (
              <span className="raw">{n.value.raw}</span>
            )}
          </>
        )}
        {n.summary && <span className="summary">{n.summary}</span>}
        {n.children.state === "locked" && (
          <span className="lock" title="Needs a password: press Enter to unlock">
            <LockIcon />
          </span>
        )}
        {worst && (
          <span
            className="diag-dot"
            data-kind={worst.kind}
            title={diags.map((d) => `${DIAG_LABELS[d.kind]}: ${d.message}`).join("\n")}
          >
            !
          </span>
        )}
        {n.span && index > 0 && <span className="offset">{hex(n.span.offset)}</span>}
      </div>
    );
  });

  const hexLines = [];
  for (let r = hexFirst; r < hexLast; r++) {
    const base = r * HEX_BYTES_PER_ROW;
    const bytes = [];
    const chars = [];
    for (let j = 0; j < HEX_BYTES_PER_ROW; j++) {
      const offset = base + j;
      if (offset >= sourceLen) break;
      const b = byteAt(offset);
      bytes.push(
        <span key={j} data-offset={offset} className={byteClass(offset, false)} data-gap={j === 7 || undefined}>
          {b === undefined ? "··" : hexByte(b)}
        </span>,
      );
      chars.push(
        <span key={j} data-offset={offset} className={byteClass(offset, true)} data-np={b !== undefined && (b < 0x20 || b > 0x7e) ? true : undefined}>
          {b === undefined ? " " : printable(b)}
        </span>,
      );
    }
    hexLines.push(
      <div
        key={r}
        className="hex-line"
        style={{ top: (r - hexTop) * HEX_ROW + (hexTop * HEX_ROW) / hexScale }}
      >
        <span className="hex-offset">{hexOffset(base, offsetWidth)}</span>
        <span className="hex-bytes">{bytes}</span>
        <span className="hex-chars">{chars}</span>
      </div>,
    );
  }

  const origin = sourceInfo?.origin ?? null;
  const sourceLabel =
    source === fileSource
      ? file.name
      : origin
        ? `${origin.transform} of ${spanText(origin.parent)}`
        : `Stream #${source}`;

  // The way down to the selected field.
  const breadcrumb = useMemo(() => {
    const path: number[] = [];
    let k = selected === null ? undefined : selected < 0 ? -selected - 1 : selected;
    while (k !== undefined) {
      path.unshift(k);
      k = parentOf.get(k);
    }
    return path;
  }, [selected, parentOf]);

  const inspectorBytes = (() => {
    const out: number[] = [];
    for (let i = 0; i < 8 && cursor + i < sourceLen; i++) {
      const b = byteAt(cursor + i);
      if (b === undefined) break;
      out.push(b);
    }
    return new Uint8Array(out);
  })();

  const rootFormat = rootNode?.interpretation?.format;

  return (
    <div className="explorer">
      <header className="topbar">
        <button type="button" className="brand" onClick={onClose} title="Close the file">
          fillyfoal
        </button>
        <div className="file-chip" title={file.name}>
          <FileIcon />
          <span className="file-name">{file.name}</span>
          <span className="file-meta">{formatSize(file.size)}</span>
          {rootFormat && (
            <span className={`badge ${rootNode?.interpretation?.forced ? "badge-forced" : "badge-strong"}`} title={rootFormat.title}>
              {rootFormat.title}
            </span>
          )}
          {rootNode && !rootFormat && rootNode.interpretation && <span className="badge">Not recognised</span>}
        </div>
        <div className="toolbar">
          <ToolButton label="Filter" kbd="/" active={filter !== null} onClick={() => {
            if (filter === null) setFilter("");
            requestAnimationFrame(() => filterRef.current?.focus());
          }}>
            <SearchIcon />
          </ToolButton>
          <ToolButton label="Go to offset" kbd="G" onClick={() => setGoToOpen(true)}>
            <JumpIcon />
          </ToolButton>
          <ToolButton label="Dissect as…" kbd="D" onClick={() => void openDissectAs()}>
            <WandIcon />
          </ToolButton>
          <ToolButton label="Bytes panel" kbd="B" active={bytesOpen} onClick={toggleBytes}>
            <HexIcon />
          </ToolButton>
          <ToolButton label="Keyboard shortcuts" kbd="?" onClick={() => setHelpOpen(true)}>
            <KeyboardIcon />
          </ToolButton>
          <button type="button" className="button button-primary" onClick={onOpen}>
            Open file
          </button>
        </div>
      </header>

      <div className="workspace">
        <section className="tree-pane" aria-label="Structure">
          {filter !== null && (
            <div className="filter-bar">
              <SearchIcon />
              <input
                ref={filterRef}
                className="filter-input"
                value={filter}
                placeholder="Filter loaded fields (regex)"
                aria-label="Filter"
                autoFocus
                spellCheck={false}
                autoComplete="off"
                onChange={(e) => setFilter(e.target.value)}
                onFocus={() => setZone("tree")}
                onKeyDown={(e) => {
                  switch (e.key) {
                    case "Escape":
                      e.preventDefault();
                      e.stopPropagation();
                      setFilter(null);
                      focusZone("tree");
                      break;
                    case "Enter":
                    case "Tab":
                      e.preventDefault();
                      focusZone("tree");
                      break;
                    case "ArrowUp":
                    case "ArrowDown":
                    case "PageUp":
                    case "PageDown":
                      onTreeKey(e);
                      break;
                  }
                }}
              />
              <span className="filter-count">
                {pattern ? `${matches.toLocaleString()} matching` : filter && !pattern ? "invalid pattern" : ""}
              </span>
              <button type="button" className="icon-button" aria-label="Close filter" onClick={() => {
                setFilter(null);
                focusZone("tree");
              }}>
                <CloseIcon />
              </button>
            </div>
          )}
          <div
            className={`tree${pattern ? " tree-filtered" : ""}`}
            ref={treeRef}
            tabIndex={0}
            role="tree"
            aria-label={`Structure of ${file.name}`}
            onKeyDown={onTreeKey}
            onFocus={() => setZone("tree")}
            onScroll={(e) => setTreeTop(e.currentTarget.scrollTop)}
            onContextMenu={openMenu}
          >
            <div style={{ height: rows.length * TREE_ROW + 8, position: "relative" }}>{treeRows}</div>
            {error && (
              <div className="tree-error">
                <strong>Something went wrong.</strong> {error}
                <button type="button" className="link" onClick={() => setError(null)}>
                  Dismiss
                </button>
              </div>
            )}
            {session === null && !error && (
              <div className="placeholder">
                <Spinner />
                Starting the dissector…
              </div>
            )}
          </div>
        </section>

        <aside className="side" hidden={!bytesOpen}>
          <div className="source-bar">
            <span className="source-label" title={sourceLabel}>
              {source === fileSource ? <FileIcon /> : <StreamIcon />}
              {sourceLabel}
            </span>
            <span className="source-len" title={lenKnown ? undefined : "Not known until the stream has been decoded to its end"}>
              {lenKnown ? formatSize(sourceLen) : "size unknown"}
            </span>
          </div>
          <div className="hex-wrap">
            <div
              className="hex"
              ref={hexRef}
              tabIndex={0}
              role="grid"
              aria-label="Bytes"
              onKeyDown={onHexKey}
              onFocus={() => setZone("hex")}
              onPointerDown={onHexPointerDown}
              onScroll={(e) =>
                setHexTop(
                  Math.min(
                    Math.max(0, hexRows - hexVisible),
                    Math.floor((e.currentTarget.scrollTop * hexScale) / HEX_ROW),
                  ),
                )
              }
            >
              <div className="hex-content" style={{ height: Math.min(hexNatural, MAX_SCROLL_HEIGHT) }}>
                {hexLines}
              </div>
              {sourceLen === 0 && session !== null && <div className="hex-empty">No bytes</div>}
            </div>
          </div>
          <Details
            node={node}
            zone={zone}
            source={sourceLabel}
            sizeOf={sizeOf}
            onFollow={followTarget}
            onSave={() => void saveSelected()}
            onCopyBytes={() => void copyBytes(span, "hex")}
            onCopyValue={copyValue}
            inspector={
              zone === "hex" || range ? (
                <Inspector offset={cursor} bytes={inspectorBytes} selection={range ? selEnd - selStart + 1 : 0} />
              ) : null
            }
          />
        </aside>
      </div>

      <footer className="statusbar">
        <nav className="crumbs" aria-label="Path">
          <div className="crumbs-inner">
          {breadcrumb.map((k, i) => (
            <React.Fragment key={k}>
              {i > 0 && <span className="crumb-sep">›</span>}
              <button
                type="button"
                tabIndex={-1}
                className="crumb"
                onClick={() => {
                  setSelected(k);
                  treeRef.current?.focus();
                }}
              >
                {nodes.get(k)?.name ?? "…"}
              </button>
            </React.Fragment>
          ))}
          </div>
        </nav>
        <span className="status-right">
          {choices.length > 0 && (
            <span className="muted" title={choices.map((c) => `${c.path.join("/") || "file"} → ${c.format}`).join("\n")}>
              {choices.length} format {choices.length === 1 ? "choice" : "choices"}
            </span>
          )}
          {showBusy && busyText && (
            <span className="busy">
              <Spinner />
              {busyText}
              {busyPercent !== null && (
                <span className="progress" aria-hidden>
                  <span style={{ width: `${busyPercent}%` }} />
                </span>
              )}
              <button type="button" className="button button-small" onClick={() => stop(null)} title="Stop (Esc)">
                Stop
              </button>
            </span>
          )}
          <span className="mono" role="status">
            {zone === "hex" || range
              ? range
                ? `Sel ${hexOffset(selStart)}–${hexOffset(selEnd)} (${formatSize(selEnd - selStart + 1)})`
                : `Offset ${hexOffset(cursor)}`
              : span
                ? `${hexOffset(span.offset)} + ${sizeOf(span)}`
                : ""}
          </span>
        </span>
      </footer>

      {pickerTarget && (
        <FormatPicker
          target={pickerTarget}
          onPick={(picked) => void pickFormat(picked)}
          onClose={() => {
            setPickerTarget(null);
            focusZone(zone);
          }}
        />
      )}
      {secret && <PasswordBar request={secret.request} onAnswer={answerSecret} />}
      {goToOpen && (
        <GoToBar
          sourceLabel={sourceLabel}
          max={sourceLen}
          onClose={() => {
            setGoToOpen(false);
            focusZone(zone);
          }}
          onSubmit={(v) => {
            setGoToOpen(false);
            goToOffset(v);
            focusZone("hex");
          }}
        />
      )}
      {menu && (
        <ContextMenu
          x={menu.x}
          y={menu.y}
          items={menuItems}
          onClose={() => {
            setMenu(null);
            treeRef.current?.focus();
          }}
        />
      )}
      {helpOpen && <Help onClose={() => setHelpOpen(false)} />}
      {toast && (
        <div className="toast" role="status">
          {toast}
        </div>
      )}
    </div>
  );
}

function percentOf({ done, total }: ProgressEvent): number {
  return Math.min(100, Math.floor((done * 100) / Math.max(total, 1)));
}

function Spinner() {
  return <span className="spinner" aria-hidden />;
}

/// `children` once whatever mounted it has been going on for a moment,
/// `before` until then: a quick load never shows as one.
function AfterGrace({ children, before = null }: { children: React.ReactNode; before?: React.ReactNode }) {
  return <>{useAfterGrace(true) ? children : before}</>;
}

function ToolButton({
  label,
  kbd,
  active,
  onClick,
  children,
}: {
  label: string;
  kbd: string;
  active?: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      className="tool"
      aria-pressed={active}
      onClick={onClick}
      data-tip={`${label} (${kbd})`}
      aria-label={label}
    >
      {children}
    </button>
  );
}

function Details({
  node,
  zone,
  source,
  sizeOf,
  onFollow,
  onSave,
  onCopyBytes,
  onCopyValue,
  inspector,
}: {
  node: FieldNode | null;
  zone: Zone;
  source: string;
  sizeOf: (span: Span) => string;
  onFollow: () => void;
  onSave: () => void;
  onCopyBytes: () => void;
  onCopyValue: () => void;
  inspector: React.ReactNode;
}) {
  if (!node) return <div className="details">{inspector}</div>;
  const v = node.value;
  const diagnostics = node.diagnostics.concat(node.children.error ? [node.children.error] : []);
  const count = node.children.count;
  return (
    <div className="details" aria-label="Field details" data-zone={zone}>
      {inspector}
      <div className="details-head">
        <h2 className="details-title">{node.name}</h2>
        <div className="details-actions">
          {v && (
            <button type="button" className="button button-small" onClick={onCopyValue}>
              Copy value
            </button>
          )}
          {node.span && node.span.len > 0 && (
            <>
              <button type="button" className="button button-small" onClick={onCopyBytes}>
                Copy hex
              </button>
              <button type="button" className="button button-small" onClick={onSave} title="Save these bytes (S)">
                Save
              </button>
            </>
          )}
        </div>
      </div>
      <dl className="details-list">
        {v && (
          <>
            <dt>Value</dt>
            <dd className="value" data-kind={v.kind}>
              {v.text}
            </dd>
          </>
        )}
        {v?.raw && (
          <>
            <dt>Raw</dt>
            <dd className="mono">{v.raw}</dd>
          </>
        )}
        {node.summary && (
          <>
            <dt>Summary</dt>
            <dd>{node.summary}</dd>
          </>
        )}
        {node.interpretation && (
          <>
            <dt>Format</dt>
            <dd>
              {node.interpretation.format?.title ?? "Not recognised"}
              {node.interpretation.forced && <span className="muted"> (chosen)</span>}
            </dd>
          </>
        )}
        {node.span && (
          <>
            <dt>Bytes</dt>
            <dd className="mono">
              {hex(node.span.offset)}–{hex(node.span.offset + node.span.len)}{" "}
              <span className="muted sans">
                {sizeOf(node.span)} in {source}
              </span>
            </dd>
          </>
        )}
        {node.target && (
          <>
            <dt>Points to</dt>
            <dd className="mono">
              <button type="button" className="link" onClick={onFollow}>
                {spanText(node.target)} →
              </button>
            </dd>
          </>
        )}
        {node.children.state === "locked" && (
          <>
            <dt>Children</dt>
            <dd>Locked: needs a password</dd>
          </>
        )}
        {count && node.children.state !== "locked" && (
          <>
            <dt>Children</dt>
            <dd>
              {count.at_least ? "at least " : ""}
              {count.n.toLocaleString()}
            </dd>
          </>
        )}
      </dl>
      {node.description && <p className="description">{node.description}</p>}
      {diagnostics.length > 0 && (
        <ul className="diagnostics">
          {diagnostics.map((d, i) => (
            <li key={i} data-kind={d.kind}>
              <span className="diag-kind">{DIAG_LABELS[d.kind]}</span>
              {d.message}
              {d.span && <span className="muted mono"> at {spanText(d.span)}</span>}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/// Asks for the password a dissection waits for. Enter unlocks (an empty
/// password too: some formats default to one), Escape skips the encrypted
/// content.
function PasswordBar({ request, onAnswer }: { request: Secret; onAnswer: (password: string | null) => void }) {
  const [value, setValue] = useState("");
  useEffect(() => setValue(""), [request]);
  return (
    <div className="overlay overlay-light">
      <form
        className="dialog"
        onSubmit={(e) => {
          e.preventDefault();
          onAnswer(value);
        }}
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            e.preventDefault();
            e.stopPropagation();
            onAnswer(null);
          }
        }}
      >
        <div className="dialog-icon">
          <LockIcon />
        </div>
        <h2>{request.attempt > 0 ? "Wrong password" : "Password needed"}</h2>
        <p className="muted">{request.prompt}. It stays in this tab and is only used to decrypt.</p>
        <input
          className="text-input"
          type="password"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          aria-label={request.prompt}
          autoComplete="off"
          autoFocus
        />
        <div className="dialog-buttons">
          <button type="button" className="button" onClick={() => onAnswer(null)}>
            Skip
          </button>
          <button type="submit" className="button button-primary">
            Unlock
          </button>
        </div>
      </form>
    </div>
  );
}

function GoToBar({
  sourceLabel,
  max,
  onSubmit,
  onClose,
}: {
  sourceLabel: string;
  max: number;
  onSubmit: (value: string) => void;
  onClose: () => void;
}) {
  const [value, setValue] = useState("");
  return (
    <div className="overlay overlay-light" onPointerDown={onClose}>
      <form
        className="goto"
        onPointerDown={(e) => e.stopPropagation()}
        onSubmit={(e) => {
          e.preventDefault();
          onSubmit(value);
        }}
      >
        <JumpIcon />
        <input
          className="goto-input"
          autoFocus
          value={value}
          placeholder="Offset in hex, e.g. 1F40"
          spellCheck={false}
          autoComplete="off"
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Escape") {
              e.preventDefault();
              e.stopPropagation();
              onClose();
            }
          }}
        />
        <span className="goto-hint" title={sourceLabel}>
          in {sourceLabel.length > 28 ? `${sourceLabel.slice(0, 27)}…` : sourceLabel} · max {hex(Math.max(0, max - 1))}
        </span>
      </form>
    </div>
  );
}

const SHORTCUTS: [string, string][] = [
  ["↑ ↓ ← →", "Move, expand and collapse in the tree; move the cursor in the bytes"],
  ["Enter / Space", "Expand or collapse; in the bytes, find the field at the cursor"],
  ["*", "Expand everything below, a few levels deep"],
  ["Tab", "Switch between the tree and the bytes"],
  ["/ or " + mod + "F", "Filter the loaded fields"],
  ["G or " + mod + "G", "Go to an offset"],
  ["T", "Go to what the field points to"],
  ["D", "Dissect as another format"],
  ["S or " + mod + "S", "Save the selected bytes, or the field's (an archive member's content)"],
  ["B", "Show or hide the bytes"],
  [mod + "C", "Copy the line, or the selected bytes"],
  ["⇧" + mod + "C", "Copy the value"],
  [mod + "A", "Select the field's bytes"],
  ["Shift + arrows", "Select bytes"],
  ["Esc", "Stop loading; close"],
  [mod + "O", "Open another file"],
];

function Help({ onClose }: { onClose: () => void }) {
  return (
    <div className="overlay" onPointerDown={onClose}>
      <div className="dialog dialog-wide" onPointerDown={(e) => e.stopPropagation()} role="dialog" aria-label="Keyboard shortcuts">
        <div className="dialog-head">
          <h2>Keyboard shortcuts</h2>
          <button type="button" className="icon-button" onClick={onClose} aria-label="Close" autoFocus>
            <CloseIcon />
          </button>
        </div>
        <dl className="shortcuts">
          {SHORTCUTS.map(([k, d]) => (
            <React.Fragment key={k}>
              <dt>
                <kbd>{k}</kbd>
              </dt>
              <dd>{d}</dd>
            </React.Fragment>
          ))}
        </dl>
      </div>
    </div>
  );
}

// --- Icons ---

const icon = {
  width: 16,
  height: 16,
  viewBox: "0 0 16 16",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.5,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  "aria-hidden": true,
};

function Chevron() {
  return (
    <svg {...icon} width={12} height={12} viewBox="0 0 12 12">
      <path d="M4.5 2.5 8 6l-3.5 3.5" />
    </svg>
  );
}
export function FileIcon() {
  return (
    <svg {...icon}>
      <path d="M9 1.75H4.5a1 1 0 0 0-1 1v10.5a1 1 0 0 0 1 1h7a1 1 0 0 0 1-1V5.25L9 1.75Z" />
      <path d="M9 1.75v3.5h3.5" />
    </svg>
  );
}
function StreamIcon() {
  return (
    <svg {...icon}>
      <path d="M2 4.5c2-2 4 2 6 0s4 2 6 0M2 8c2-2 4 2 6 0s4 2 6 0M2 11.5c2-2 4 2 6 0s4 2 6 0" />
    </svg>
  );
}
function SearchIcon() {
  return (
    <svg {...icon}>
      <circle cx="7" cy="7" r="4.25" />
      <path d="m10.25 10.25 3.5 3.5" />
    </svg>
  );
}
function JumpIcon() {
  return (
    <svg {...icon}>
      <path d="M2.5 8h9M8.5 4.5 12 8l-3.5 3.5M14 3v10" />
    </svg>
  );
}
function WandIcon() {
  return (
    <svg {...icon}>
      <path d="m2.5 13.5 8-8M9 4l1.5 1.5M12 1.75v2M13 2.75h-2M13.75 6.5v1.5M14.5 7.25H13M6.5 1.75V3M7.125 2.375h-1.25" />
    </svg>
  );
}
function HexIcon() {
  return (
    <svg {...icon}>
      <rect x="1.75" y="2.75" width="12.5" height="10.5" rx="1.5" />
      <path d="M4.5 6h2M4.5 8h2M4.5 10h2M9 6h2.5M9 8h2.5M9 10h2.5" />
    </svg>
  );
}
function KeyboardIcon() {
  return (
    <svg {...icon}>
      <rect x="1.5" y="3.75" width="13" height="8.5" rx="1.5" />
      <path d="M4 6.5h.01M6.5 6.5h.01M9 6.5h.01M11.5 6.5h.01M5 9.5h6" />
    </svg>
  );
}
function CloseIcon() {
  return (
    <svg {...icon}>
      <path d="m4 4 8 8M12 4l-8 8" />
    </svg>
  );
}
function LockIcon() {
  return (
    <svg {...icon}>
      <rect x="3" y="7" width="10" height="7" rx="1.5" />
      <path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2" />
    </svg>
  );
}
