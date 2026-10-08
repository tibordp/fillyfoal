/// <reference lib="webworker" />
// The dissections, off the page's thread. Each is a fillyfoal session over a
// file the page handed over; the session asks for bytes and this side reads
// them with `Blob.slice()`, so only what the tree is expanded over is ever
// read. Requests share a dissection: each holds it for one step of work, so a
// long expansion never keeps the others (or a request to stop) waiting.

import init, { Dissection, formats } from "./wasm-pkg/fillyfoal_wasm.js";
import type {
  Api,
  Choice,
  Content,
  Located,
  Method,
  Page,
  Request,
  Response,
  Span,
} from "./types";

declare const self: DedicatedWorkerGlobalScope;

/// Work units per call into the session.
const BUDGET = 10_000;
/// How long the worker runs before it lets other requests in.
const SLICE_MS = 12;
/// Children produced per request for more.
const PAGE = 200;
/// How many children `locate` looks through under one node before giving up
/// on it.
const LOCATE_SCAN = 20_000;
const LOCATE_DEPTH = 64;
/// How many of a node's children `contentOf` looks through for the file it
/// holds.
const CONTENT_SCAN = 16;
/// Largest byte range a read may ask for at once.
const MAX_READ = 256 * 1024 * 1024;
/// How often a running expansion reports how far it has got, and how long it
/// runs before it starts to: a quick one never does.
const PROGRESS_MS = 100;

class Cancelled extends Error {
  constructor() {
    super("operation cancelled");
  }
}

// --- Yielding to the event loop without setTimeout's clamping ---

const channel = new MessageChannel();
const waiting: (() => void)[] = [];
channel.port1.onmessage = () => waiting.shift()?.();
const yieldNow = () =>
  new Promise<void>((resolve) => {
    waiting.push(resolve);
    channel.port2.postMessage(null);
  });

type Token = { cancelled(): boolean };

const ok = (r: string): any => JSON.parse(r);

class Session {
  readonly root: number;
  readonly fileSource: number;
  /// Bumped to stop every request so far, or one node's.
  private generation = 0;
  private nodeGenerations = new Map<number, number>();
  private sliceStart = performance.now();
  /// Requests about it still running, and whether it has been closed: it
  /// is freed once both say so.
  inflight = 0;
  closed = false;

  constructor(
    readonly id: number,
    readonly d: Dissection,
    readonly file: Blob,
  ) {
    this.root = d.root();
    this.fileSource = d.fileSource();
  }

  /// What stops a request: everything stopping, or for one about `node`,
  /// that node's work stopping.
  token(node: number | null): Token {
    const all = this.generation;
    const own = node === null ? 0 : (this.nodeGenerations.get(node) ?? 0);
    return {
      cancelled: () =>
        this.generation !== all ||
        (node !== null && (this.nodeGenerations.get(node) ?? 0) !== own),
    };
  }

  stop(node: number | null) {
    if (node === null) this.generation++;
    else
      this.nodeGenerations.set(node, (this.nodeGenerations.get(node) ?? 0) + 1);
  }

  /// Let other requests in once this one has run for a while.
  private async pace() {
    if (performance.now() - this.sliceStart < SLICE_MS) return;
    await yieldNow();
    this.sliceStart = performance.now();
  }

  /// Read the file bytes the session asked for into it.
  private async fetch(requests: Span[]) {
    const read = await Promise.all(
      requests.map(async (r) => {
        const end = r.offset + r.len;
        const data = new Uint8Array(
          await this.file.slice(r.offset, end).arrayBuffer(),
        );
        return { r, data };
      }),
    );
    for (const { r, data } of read) {
      this.d.supply(r.source, r.offset, data);
      if (data.length < r.len) {
        this.d.setSourceLen(r.source, r.offset + data.length);
      }
    }
  }

  /// Run `key`'s expansion until it has what was asked of it, reading what
  /// it needs, until it waits for a password, or until stopped.
  async drive(key: number, token: Token) {
    const started = performance.now();
    let reported = started;
    for (;;) {
      if (token.cancelled()) return;
      const r = ok(this.d.poll(key, BUDGET));
      if (r.step === "idle" || r.step === "secret") return;
      if (r.step === "bytes") await this.fetch(r.requests);
      await this.pace();
      const now = performance.now();
      if (
        r.progress &&
        now - started >= PROGRESS_MS &&
        now - reported >= PROGRESS_MS
      ) {
        reported = now;
        const [done, total] = r.progress;
        post({
          event: "progress",
          progress: { session: this.id, node: key, done, total },
        });
      }
    }
  }

  /// Have at least `atLeast` children of `key`, or all of them.
  async expand(key: number, atLeast: number, token: Token) {
    this.d.expand(key, atLeast);
    await this.drive(key, token);
  }

  /// The bytes of a span, from the file, a decoded stream or the pieces a
  /// fragmented one is made of, decoded a step at a time.
  async read(span: Span, token: Token): Promise<Uint8Array> {
    if (span.len > MAX_READ) {
      throw new Error(`${span.len} bytes is more than can be read at once`);
    }
    if (span.source === this.fileSource) {
      const end = Math.min(span.offset + span.len, this.file.size);
      return new Uint8Array(
        await this.file.slice(span.offset, end).arrayBuffer(),
      );
    }
    for (;;) {
      if (token.cancelled()) throw new Cancelled();
      const r = ok(this.d.readStep(span.source, span.offset, span.len, BUDGET));
      if (r.step === "done") return this.d.takeRead();
      if (r.step === "bytes") await this.fetch(r.requests);
      await this.pace();
    }
  }

  /// Whether `key` holds a file within the file. Only its expansion tells,
  /// so an unexpanded node is expanded.
  async holdsContent(key: number, token: Token) {
    if (!this.d.holdsContent(key) && this.d.childState(key) === "unloaded") {
      await this.expand(key, 1, token);
    }
    return this.d.holdsContent(key);
  }

  /// The node holding the file within the file that `key` stands for: `key`
  /// itself, or else the one child that holds one, as an archive member
  /// holds its data beside its headers.
  async contentOf(key: number, token: Token): Promise<number | null> {
    if (await this.holdsContent(key, token)) return key;
    if (this.d.childState(key) !== "leaf") {
      await this.expand(key, CONTENT_SCAN, token);
    }
    const children = Array.from(this.d.childKeys(key)).slice(0, CONTENT_SCAN);
    const holding = [];
    for (const child of children) {
      if (await this.holdsContent(child, token)) holding.push(child);
    }
    if (token.cancelled()) throw new Cancelled();
    return holding.length === 1 ? holding[0] : null;
  }

  /// The path from the root to the innermost node whose bytes include
  /// `offset` of `source`, expanding along the way; as far as it got when
  /// stopped.
  async locate(source: number, offset: number, token: Token) {
    const path = [this.root];
    let current = this.root;
    while (path.length < LOCATE_DEPTH && !token.cancelled()) {
      let scanned = 0;
      let found: number | null = null;
      for (;;) {
        if (this.d.childState(current) === "unloaded") {
          await this.expand(current, PAGE, token);
        }
        if (this.d.childState(current) === "leaf") break;
        const loaded = this.d.childCount(current);
        while (found === null && scanned < loaded) {
          const r = ok(this.d.findChildAt(current, scanned, source, offset));
          found = r.found;
          scanned = r.scanned;
        }
        const more = this.d.childState(current) === "more";
        if (
          found !== null ||
          !more ||
          scanned > LOCATE_SCAN ||
          token.cancelled()
        ) {
          break;
        }
        this.d.expandMore(current, PAGE);
        await this.drive(current, token);
      }
      if (found === null) break;
      path.push(found);
      current = found;
    }
    return path;
  }

  page(key: number): Page {
    return ok(this.d.page(key));
  }

  /// The pages along `path` (those with children), for the page to merge.
  located(path: number[], withLast: boolean): Located {
    const along = withLast ? path : path.slice(0, -1);
    return {
      path,
      pages: along.map((k) => this.page(k)),
      secret: ok(this.d.secret()),
    };
  }
}

// --- Requests ---

const sessions = new Map<number, Session>();
let nextSession = 1;

/// A request about a dissection that has been closed (another file was
/// opened while it was in flight) was, in effect, stopped.
function session(id: number): Session {
  const s = sessions.get(id);
  if (!s) throw new Cancelled();
  return s;
}

type Handlers = {
  [M in Method]: (args: Api[M][0]) => Promise<Api[M][1]> | Api[M][1];
};

const handlers: Handlers = {
  open({ file, name, choices }) {
    const d = new Dissection(name, file.size, JSON.stringify(choices));
    const id = nextSession++;
    const s = new Session(id, d, file);
    sessions.set(id, s);
    return { session: id, fileSource: s.fileSource, page: s.page(s.root) };
  },

  close({ session: id }) {
    const s = sessions.get(id);
    if (!s) return;
    s.stop(null);
    sessions.delete(id);
    s.closed = true;
    if (s.inflight === 0) s.d.free();
  },

  stop({ session: id, node }) {
    sessions.get(id)?.stop(node);
  },

  async children({ session: id, node, atLeast }) {
    const s = session(id);
    await s.expand(node, atLeast, s.token(node));
    return s.page(node);
  },

  async contentOf({ session: id, node }): Promise<Content | null> {
    const s = session(id);
    const content = await s.contentOf(node, s.token(node));
    if (content === null) return null;
    return {
      name: s.d.contentName(content),
      node: ok(s.d.node(content)),
    };
  },

  async reinterpret({ session: id, node, format }) {
    const s = session(id);
    s.d.reinterpret(node, format);
    await s.expand(node, PAGE, s.token(node));
    const path = Array.from(s.d.pathTo(node));
    const choices: Choice[] = ok(s.d.choices());
    return { located: s.located(path, true), choices };
  },

  async locate({ session: id, source, offset }) {
    const s = session(id);
    const path = await s.locate(source, offset, s.token(null));
    return s.located(path, false);
  },

  answerSecret({ session: id, index, password }) {
    session(id).d.answerSecret(index, password ?? undefined);
  },

  source({ session: id, source }) {
    return ok(session(id).d.sourceInfo(source));
  },

  async read({ session: id, source, offset, len }) {
    const s = session(id);
    return s.read({ source, offset, len }, s.token(null));
  },

  formats({ name }) {
    return ok(formats(name));
  },

  engineUrl() {
    return ENGINE_URL;
  },
};

function post(message: Response, transfer: Transferable[] = []) {
  self.postMessage(message, transfer);
}

/// Where the engine is loaded from; the page fetches it again (from the
/// cache) to show fillyfoal its own module.
const ENGINE_URL = new URL("./wasm-pkg/fillyfoal_wasm_bg.wasm", import.meta.url).href;
const ready = init({ module_or_path: ENGINE_URL });

self.onmessage = async (e: MessageEvent<Request>) => {
  const { id, method, args } = e.data;
  // Whatever the request is about stays allocated until it's done.
  const about =
    method !== "close" && "session" in args ? sessions.get(args.session) : undefined;
  if (about) about.inflight++;
  try {
    await ready;
    const handler = handlers[method] as (a: unknown) => unknown;
    const result = await handler(args);
    const transfer =
      result instanceof Uint8Array ? [result.buffer as ArrayBuffer] : [];
    post({ id, ok: true, result }, transfer);
  } catch (err) {
    post({
      id,
      ok: false,
      error: err instanceof Error ? err.message : String(err),
      cancelled: err instanceof Cancelled || !!about?.closed,
    });
  } finally {
    if (about && --about.inflight === 0 && about.closed) about.d.free();
  }
};

ready.then(
  () => post({ event: "ready" }),
  (err) => console.error("fillyfoal: failed to load", err),
);
