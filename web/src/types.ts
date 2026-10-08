// What the worker sends: the JSON the wasm bindings produce, and what the
// worker builds out of it.

export type ChildrenState =
  | "leaf"
  /// Not expanded yet.
  | "unloaded"
  /// The expansion waits for a password.
  | "locked"
  /// More children follow those loaded.
  | "more"
  /// Its expansion was stopped part-way; asking again continues it.
  | "stopped"
  | "complete"
  /// The expansion failed; children produced before it remain.
  | "failed";

export type Span = {
  /// The byte space: the file, or a stream decoded or reassembled from it.
  source: number;
  offset: number;
  len: number;
};

export type DiagnosticKind =
  | "truncated"
  | "malformed"
  | "unsupported"
  | "limit"
  | "warning"
  | "note";

export type Diagnostic = {
  kind: DiagnosticKind;
  message: string;
  span: Span | null;
};

export type ValueKind =
  | "bool"
  | "number"
  | "enum"
  | "flags"
  | "float"
  | "time"
  | "text"
  | "bytes"
  | "guid";

export type FieldValue = {
  kind: ValueKind;
  /// The value as read: a name for an enum, the set flags, the number in the
  /// radix the format gives it.
  text: string;
  /// The number underneath, in the other radix (or the raw integer of an
  /// enum, flags or timestamp).
  raw: string | null;
};

export type FieldNode = {
  key: number;
  name: string;
  value: FieldValue | null;
  summary: string | null;
  description: string | null;
  span: Span | null;
  /// What the field points to (an offset field's target).
  target: Span | null;
  diagnostics: Diagnostic[];
  /// What dissects the node's content, for one holding a file within the
  /// file; known once it has been expanded.
  interpretation: {
    format: { name: string; title: string } | null;
    forced: boolean;
  } | null;
  children: {
    state: ChildrenState;
    loaded: number;
    count: { n: number; at_least: boolean } | null;
    error: Diagnostic | null;
  };
};

export type Secret = {
  index: number;
  /// What it unlocks, e.g. "Password for the encrypted ZIP entries".
  prompt: string;
  /// 0 at first; more after a wrong password.
  attempt: number;
};

export type Page = {
  parent: FieldNode;
  /// Every child loaded so far.
  nodes: FieldNode[];
  secret: Secret | null;
};

/// A format chosen for the file (an empty path) or for a file within it, by
/// the child indices down to it.
export type Choice = { path: number[]; format: string };

export type Located = {
  /// Keys from the root down to the node found.
  path: number[];
  /// The children of each node on the path that has any loaded.
  pages: Page[];
  secret: Secret | null;
};

export type Content = {
  node: FieldNode;
  /// The file's name, for suggesting formats by its extension.
  name: string;
};

export type Format = {
  name: string;
  title: string;
  extensions: string[];
  /// It lists the file's extension.
  suggested: boolean;
};

export type SourceInfo = {
  /// An upper bound until `len_known`.
  len: number;
  /// Whether `len` is the real length: not for a stream decoded on demand
  /// whose size nothing records, until it has been decoded to its end.
  len_known: boolean;
  /// Where a decoded or reassembled stream came from (none for the file).
  origin: { parent: Span; transform: string } | null;
};

export type Opened = {
  session: number;
  fileSource: number;
  page: Page;
};

/// How far a node's expansion has got.
export type ProgressEvent = {
  session: number;
  node: number;
  done: number;
  total: number;
};

/// Every request the worker answers, by method: arguments and result.
export type Api = {
  open: [{ file: Blob; name: string; choices: Choice[] }, Opened];
  close: [{ session: number }, void];
  stop: [{ session: number; node: number | null }, void];
  children: [{ session: number; node: number; atLeast: number }, Page];
  contentOf: [{ session: number; node: number }, Content | null];
  reinterpret: [
    { session: number; node: number; format: string | null },
    { located: Located; choices: Choice[] },
  ];
  locate: [{ session: number; source: number; offset: number }, Located];
  answerSecret: [
    { session: number; index: number; password: string | null },
    void,
  ];
  source: [{ session: number; source: number }, SourceInfo];
  read: [
    { session: number; source: number; offset: number; len: number },
    Uint8Array,
  ];
  formats: [{ name: string }, Format[]];
  engineUrl: [Record<string, never>, string];
};

export type Method = keyof Api;

export type Request<M extends Method = Method> = {
  id: number;
  method: M;
  args: Api[M][0];
};

export type Response =
  | { id: number; ok: true; result: unknown }
  | { id: number; ok: false; error: string; cancelled: boolean }
  | { event: "progress"; progress: ProgressEvent }
  | { event: "ready" };
