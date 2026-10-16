//! Terraform saved plans (`terraform plan -out=FILE`).
//!
//! A saved plan is a ZIP archive (the `terraform-plan` variant in `zip.rs`)
//! holding `tfplan`, the plan itself as a protocol buffer; `tfstate` and
//! `tfstate-prev`, the state snapshots it was made against (JSON);
//! `tfconfig/`, the configuration's source files with `modules.json`; and
//! the dependency lock file `.terraform.lock.hcl`. Everything but `tfplan`
//! is dissected by the ZIP member's own format.
//!
//! `tfplan` has no magic: it is found by its member name and a protobuf
//! check of its start (a plan begins with its format version, field 1),
//! in the second probing phase. Message and field names, numbers and enum
//! values are taken from Terraform's `internal/plans/planproto/planfile.proto`
//! (facts only); the layout was checked against plans written by Terraform
//! 1.16.6. Values (`DynamicValue`) are MessagePack-encoded `cty` values,
//! shown as go-cty's `msgpack` package reads them (facts from its
//! `unknown.go`; the dynamic pair as Terraform 1.16.6 writes it): nil is
//! null; an extension of at most a
//! byte (Terraform writes type 0) is an unknown value, "known after
//! apply"; extension 12 is an unknown with refinements (a map by key: 1
//! not null, 2 a string prefix, 3 and 4 number bounds with their
//! inclusiveness, 5 and 6 collection length bounds); and a value of a
//! dynamic type is a pair of its type (JSON, as binary) and the value,
//! shown as the value with its type. Lists, sets and tuples are arrays,
//! maps and objects are maps. Values over 16 MiB go to the MessagePack
//! dissector instead.

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::fmt::plural;
use crate::formats::util::wire::protobuf::{self as pb, F, LEN, Msg, Payload, Ty, VARINT, f};
use crate::formats::{DeepProbe, Format, Input, Probe, embedded_named};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

/// Messages nested deeper than this are not expanded.
const MAX_DEPTH: u32 = 32;
/// Messages up to this size are read to compute their summary.
const TITLE_MAX: u64 = 16 * 1024;
/// How much of a string field is shown.
const TEXT_MAX: u64 = 512;

pub static TFPLAN: Format = Format {
    name: "terraform-tfplan",
    title: "Terraform plan (protobuf)",
    extensions: &[],
    mime: "application/x-protobuf",
    probe: Probe::Never,
    dissect: crate::expander!(dissect: Input),
};

/// The `tfplan` member of a saved plan: its name, then a well-formed
/// message that starts with a small format version (field 1) and whose
/// fields in the probe window are all fields of `Plan`.
pub static TFPLAN_DEEP: DeepProbe = DeepProbe {
    format: &TFPLAN,
    tail: false,
    over: &[],
    probe: deep_probe,
};

fn deep_probe(d: &crate::formats::Deep<'_>) -> bool {
    let named = d
        .name
        .is_some_and(|n| n == "tfplan" || n.ends_with("/tfplan"));
    named && looks_like_plan(d.head.data)
}

/// The format of content given as a plan that does not look like one, if
/// the first phase of identification recognises it.
async fn not_a_plan(cx: &Cx, span: Span) -> Result<Option<&'static Format>> {
    let (data, tail) = crate::formats::head(cx, span).await?;
    if looks_like_plan(&data) {
        return Ok(None);
    }
    let (found, units) = cx.registry().identify_costed(&crate::formats::Head {
        data: &data,
        tail: &tail,
        len: span.len,
        len_known: cx.len_known(span.source),
    });
    // Probes run synchronously over the head; charge them.
    cx.charge(units).await;
    Ok(found.filter(|f| !std::ptr::eq(*f, &TFPLAN)))
}

fn looks_like_plan(data: &[u8]) -> bool {
    let mut at = 0usize;
    let Some(first) = pb::field(data, &mut at) else {
        return false;
    };
    if first.number != 1 || first.wire != VARINT || !(1..=64).contains(&first.value) {
        return false;
    }
    let mut seen = 1usize;
    while at < data.len() && seen < 64 {
        let Some(field) = pb::field(data, &mut at) else {
            // A field cut off by the end of the probe window is fine.
            return true;
        };
        let known = PLAN.fields.iter().find(|s| s.num == field.number);
        let wire_ok = match known.map(|s| s.ty) {
            Some(Ty::Int | Ty::Bool | Ty::Enum(_)) => field.wire == VARINT,
            Some(_) => field.wire == LEN,
            None => false,
        };
        if !wire_ok {
            return false;
        }
        seen = seen.saturating_add(1);
    }
    true
}

// ---------------------------------------------------------------------------
// Schema (planfile.proto)

const MODE: EnumTable = &[(0, "NORMAL"), (1, "DESTROY"), (2, "REFRESH_ONLY")];

const ACTION: EnumTable = &[
    (0, "NOOP"),
    (1, "CREATE"),
    (2, "READ"),
    (3, "UPDATE"),
    (5, "DELETE"),
    (6, "DELETE_THEN_CREATE"),
    (7, "CREATE_THEN_DELETE"),
    (8, "FORGET"),
    (9, "CREATE_THEN_FORGET"),
    (10, "FORGET_THEN_CREATE"),
];

const ACTION_REASON: EnumTable = &[
    (0, "NONE"),
    (1, "REPLACE_BECAUSE_TAINTED"),
    (2, "REPLACE_BY_REQUEST"),
    (3, "REPLACE_BECAUSE_CANNOT_UPDATE"),
    (4, "DELETE_BECAUSE_NO_RESOURCE_CONFIG"),
    (5, "DELETE_BECAUSE_WRONG_REPETITION"),
    (6, "DELETE_BECAUSE_COUNT_INDEX"),
    (7, "DELETE_BECAUSE_EACH_KEY"),
    (8, "DELETE_BECAUSE_NO_MODULE"),
    (9, "REPLACE_BY_TRIGGERS"),
    (10, "READ_BECAUSE_CONFIG_UNKNOWN"),
    (11, "READ_BECAUSE_DEPENDENCY_PENDING"),
    (12, "DELETE_BECAUSE_NO_MOVE_TARGET"),
    (13, "READ_BECAUSE_CHECK_NESTED"),
];

const CHECK_STATUS: EnumTable = &[(0, "UNKNOWN"), (1, "PASS"), (2, "FAIL"), (3, "ERROR")];

const CHECK_KIND: EnumTable = &[
    (0, "UNSPECIFIED"),
    (1, "RESOURCE"),
    (2, "OUTPUT_VALUE"),
    (3, "CHECK"),
    (4, "INPUT_VARIABLE"),
];

const DEFERRED_REASON: EnumTable = &[
    (0, "INVALID"),
    (1, "INSTANCE_COUNT_UNKNOWN"),
    (2, "RESOURCE_CONFIG_UNKNOWN"),
    (3, "PROVIDER_CONFIG_UNKNOWN"),
    (4, "ABSENT_PREREQ"),
    (5, "DEFERRED_PREREQ"),
];

const TRIGGER_EVENT: EnumTable = &[
    (0, "INVALID_EVENT"),
    (1, "BEFORE_CREATE"),
    (2, "AFTER_CREATE"),
    (3, "BEFORE_UPDATE"),
    (4, "AFTER_UPDATE"),
    (5, "BEFORE_DESTROY"),
    (6, "AFTER_DESTROY"),
    (7, "INVOKE"),
];

const ON_FAILURE: EnumTable = &[
    (0, "ON_FAILURE_HALT"),
    (1, "ON_FAILURE_TAINT"),
    (2, "ON_FAILURE_CONTINUE"),
];

/// A MessagePack-encoded `cty` value (field 1), dissected as MessagePack.
static DYNAMIC_VALUE: Msg = Msg {
    name: "DynamicValue",
    fields: &[f(1, "msgpack", Ty::Bytes)],
    title: &[],
};

static VARIABLE: Msg = Msg {
    name: "variable",
    fields: &[f(1, "key", Ty::Str), f(2, "value", Ty::Msg(&DYNAMIC_VALUE))],
    title: &[1],
};

static STEP: Msg = Msg {
    name: "Path.Step",
    fields: &[
        f(1, "attribute_name", Ty::Str),
        f(2, "element_key", Ty::Msg(&DYNAMIC_VALUE)),
    ],
    title: &[1],
};

static PATH: Msg = Msg {
    name: "Path",
    fields: &[f(1, "steps", Ty::Msg(&STEP))],
    title: &[],
};

static IMPORTING: Msg = Msg {
    name: "Importing",
    fields: &[
        f(1, "id", Ty::Str),
        f(2, "unknown", Ty::Bool),
        f(3, "identity", Ty::Msg(&DYNAMIC_VALUE)),
    ],
    title: &[1],
};

static CHANGE: Msg = Msg {
    name: "Change",
    fields: &[
        f(1, "action", Ty::Enum(ACTION)),
        f(2, "values", Ty::Msg(&DYNAMIC_VALUE)),
        f(3, "before_sensitive_paths", Ty::Msg(&PATH)),
        f(4, "after_sensitive_paths", Ty::Msg(&PATH)),
        f(5, "importing", Ty::Msg(&IMPORTING)),
        f(6, "generated_config", Ty::Str),
        f(7, "before_identity", Ty::Msg(&DYNAMIC_VALUE)),
        f(8, "after_identity", Ty::Msg(&DYNAMIC_VALUE)),
    ],
    title: &[1],
};

static RESOURCE_CHANGE: Msg = Msg {
    name: "ResourceInstanceChange",
    fields: &[
        f(13, "addr", Ty::Str),
        f(14, "prev_run_addr", Ty::Str),
        f(7, "deposed_key", Ty::Str),
        f(8, "provider", Ty::Str),
        f(9, "change", Ty::Msg(&CHANGE)),
        f(10, "private", Ty::Bytes),
        f(11, "required_replace", Ty::Msg(&PATH)),
        f(12, "action_reason", Ty::Enum(ACTION_REASON)),
    ],
    title: &[13],
};

static DEFERRED: Msg = Msg {
    name: "Deferred",
    fields: &[f(1, "reason", Ty::Enum(DEFERRED_REASON))],
    title: &[1],
};

static DEFERRED_CHANGE: Msg = Msg {
    name: "DeferredResourceInstanceChange",
    fields: &[
        f(1, "deferred", Ty::Msg(&DEFERRED)),
        f(2, "change", Ty::Msg(&RESOURCE_CHANGE)),
    ],
    title: &[],
};

static RESOURCE_TRIGGER: Msg = Msg {
    name: "ResourceActionTrigger",
    fields: &[
        f(1, "triggering_resource_addr", Ty::Str),
        f(2, "trigger_event", Ty::Enum(TRIGGER_EVENT)),
        f(3, "action_trigger_block_index", Ty::Int),
        f(4, "actions_list_index", Ty::Int),
        f(5, "on_failure", Ty::Enum(ON_FAILURE)),
    ],
    title: &[1],
};

static INVOKE_TRIGGER: Msg = Msg {
    name: "InvokeActionTrigger",
    fields: &[f(1, "calling_resource_addr", Ty::Str)],
    title: &[1],
};

static ACTION_INVOCATION: Msg = Msg {
    name: "ActionInvocationInstance",
    fields: &[
        f(1, "addr", Ty::Str),
        f(2, "provider", Ty::Str),
        f(4, "config_value", Ty::Msg(&DYNAMIC_VALUE)),
        f(5, "sensitive_config_paths", Ty::Msg(&PATH)),
        f(6, "resource_action_trigger", Ty::Msg(&RESOURCE_TRIGGER)),
        f(7, "invoke_action_trigger", Ty::Msg(&INVOKE_TRIGGER)),
    ],
    title: &[1],
};

static DEFERRED_ACTION: Msg = Msg {
    name: "DeferredActionInvocation",
    fields: &[
        f(1, "deferred", Ty::Msg(&DEFERRED)),
        f(2, "action_invocation", Ty::Msg(&ACTION_INVOCATION)),
    ],
    title: &[],
};

static OUTPUT_CHANGE: Msg = Msg {
    name: "OutputChange",
    fields: &[
        f(1, "name", Ty::Str),
        f(2, "change", Ty::Msg(&CHANGE)),
        f(3, "sensitive", Ty::Bool),
    ],
    title: &[1],
};

static OBJECT_RESULT: Msg = Msg {
    name: "CheckResults.ObjectResult",
    fields: &[
        f(1, "object_addr", Ty::Str),
        f(2, "status", Ty::Enum(CHECK_STATUS)),
        f(3, "failure_messages", Ty::Str),
    ],
    title: &[1, 2],
};

static CHECK_RESULTS: Msg = Msg {
    name: "CheckResults",
    fields: &[
        f(1, "kind", Ty::Enum(CHECK_KIND)),
        f(2, "config_addr", Ty::Str),
        f(3, "status", Ty::Enum(CHECK_STATUS)),
        f(4, "objects", Ty::Msg(&OBJECT_RESULT)),
    ],
    title: &[2, 3],
};

static PROVIDER: Msg = Msg {
    name: "Provider",
    fields: &[
        f(1, "source", Ty::Str),
        f(2, "version", Ty::Str),
        f(3, "config", Ty::Msg(&DYNAMIC_VALUE)),
    ],
    title: &[1, 2],
};

static BACKEND: Msg = Msg {
    name: "Backend",
    fields: &[
        f(1, "type", Ty::Str),
        f(2, "config", Ty::Msg(&DYNAMIC_VALUE)),
        f(3, "workspace", Ty::Str),
    ],
    title: &[1, 3],
};

static STATE_STORE: Msg = Msg {
    name: "StateStore",
    fields: &[
        f(1, "type", Ty::Str),
        f(2, "config", Ty::Msg(&DYNAMIC_VALUE)),
        f(3, "workspace", Ty::Str),
        f(4, "provider", Ty::Msg(&PROVIDER)),
    ],
    title: &[1, 3],
};

static RESOURCE_ATTR: Msg = Msg {
    name: "resource_attr",
    fields: &[f(1, "resource", Ty::Str), f(2, "attr", Ty::Msg(&PATH))],
    title: &[1],
};

static FUNCTION_HASH: Msg = Msg {
    name: "FunctionCallHash",
    fields: &[f(1, "key", Ty::Bytes), f(2, "result", Ty::Bytes)],
    title: &[],
};

static PLAN: Msg = Msg {
    name: "Plan",
    fields: &[
        f(1, "version", Ty::Int),
        f(17, "ui_mode", Ty::Enum(MODE)),
        f(25, "applyable", Ty::Bool),
        f(26, "complete", Ty::Bool),
        f(20, "errored", Ty::Bool),
        f(2, "variables", Ty::Msg(&VARIABLE)),
        f(28, "apply_time_variables", Ty::Str),
        f(3, "resource_changes", Ty::Msg(&RESOURCE_CHANGE)),
        f(18, "resource_drift", Ty::Msg(&RESOURCE_CHANGE)),
        f(27, "deferred_changes", Ty::Msg(&DEFERRED_CHANGE)),
        f(31, "deferred_action_invocations", Ty::Msg(&DEFERRED_ACTION)),
        f(4, "output_changes", Ty::Msg(&OUTPUT_CHANGE)),
        f(19, "check_results", Ty::Msg(&CHECK_RESULTS)),
        f(30, "action_invocations", Ty::Msg(&ACTION_INVOCATION)),
        f(5, "target_addrs", Ty::Str),
        f(32, "action_target_addrs", Ty::Str),
        f(16, "force_replace_addrs", Ty::Str),
        f(14, "terraform_version", Ty::Str),
        f(13, "backend", Ty::Msg(&BACKEND)),
        f(29, "state_store", Ty::Msg(&STATE_STORE)),
        f(15, "relevant_attributes", Ty::Msg(&RESOURCE_ATTR)),
        f(21, "timestamp", Ty::Str),
        f(22, "function_results", Ty::Msg(&FUNCTION_HASH)),
    ],
    title: &[],
};

// ---------------------------------------------------------------------------
// Dissection

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    // A ZIP member named `tfplan` is taken for a plan by its name alone;
    // in a CI artifact it is often a whole saved plan (a ZIP) instead.
    // What the probes recognise is handed to them.
    if let Some(format) = not_a_plan(&cx, input.span).await?
        && cx.hand_off(&input, format)
    {
        return (format.dissect)(cx, input).await;
    }
    let head = cx.read(input.span.sub(0, 64 * 1024)).await?;
    let whole = crate::bytes::to_u64(head.len()) == input.span.len;
    let mut version = None;
    let mut tf = None;
    let mut mode = 0u64;
    let mut changes = 0u64;
    let mut at = 0usize;
    while let Some(field) = pb::field(&head, &mut at) {
        match (field.number, field.wire) {
            (1, VARINT) => version = Some(field.value),
            (17, VARINT) => mode = field.value,
            (3, LEN) => changes = changes.saturating_add(1),
            (14, LEN) => tf = Some(String::from_utf8_lossy(field.payload(&head)).into_owned()),
            _ => {}
        }
    }
    cx.charge(crate::bytes::to_u64(head.len()) / 64).await;
    let mut summary = match tf {
        Some(v) => format!("Terraform {v} plan"),
        None => "Terraform plan".to_owned(),
    };
    if let Some(v) = version {
        summary.push_str(&format!(" (format {v})"));
    }
    summary.push_str(&format!(
        ", {} mode",
        lookup(MODE, mode).unwrap_or("unknown")
    ));
    let more = if whole { "" } else { "≥" };
    summary.push_str(&format!(
        ", {more}{changes} resource change{}",
        if changes == 1 { "" } else { "s" }
    ));
    cx.annotate(summary);
    walk(cx, (input, input.span, &PLAN, 0)).await
}

type State = (Input, Span, &'static Msg, u32);

fn is_dynamic(msg: &'static Msg) -> bool {
    std::ptr::eq(msg, &DYNAMIC_VALUE)
}

/// Walks one message, pushing a node per field.
async fn walk(cx: Cx, (input, span, msg, depth): State) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(Diagnostic::limit("messages nested too deeply").at(span));
    }
    // A change's values are named by its action.
    let action = if std::ptr::eq(msg, &CHANGE) {
        Some(change_action(&cx, span).await?)
    } else {
        None
    };
    let mut values = 0usize;
    let mut cur = Cursor::new(&cx, span, Endian::Little);
    while !cur.at_end() {
        let start = cur.pos();
        let (num, payload) = pb::read_field(&mut cur).await?;
        let spec: Option<&F> = msg.fields.iter().find(|s| s.num == num);
        let label: String = match (spec, action) {
            (Some(s), Some(action)) if s.num == 2 => {
                let label = value_label(action, values);
                values = values.saturating_add(1);
                label
            }
            (Some(s), _) => s.name.to_owned(),
            (None, _) => format!("field {num}"),
        };
        let ty = spec.map(|s| s.ty);
        let node = match payload {
            Payload::Varint(v) => Node::new(label).value(match ty {
                Some(Ty::Bool) => Value::Bool(v != 0),
                Some(Ty::Enum(table)) => Value::Enum {
                    raw: v,
                    bits: 32,
                    name: lookup(table, v),
                },
                _ => match i64::try_from(v) {
                    Ok(_) => Value::UInt {
                        value: v,
                        bits: 64,
                        radix: Radix::Dec,
                    },
                    Err(_) => Value::Int {
                        value: i64::from_ne_bytes(v.to_ne_bytes()),
                        bits: 64,
                    },
                },
            }),
            Payload::I64(v) => Node::new(label).value(Value::UInt {
                value: v,
                bits: 64,
                radix: Radix::Hex,
            }),
            Payload::I32(v) => Node::new(label).value(Value::UInt {
                value: v.into(),
                bits: 32,
                radix: Radix::Hex,
            }),
            Payload::Len(body) => delimited(&cx, &input, label, body, ty, msg, depth).await?,
            Payload::StartGroup | Payload::EndGroup => {
                return Err(
                    Diagnostic::malformed("protobuf groups are not used in plans")
                        .at(cur.since(start)),
                );
            }
        };
        cx.push(node.span(cur.since(start))).await;
    }
    Ok(())
}

/// The action of the `Change` at `span`: its first field, as Go's
/// protobuf writes fields in order; absent (proto3's default) is NOOP.
async fn change_action(cx: &Cx, span: Span) -> Result<u64> {
    let head = cx.read(span.sub(0, 11)).await?;
    let mut at = 0usize;
    Ok(match pb::field(&head, &mut at) {
        Some(fl) if fl.number == 1 && fl.wire == VARINT => fl.value,
        _ => 0,
    })
}

/// The name of a change's `n`th value (planfile.proto: CREATE and READ
/// hold the value after, DELETE the value before, UPDATE and the
/// replacements both, NOOP the unchanged value).
fn value_label(action: u64, n: usize) -> String {
    let names: &[&str] = match action {
        0 => &["value"],
        1 | 2 => &["after"],
        5 => &["before"],
        3 | 6 | 7 => &["before", "after"],
        _ => &[],
    };
    match names.get(n) {
        Some(name) => format!("values[{n}] ({name})"),
        None => format!("values[{n}]"),
    }
}

async fn delimited(
    cx: &Cx,
    input: &Input,
    label: String,
    body: Span,
    ty: Option<Ty>,
    parent: &'static Msg,
    depth: u32,
) -> Result<Node> {
    Ok(match ty {
        Some(Ty::Str) => {
            let data = cx.read(body.sub(0, TEXT_MAX)).await?;
            let node =
                Node::new(label).value(Value::Text(String::from_utf8_lossy(&data).into_owned()));
            if body.len > TEXT_MAX {
                node.summary(format!("{} bytes", body.len))
            } else {
                node
            }
        }
        Some(Ty::Bytes) if is_dynamic(parent) => {
            cty_value(cx, input, "value".to_owned(), body).await?
        }
        Some(Ty::Msg(m)) => {
            let summary = match title(cx, body, m).await? {
                Some(t) => t,
                None => format!("{}, {} bytes", m.name, body.len),
            };
            Node::new(label).summary(summary).lazy(
                crate::expander!(self::walk: State),
                (*input, body, m, depth.saturating_add(1)),
            )
        }
        _ => Node::new(label).summary(format!("{} bytes", body.len)),
    })
}

/// A summary for a message instance: its title fields, the action of its
/// `Change` (resource and output changes), or the size of a value.
async fn title(cx: &Cx, body: Span, msg: &'static Msg) -> Result<Option<String>> {
    if body.len > TITLE_MAX {
        return Ok(None);
    }
    let data = cx.read(body).await?;
    let mut parts: Vec<String> = Vec::new();
    for &n in msg.title {
        let Some(spec) = msg.fields.iter().find(|s| s.num == n) else {
            continue;
        };
        match spec.ty {
            Ty::Enum(table) => {
                // A change's action is left out when it is NOOP (0).
                let v = pb::varint_in(&data, n).or_else(|| std::ptr::eq(msg, &CHANGE).then_some(0));
                if let Some(v) = v {
                    parts.push(lookup(table, v).map_or_else(|| v.to_string(), str::to_owned));
                }
            }
            Ty::Str => {
                if let Some(s) = pb::string_in(&data, n).filter(|s| !s.is_empty()) {
                    parts.push(short(&s));
                }
            }
            _ => {}
        }
    }
    if msg
        .fields
        .iter()
        .any(|s| matches!(s.ty, Ty::Msg(m) if std::ptr::eq(m, &CHANGE)))
    {
        let change = pb::fields_in(&data).find(|fl| {
            fl.wire == LEN
                && msg.fields.iter().any(|s| {
                    s.num == fl.number && matches!(s.ty, Ty::Msg(m) if std::ptr::eq(m, &CHANGE))
                })
        });
        if let Some(c) = change {
            let action = pb::varint_in(c.payload(&data), 1).unwrap_or(0);
            parts.push(lookup(ACTION, action).unwrap_or("?").to_owned());
        }
    }
    if is_dynamic(msg)
        && let Some(v) = pb::fields_in(&data).find(|fl| fl.number == 1 && fl.wire == LEN)
    {
        parts.push(format!("MessagePack, {} bytes", v.value_len()));
    }
    Ok((!parts.is_empty()).then(|| parts.join(" · ")))
}

fn short(s: &str) -> String {
    if s.chars().count() > 80 {
        s.chars().take(80).collect::<String>() + "…"
    } else {
        s.to_owned()
    }
}

// ---------------------------------------------------------------------------
// cty values

/// Largest value shown as a `cty` value; larger ones are handed to the
/// MessagePack dissector, which reads them a piece at a time.
const CTY_MAX: u64 = 16 << 20;

/// A MessagePack item's header, as `cty` writes them.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Mp {
    Nil,
    Bool(bool),
    UInt(u64),
    Int(i64),
    Float(f64),
    Str,
    Bin,
    Array,
    Map,
    Ext(i8),
    /// 0xc1, never used.
    Unused,
}

/// A header: its kind, length, and payload length (strings, binary,
/// extensions) or element count (arrays; maps count pairs).
#[derive(Clone, Copy, Debug)]
struct Hd {
    kind: Mp,
    head: usize,
    arg: u64,
}

fn hd(b: &[u8], at: usize) -> Option<Hd> {
    let &t = b.get(at)?;
    let be = |n: usize| -> Option<u64> {
        let bytes = b.get(at.checked_add(1)?..at.checked_add(1)?.checked_add(n)?)?;
        Some(bytes.iter().fold(0u64, |a, &x| (a << 8) | u64::from(x)))
    };
    let h = |kind, head, arg| Some(Hd { kind, head, arg });
    let sized = |kind, n: usize| h(kind, n.saturating_add(1), be(n)?);
    let ext = |n: usize| {
        let len = be(n)?;
        let ty = *b.get(at.checked_add(1)?.checked_add(n)?)?;
        h(Mp::Ext(i8::from_le_bytes([ty])), n.saturating_add(2), len)
    };
    let fixext = |len: u64| {
        let ty = *b.get(at.checked_add(1)?)?;
        h(Mp::Ext(i8::from_le_bytes([ty])), 2, len)
    };
    let int = |n: usize, bits: u32| {
        let v = be(n)?;
        let shift = 64u32.saturating_sub(bits);
        let v = (v.checked_shl(shift).unwrap_or(0) as i64)
            .checked_shr(shift)
            .unwrap_or(0);
        h(Mp::Int(v), n.saturating_add(1), 0)
    };
    match t {
        0x00..=0x7f => h(Mp::UInt(t.into()), 1, 0),
        0x80..=0x8f => h(Mp::Map, 1, u64::from(t & 0x0f)),
        0x90..=0x9f => h(Mp::Array, 1, u64::from(t & 0x0f)),
        0xa0..=0xbf => h(Mp::Str, 1, u64::from(t & 0x1f)),
        0xc0 => h(Mp::Nil, 1, 0),
        0xc1 => h(Mp::Unused, 1, 0),
        0xc2 | 0xc3 => h(Mp::Bool(t == 0xc3), 1, 0),
        0xc4 => sized(Mp::Bin, 1),
        0xc5 => sized(Mp::Bin, 2),
        0xc6 => sized(Mp::Bin, 4),
        0xc7 => ext(1),
        0xc8 => ext(2),
        0xc9 => ext(4),
        0xca => h(
            Mp::Float(f64::from(f32::from_bits(u32::try_from(be(4)?).ok()?))),
            5,
            0,
        ),
        0xcb => h(Mp::Float(f64::from_bits(be(8)?)), 9, 0),
        0xcc => h(Mp::UInt(be(1)?), 2, 0),
        0xcd => h(Mp::UInt(be(2)?), 3, 0),
        0xce => h(Mp::UInt(be(4)?), 5, 0),
        0xcf => h(Mp::UInt(be(8)?), 9, 0),
        0xd0 => int(1, 8),
        0xd1 => int(2, 16),
        0xd2 => int(4, 32),
        0xd3 => int(8, 64),
        0xd4 => fixext(1),
        0xd5 => fixext(2),
        0xd6 => fixext(4),
        0xd7 => fixext(8),
        0xd8 => fixext(16),
        0xd9 => sized(Mp::Str, 1),
        0xda => sized(Mp::Str, 2),
        0xdb => sized(Mp::Str, 4),
        0xdc => sized(Mp::Array, 2),
        0xdd => sized(Mp::Array, 4),
        0xde => sized(Mp::Map, 2),
        0xdf => sized(Mp::Map, 4),
        0xe0..=0xff => h(Mp::Int(i64::from(i8::from_le_bytes([t]))), 1, 0),
    }
}

/// Where the item at `at` ends, if it ends inside `b`. Iterative, with a
/// suspension point every 1,024 items.
async fn end_of(cx: &Cx, b: &[u8], at: usize) -> Option<usize> {
    let mut pos = at;
    let mut pending = 1u64;
    let mut n = 0u32;
    while pending > 0 {
        let h = hd(b, pos)?;
        pending = pending.saturating_sub(1);
        pos = pos.checked_add(h.head)?;
        match h.kind {
            Mp::Str | Mp::Bin | Mp::Ext(_) => {
                pos = pos.checked_add(usize::try_from(h.arg).ok()?)?;
            }
            Mp::Array => pending = pending.saturating_add(h.arg),
            Mp::Map => pending = pending.saturating_add(h.arg.saturating_mul(2)),
            _ => {}
        }
        // Every pending item takes at least a byte.
        if pos > b.len() || pending > to_u64(b.len().saturating_sub(pos)) {
            return None;
        }
        n = n.wrapping_add(1);
        if n.is_multiple_of(1024) {
            cx.checkpoint().await;
        }
    }
    Some(pos)
}

/// The payload of a string, binary or extension item at `at`.
fn payload<'a>(b: &'a [u8], at: usize, h: &Hd) -> &'a [u8] {
    whole(b, at, h).unwrap_or_default()
}

/// The payload of the item at `at`, if `b` holds all of it.
fn whole<'a>(b: &'a [u8], at: usize, h: &Hd) -> Option<&'a [u8]> {
    let start = at.saturating_add(h.head);
    let end = start.saturating_add(usize::try_from(h.arg).unwrap_or(usize::MAX));
    b.get(start..end)
}

/// What a refined unknown value is known to be (go-cty `msgpack`
/// extension 12: a map of refinements by key): not null, a string
/// prefix, number bounds, collection length bounds.
fn refinements(b: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let Some(m) = hd(b, 0).filter(|h| h.kind == Mp::Map) else {
        return out;
    };
    let mut pos = m.head;
    for _ in 0..m.arg.min(16) {
        let Some(k) = hd(b, pos) else { break };
        pos = pos.saturating_add(k.head);
        let Some(v) = hd(b, pos) else { break };
        let key = match k.kind {
            Mp::UInt(k) => k,
            _ => 0,
        };
        let scalar = |at: usize| -> Option<String> {
            let h = hd(b, at)?;
            Some(match h.kind {
                Mp::UInt(n) => n.to_string(),
                Mp::Int(n) => n.to_string(),
                Mp::Float(f) => f.to_string(),
                // Big numbers are written as their decimal text.
                Mp::Str => String::from_utf8_lossy(payload(b, at, &h)).into_owned(),
                _ => return None,
            })
        };
        let bound = |at: usize, below: bool| -> Option<String> {
            let a = hd(b, at).filter(|h| h.kind == Mp::Array && h.arg == 2)?;
            let n_at = at.saturating_add(a.head);
            let n = scalar(n_at)?;
            let n_len = hd(b, n_at)?;
            let skip = n_len.head.saturating_add(match n_len.kind {
                Mp::Str => usize::try_from(n_len.arg).ok()?,
                _ => 0,
            });
            let inclusive = matches!(hd(b, n_at.saturating_add(skip))?.kind, Mp::Bool(true));
            Some(match (below, inclusive) {
                (false, true) => format!("≥ {n}"),
                (false, false) => format!("> {n}"),
                (true, true) => format!("≤ {n}"),
                (true, false) => format!("< {n}"),
            })
        };
        let text = match (key, v.kind) {
            (1, Mp::Bool(false)) => Some("not null".to_owned()),
            (2, Mp::Str) => {
                whole(b, pos, &v).map(|p| format!("starts with {:?}", String::from_utf8_lossy(p)))
            }
            (3, _) => bound(pos, false),
            (4, _) => bound(pos, true),
            (5, _) => scalar(pos).map(|n| format!("length ≥ {n}")),
            (6, _) => scalar(pos).map(|n| format!("length ≤ {n}")),
            _ => None,
        };
        out.extend(text);
        // Skip the value (small: the extension is at most 1 KiB).
        let mut end = pos;
        let mut pending = 1u64;
        while pending > 0 {
            let Some(h) = hd(b, end) else { return out };
            pending = pending.saturating_sub(1);
            end = end.saturating_add(h.head);
            match h.kind {
                Mp::Str | Mp::Bin | Mp::Ext(_) => {
                    end = end.saturating_add(usize::try_from(h.arg).unwrap_or(usize::MAX));
                }
                Mp::Array => pending = pending.saturating_add(h.arg),
                Mp::Map => pending = pending.saturating_add(h.arg.saturating_mul(2)),
                _ => {}
            }
            if end > b.len() || pending > to_u64(b.len()) {
                return out;
            }
        }
        pos = end;
    }
    out
}

/// The node of the cty value encoded in `b[start..end]` (at `span` of the
/// source), named `name`. go-cty's `msgpack` encoding: an unknown value
/// ("known after apply") is extension 0 (or any extension of at most one
/// byte), or extension 12 with its refinements; a value of a dynamic type
/// is a pair of its type (JSON, as binary) and the value; null is nil.
fn cty_node(b: &[u8], start: usize, end: usize, span: Span, name: String, depth: u32) -> Node {
    let b = b.get(..end).unwrap_or(b);
    let node = Node::new(name).span(span);
    let Some(h) = hd(b, start) else {
        return node.diag(Diagnostic::malformed("invalid MessagePack value"));
    };
    match h.kind {
        Mp::Nil => node.summary("null"),
        Mp::Bool(v) => node.value(Value::Bool(v)),
        Mp::UInt(v) => node.value(Value::UInt {
            value: v,
            bits: 64,
            radix: Radix::Dec,
        }),
        Mp::Int(v) => node.value(Value::Int { value: v, bits: 64 }),
        Mp::Float(v) => node.value(Value::Float(v)),
        Mp::Str => {
            let s = payload(b, start, &h);
            let shown = s.get(..to_usize(TEXT_MAX)).unwrap_or(s);
            let node = node.value(Value::Text(String::from_utf8_lossy(shown).into_owned()));
            if to_u64(s.len()) > TEXT_MAX {
                node.summary(format!("{} bytes", s.len()))
            } else {
                node
            }
        }
        Mp::Ext(t) if h.arg <= 1 || t == 12 => {
            let mut summary = "(known after apply)".to_owned();
            if t == 12 {
                let r = refinements(payload(b, start, &h));
                if !r.is_empty() {
                    summary = format!("{summary}, {}", r.join(", "));
                }
            }
            node.summary(summary)
        }
        Mp::Array | Mp::Map if h.arg == 0 => node.summary(if h.kind == Mp::Map {
            "map, empty"
        } else {
            "list, empty"
        }),
        Mp::Array | Mp::Map => {
            if depth >= MAX_DEPTH {
                return node.diag(Diagnostic::limit("value nested too deeply"));
            }
            let summary = if h.kind == Mp::Map {
                format!("map, {}", plural(h.arg, "entry"))
            } else {
                format!("list, {}", plural(h.arg, "element"))
            };
            // A dynamic value: [type, value], the type as binary JSON.
            if h.kind == Mp::Array && h.arg == 2 {
                let first = start.saturating_add(h.head);
                if let Some(t) = hd(b, first).filter(|t| t.kind == Mp::Bin) {
                    let ty = String::from_utf8_lossy(payload(b, first, &t)).into_owned();
                    let at = first
                        .saturating_add(t.head)
                        .saturating_add(usize::try_from(t.arg).unwrap_or(usize::MAX));
                    let inner_span = span.sub(to_u64(at.saturating_sub(start)), span.len);
                    let mut inner = cty_node(b, at, end, inner_span, node.name.to_string(), depth);
                    // A primitive type is a JSON string: shown bare.
                    let ty = ty
                        .strip_prefix('"')
                        .and_then(|t| t.strip_suffix('"'))
                        .unwrap_or(&ty);
                    let ty = format!("type {}", short(ty));
                    inner.summary = Some(match inner.summary.take() {
                        Some(s) => format!("{s} · {ty}"),
                        None => ty,
                    });
                    return inner.span(span);
                }
            }
            node.summary(summary).lazy(
                crate::expander!(self::cty_members: (Span, u32)),
                (span, depth),
            )
        }
        Mp::Bin => node
            .value(Value::Bytes(payload(b, start, &h).to_vec()))
            .summary("binary"),
        Mp::Ext(t) => node.summary(format!("MessagePack extension type {t}, {} bytes", h.arg)),
        Mp::Unused => node.diag(Diagnostic::malformed("MessagePack type 0xc1")),
    }
}

/// Expander: the members of the cty list or map at `span`.
async fn cty_members(cx: Cx, (span, depth): (Span, u32)) -> Result<()> {
    let b = cx.read(span).await?;
    let h = hd(&b, 0).ok_or_else(|| Diagnostic::malformed("invalid MessagePack value"))?;
    let is_map = h.kind == Mp::Map;
    let mut pos = h.head;
    for i in 0..h.arg {
        let mut name = format!("[{i}]");
        // A map member spans its key too.
        let from = pos;
        if is_map {
            let k = hd(&b, pos).ok_or_else(|| Diagnostic::truncated(span, to_u64(b.len())))?;
            let end = end_of(&cx, &b, pos)
                .await
                .ok_or_else(|| Diagnostic::malformed("invalid MessagePack map key"))?;
            name = match k.kind {
                Mp::Str => String::from_utf8_lossy(payload(&b, pos, &k)).into_owned(),
                _ => name,
            };
            pos = end;
        }
        let end = end_of(&cx, &b, pos)
            .await
            .ok_or_else(|| Diagnostic::malformed("invalid MessagePack value"))?;
        let sub = span.sub(to_u64(pos), to_u64(end.saturating_sub(pos)));
        let node = cty_node(&b, pos, end, sub, name, depth.saturating_add(1));
        let whole = span.sub(to_u64(from), to_u64(end.saturating_sub(from)));
        cx.push(node.span(whole)).await;
        pos = end;
    }
    Ok(())
}

/// The node of the cty value (a `DynamicValue`'s MessagePack) at `body`.
async fn cty_value(cx: &Cx, input: &Input, label: String, body: Span) -> Result<Node> {
    if body.len > CTY_MAX {
        return Ok(embedded_named(label, input.nested(body), "msgpack")
            .summary(format!("MessagePack value, {} bytes", body.len)));
    }
    let b = cx.read(body).await?;
    cx.charge(to_u64(b.len()) / 256).await;
    let end = match end_of(cx, &b, 0).await {
        Some(end) => end,
        None => {
            return Ok(Node::new(label)
                .span(body)
                .diag(Diagnostic::malformed("invalid MessagePack value")));
        }
    };
    let mut node = cty_node(&b, 0, end, body.sub(0, to_u64(end)), label, 0);
    if end < b.len() {
        node = node.diag(Diagnostic::malformed(format!(
            "{} bytes after the value",
            b.len().saturating_sub(end)
        )));
    }
    Ok(node)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn refinements_are_described() {
        // {1: false, 2: "ab", 3: [1, true], 4: [9.5, false], 5: 2, 6: 4}
        let mut b = vec![
            0x86, 0x01, 0xc2, 0x02, 0xa2, b'a', b'b', 0x03, 0x92, 0x01, 0xc3,
        ];
        b.extend([0x04, 0x92, 0xcb]);
        b.extend(9.5f64.to_be_bytes());
        b.extend([0xc2, 0x05, 0x02, 0x06, 0x04]);
        assert_eq!(
            refinements(&b),
            [
                "not null",
                "starts with \"ab\"",
                "≥ 1",
                "< 9.5",
                "length ≥ 2",
                "length ≤ 4"
            ]
        );
        // Truncated: what was read so far.
        assert_eq!(refinements(&b[..5]), ["not null"]);
    }
}
