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
//! 1.16.6. Values (`DynamicValue`) are MessagePack-encoded `cty` values and
//! are handed to the MessagePack dissector.

use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
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
    let mut cur = Cursor::new(&cx, span, Endian::Little);
    while !cur.at_end() {
        let start = cur.pos();
        let (num, payload) = pb::read_field(&mut cur).await?;
        let spec: Option<&F> = msg.fields.iter().find(|s| s.num == num);
        let label: String = match spec {
            Some(s) => s.name.to_owned(),
            None => format!("field {num}"),
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
            embedded_named(label, input.nested(body), "msgpack")
                .summary(format!("MessagePack value, {} bytes", body.len))
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
                if let Some(v) = pb::varint_in(&data, n) {
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
