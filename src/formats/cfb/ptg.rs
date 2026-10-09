//! Excel parsed formulas ([MS-XLS] 2.5.198): BIFF8 `rgce` token arrays,
//! decoded token by token and rendered back to formula text.

use crate::bytes::{u16_le, u32_le, u64_le};
use crate::value::{EnumTable, lookup};

use super::rec::{column_name, number};

/// What a formula's references resolve against.
#[derive(Default, Clone, Debug)]
pub struct Names {
    /// Sheet names by XTI index (from EXTERNSHEET and BOUNDSHEET).
    pub xti: Vec<String>,
    /// Defined names, in NAME record order (ptgName indices are 1-based).
    pub defined: Vec<String>,
}

pub const ERRORS: EnumTable = &[
    (0x00, "#NULL!"),
    (0x07, "#DIV/0!"),
    (0x0f, "#VALUE!"),
    (0x17, "#REF!"),
    (0x1d, "#NAME?"),
    (0x24, "#NUM!"),
    (0x2a, "#N/A"),
    (0x2b, "#GETTING_DATA"),
];

/// Built-in functions: index (iftab), name, and fixed argument count
/// (-1 for functions that are always called with ptgFuncVar).
const FUNCTIONS: &[(u16, &str, i8)] = &[
    (0, "COUNT", -1),
    (1, "IF", -1),
    (2, "ISNA", 1),
    (3, "ISERROR", 1),
    (4, "SUM", -1),
    (5, "AVERAGE", -1),
    (6, "MIN", -1),
    (7, "MAX", -1),
    (8, "ROW", -1),
    (9, "COLUMN", -1),
    (10, "NA", 0),
    (11, "NPV", -1),
    (12, "STDEV", -1),
    (13, "DOLLAR", -1),
    (14, "FIXED", -1),
    (15, "SIN", 1),
    (16, "COS", 1),
    (17, "TAN", 1),
    (18, "ATAN", 1),
    (19, "PI", 0),
    (20, "SQRT", 1),
    (21, "EXP", 1),
    (22, "LN", 1),
    (23, "LOG10", 1),
    (24, "ABS", 1),
    (25, "INT", 1),
    (26, "SIGN", 1),
    (27, "ROUND", 2),
    (28, "LOOKUP", -1),
    (29, "INDEX", -1),
    (30, "REPT", 2),
    (31, "MID", 3),
    (32, "LEN", 1),
    (33, "VALUE", 1),
    (34, "TRUE", 0),
    (35, "FALSE", 0),
    (36, "AND", -1),
    (37, "OR", -1),
    (38, "NOT", 1),
    (39, "MOD", 2),
    (40, "DCOUNT", 3),
    (41, "DSUM", 3),
    (42, "DAVERAGE", 3),
    (43, "DMIN", 3),
    (44, "DMAX", 3),
    (45, "DSTDEV", 3),
    (46, "VAR", -1),
    (47, "DVAR", 3),
    (48, "TEXT", 2),
    (49, "LINEST", -1),
    (50, "TREND", -1),
    (51, "LOGEST", -1),
    (52, "GROWTH", -1),
    (56, "PV", -1),
    (57, "FV", -1),
    (58, "NPER", -1),
    (59, "PMT", -1),
    (60, "RATE", -1),
    (61, "MIRR", 3),
    (62, "IRR", -1),
    (63, "RAND", 0),
    (64, "MATCH", -1),
    (65, "DATE", 3),
    (66, "TIME", 3),
    (67, "DAY", 1),
    (68, "MONTH", 1),
    (69, "YEAR", 1),
    (70, "WEEKDAY", -1),
    (71, "HOUR", 1),
    (72, "MINUTE", 1),
    (73, "SECOND", 1),
    (74, "NOW", 0),
    (75, "AREAS", 1),
    (76, "ROWS", 1),
    (77, "COLUMNS", 1),
    (78, "OFFSET", -1),
    (82, "SEARCH", -1),
    (83, "TRANSPOSE", 1),
    (86, "TYPE", 1),
    (97, "ATAN2", 2),
    (98, "ASIN", 1),
    (99, "ACOS", 1),
    (100, "CHOOSE", -1),
    (101, "HLOOKUP", -1),
    (102, "VLOOKUP", -1),
    (105, "ISREF", 1),
    (109, "LOG", -1),
    (111, "CHAR", 1),
    (112, "LOWER", 1),
    (113, "UPPER", 1),
    (114, "PROPER", 1),
    (115, "LEFT", -1),
    (116, "RIGHT", -1),
    (117, "EXACT", 2),
    (118, "TRIM", 1),
    (119, "REPLACE", 4),
    (120, "SUBSTITUTE", -1),
    (121, "CODE", 1),
    (124, "FIND", -1),
    (125, "CELL", -1),
    (126, "ISERR", 1),
    (127, "ISTEXT", 1),
    (128, "ISNUMBER", 1),
    (129, "ISBLANK", 1),
    (130, "T", 1),
    (131, "N", 1),
    (140, "DATEVALUE", 1),
    (141, "TIMEVALUE", 1),
    (142, "SLN", 3),
    (143, "SYD", 4),
    (144, "DDB", -1),
    (148, "INDIRECT", -1),
    (162, "CLEAN", 1),
    (163, "MDETERM", 1),
    (164, "MINVERSE", 1),
    (165, "MMULT", 2),
    (167, "IPMT", -1),
    (168, "PPMT", -1),
    (169, "COUNTA", -1),
    (183, "PRODUCT", -1),
    (184, "FACT", 1),
    (189, "DPRODUCT", 3),
    (190, "ISNONTEXT", 1),
    (193, "STDEVP", -1),
    (194, "VARP", -1),
    (195, "DSTDEVP", 3),
    (196, "DVARP", 3),
    (197, "TRUNC", -1),
    (198, "ISLOGICAL", 1),
    (199, "DCOUNTA", 3),
    (212, "ROUNDUP", 2),
    (213, "ROUNDDOWN", 2),
    (216, "RANK", -1),
    (219, "ADDRESS", -1),
    (220, "DAYS360", -1),
    (221, "TODAY", 0),
    (222, "VDB", -1),
    (227, "MEDIAN", -1),
    (228, "SUMPRODUCT", -1),
    (229, "SINH", 1),
    (230, "COSH", 1),
    (231, "TANH", 1),
    (232, "ASINH", 1),
    (233, "ACOSH", 1),
    (234, "ATANH", 1),
    (235, "DGET", 3),
    (244, "INFO", 1),
    (247, "DB", -1),
    (252, "FREQUENCY", 2),
    (255, "(user-defined)", -1),
    (261, "ERROR.TYPE", 1),
    (269, "AVEDEV", -1),
    (270, "BETADIST", -1),
    (271, "GAMMALN", 1),
    (272, "BETAINV", -1),
    (273, "BINOMDIST", 4),
    (274, "CHIDIST", 2),
    (275, "CHIINV", 2),
    (276, "COMBIN", 2),
    (277, "CONFIDENCE", 3),
    (278, "CRITBINOM", 3),
    (279, "EVEN", 1),
    (280, "EXPONDIST", 3),
    (281, "FDIST", 3),
    (282, "FINV", 3),
    (283, "FISHER", 1),
    (284, "FISHERINV", 1),
    (285, "FLOOR", 2),
    (286, "GAMMADIST", 4),
    (287, "GAMMAINV", 3),
    (288, "CEILING", 2),
    (289, "HYPGEOMDIST", 4),
    (290, "LOGNORMDIST", 3),
    (291, "LOGINV", 3),
    (292, "NEGBINOMDIST", 3),
    (293, "NORMDIST", 4),
    (294, "NORMSDIST", 1),
    (295, "NORMINV", 3),
    (296, "NORMSINV", 1),
    (297, "STANDARDIZE", 3),
    (298, "ODD", 1),
    (299, "PERMUT", 2),
    (300, "POISSON", 3),
    (301, "TDIST", 3),
    (302, "WEIBULL", 4),
    (303, "SUMXMY2", 2),
    (304, "SUMX2MY2", 2),
    (305, "SUMX2PY2", 2),
    (306, "CHITEST", 2),
    (307, "CORREL", 2),
    (308, "COVAR", 2),
    (309, "FORECAST", 3),
    (310, "FTEST", 2),
    (311, "INTERCEPT", 2),
    (312, "PEARSON", 2),
    (313, "RSQ", 2),
    (314, "STEYX", 2),
    (315, "SLOPE", 2),
    (316, "TTEST", 4),
    (317, "PROB", -1),
    (318, "DEVSQ", -1),
    (319, "GEOMEAN", -1),
    (320, "HARMEAN", -1),
    (321, "SUMSQ", -1),
    (322, "KURT", -1),
    (323, "SKEW", -1),
    (324, "ZTEST", -1),
    (325, "LARGE", 2),
    (326, "SMALL", 2),
    (327, "QUARTILE", 2),
    (328, "PERCENTILE", 2),
    (329, "PERCENTRANK", -1),
    (330, "MODE", -1),
    (331, "TRIMMEAN", 2),
    (332, "TINV", 2),
    (336, "CONCATENATE", -1),
    (337, "POWER", 2),
    (342, "RADIANS", 1),
    (343, "DEGREES", 1),
    (344, "SUBTOTAL", -1),
    (345, "SUMIF", -1),
    (346, "COUNTIF", 2),
    (347, "COUNTBLANK", 1),
    (350, "ISPMT", 4),
    (351, "DATEDIF", 3),
    (354, "ROMAN", -1),
    (358, "GETPIVOTDATA", -1),
    (359, "HYPERLINK", -1),
    (360, "PHONETIC", 1),
    (361, "AVERAGEA", -1),
    (362, "MAXA", -1),
    (363, "MINA", -1),
    (364, "STDEVPA", -1),
    (365, "VARPA", -1),
    (366, "STDEVA", -1),
    (367, "VARA", -1),
];

fn function(index: u16) -> Option<(&'static str, i8)> {
    FUNCTIONS
        .binary_search_by_key(&index, |&(i, _, _)| i)
        .ok()
        .and_then(|i| FUNCTIONS.get(i))
        .map(|&(_, n, a)| (n, a))
}

const BUILTIN_NAMES: &[&str] = &[
    "Consolidate_Area",
    "Auto_Open",
    "Auto_Close",
    "Extract",
    "Database",
    "Criteria",
    "Print_Area",
    "Print_Titles",
    "Recorder",
    "Data_Form",
    "Auto_Activate",
    "Auto_Deactivate",
    "Sheet_Title",
    "_FilterDatabase",
];

/// The name of a built-in defined name (a one-character code).
pub fn builtin_name(code: u8) -> String {
    BUILTIN_NAMES
        .get(usize::from(code))
        .map_or_else(|| format!("builtin {code:#04x}"), |n| (*n).to_owned())
}

/// One decoded token.
pub struct Token {
    pub at: usize,
    pub len: usize,
    pub name: &'static str,
    pub detail: String,
}

/// The base name of a token (operand class removed).
fn ptg_name(ptg: u8) -> &'static str {
    match ptg {
        0x01 => "PtgExp",
        0x02 => "PtgTbl",
        0x03 => "PtgAdd",
        0x04 => "PtgSub",
        0x05 => "PtgMul",
        0x06 => "PtgDiv",
        0x07 => "PtgPower",
        0x08 => "PtgConcat",
        0x09 => "PtgLt",
        0x0a => "PtgLe",
        0x0b => "PtgEq",
        0x0c => "PtgGe",
        0x0d => "PtgGt",
        0x0e => "PtgNe",
        0x0f => "PtgIsect",
        0x10 => "PtgUnion",
        0x11 => "PtgRange",
        0x12 => "PtgUplus",
        0x13 => "PtgUminus",
        0x14 => "PtgPercent",
        0x15 => "PtgParen",
        0x16 => "PtgMissArg",
        0x17 => "PtgStr",
        0x18 => "PtgElf/PtgSxName",
        0x19 => "PtgAttr",
        0x1c => "PtgErr",
        0x1d => "PtgBool",
        0x1e => "PtgInt",
        0x1f => "PtgNum",
        _ => match (ptg & 0x1f) | 0x20 {
            0x20 => "PtgArray",
            0x21 => "PtgFunc",
            0x22 => "PtgFuncVar",
            0x23 => "PtgName",
            0x24 => "PtgRef",
            0x25 => "PtgArea",
            0x26 => "PtgMemArea",
            0x27 => "PtgMemErr",
            0x28 => "PtgMemNoMem",
            0x29 => "PtgMemFunc",
            0x2a => "PtgRefErr",
            0x2b => "PtgAreaErr",
            0x2c => "PtgRefN",
            0x2d => "PtgAreaN",
            0x39 => "PtgNameX",
            0x3a => "PtgRef3d",
            0x3b => "PtgArea3d",
            0x3c => "PtgRefErr3d",
            0x3d => "PtgAreaErr3d",
            _ => "unknown token",
        },
    }
}

fn class(ptg: u8) -> &'static str {
    if ptg < 0x20 {
        return "";
    }
    match (ptg >> 5) & 3 {
        1 => " (reference)",
        2 => " (value)",
        3 => " (array)",
        _ => "",
    }
}

/// A cell reference with its relative flags (BIFF8: flags in the column).
fn cell(row: u16, col: u16) -> String {
    let c = u32::from(col & 0x3fff);
    format!(
        "{}{}{}{}",
        if col & 0x4000 != 0 { "" } else { "$" },
        column_name(c),
        if col & 0x8000 != 0 { "" } else { "$" },
        u32::from(row).saturating_add(1)
    )
}

/// A relative reference of a shared formula (row and column offsets).
fn relative(row: u16, col: u16) -> String {
    let r = if col & 0x8000 != 0 {
        format!("R[{}]", row.cast_signed())
    } else {
        format!("R{}", u32::from(row).saturating_add(1))
    };
    let c = if col & 0x4000 != 0 {
        // BIFF8 has 256 columns: the offset is the low byte, signed.
        format!("C[{}]", ((col & 0xff) as u8).cast_signed())
    } else {
        format!("C{}", u32::from(col & 0x3fff).saturating_add(1))
    };
    format!("{r}{c}")
}

/// A BIFF2–5 cell reference (a 14-bit row with the relative flags in its
/// top bits, an 8-bit column) in the BIFF8 form: the flags are at the same
/// bit positions, moved to the column.
fn early_ref(row: u16, col: u8) -> (u16, u16) {
    (row & 0x3fff, u16::from(col) | (row & 0xc000))
}

/// A BIFF2–5 relative reference of a shared or name formula: a relative
/// row is a signed 14-bit offset.
fn early_relative(row: u16, col: u8) -> (u16, u16) {
    let (r, c) = early_ref(row, col);
    let r = if row & 0x8000 != 0 && r & 0x2000 != 0 {
        r | 0xc000
    } else {
        r
    };
    (r, c)
}

/// Splits a BIFF8 `rgce` into tokens; see [`tokens_for`].
pub fn tokens(rgce: &[u8], names: &Names) -> (Vec<Token>, Option<String>) {
    tokens_for(rgce, names, 8)
}

/// Splits `rgce` of BIFF version `version` (2, 3, 4 or 8) into tokens.
/// Rendering needs every token decoded, so decoding stops at the first
/// unknown one. Before BIFF8 ([MS-XLS] covers BIFF8 only; the earlier forms
/// follow the OpenOffice.org "Excel File Format" documentation and
/// LibreOffice's importer): references hold an 8-bit column with the
/// relative flags in the row, strings are byte strings, names carry unused
/// bytes, function indices are 8-bit before BIFF4 and tAttr data is 8-bit
/// in BIFF2.
pub fn tokens_for(rgce: &[u8], names: &Names, version: u8) -> (Vec<Token>, Option<String>) {
    let early = version < 8;
    let v2 = version == 2;
    let byte = |o: usize| rgce.get(o).copied().unwrap_or(0);
    let mut out = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut ok = true;
    let mut at = 0usize;
    while at < rgce.len() && out.len() < 4096 {
        let Some(&ptg) = rgce.get(at) else { break };
        let p = at.saturating_add(1);
        let u16_at = |o: usize| u16_le(rgce, p.saturating_add(o));
        let base = if ptg >= 0x20 {
            (ptg & 0x1f) | 0x20
        } else {
            ptg
        };
        let mut detail = String::new();
        let len: Option<usize> = match base {
            0x01 | 0x02 => {
                // BIFF2: an 8-bit column.
                let (r, c) = if v2 {
                    (
                        u16_at(0),
                        rgce.get(p.saturating_add(2)).map(|&c| u16::from(c)),
                    )
                } else {
                    (u16_at(0), u16_at(2))
                };
                detail = format!(
                    "{} at {}",
                    match (base, early) {
                        (0x01, false) => "shared formula",
                        (0x01, true) => "array formula",
                        _ => "data table",
                    },
                    match (r, c) {
                        (Some(r), Some(c)) => super::rec::cell_name(c.into(), r.into()),
                        _ => "?".to_owned(),
                    }
                );
                stack.push(format!("{{{detail}}}"));
                Some(if v2 { 4 } else { 5 })
            }
            0x03..=0x11 => {
                let op = match base {
                    0x03 => "+",
                    0x04 => "-",
                    0x05 => "*",
                    0x06 => "/",
                    0x07 => "^",
                    0x08 => "&",
                    0x09 => "<",
                    0x0a => "<=",
                    0x0b => "=",
                    0x0c => ">=",
                    0x0d => ">",
                    0x0e => "<>",
                    0x0f => " ",
                    0x10 => ",",
                    _ => ":",
                };
                match (stack.pop(), stack.pop()) {
                    (Some(b), Some(a)) => stack.push(format!("{a}{op}{b}")),
                    _ => ok = false,
                }
                Some(1)
            }
            0x12..=0x15 => {
                match stack.pop() {
                    Some(a) => stack.push(match base {
                        0x12 => format!("+{a}"),
                        0x13 => format!("-{a}"),
                        0x14 => format!("{a}%"),
                        _ => format!("({a})"),
                    }),
                    None => ok = false,
                }
                Some(1)
            }
            0x16 => {
                stack.push(String::new());
                Some(1)
            }
            0x17 => match super::rec::xl_string(
                rgce,
                p,
                if early {
                    super::rec::StrForm::Bytes8
                } else {
                    super::rec::StrForm::Wide8
                },
            ) {
                Some((s, used)) => {
                    detail = format!("{s:?}");
                    stack.push(format!("\"{}\"", s.replace('"', "\"\"")));
                    Some(used.saturating_add(1))
                }
                None => None,
            },
            0x19 => {
                let kind = rgce.get(p).copied().unwrap_or(0);
                // BIFF2: 8-bit data and jump table entries.
                let (data, width) = if v2 {
                    (u16::from(byte(p.saturating_add(1))), 1usize)
                } else {
                    (u16_at(1).unwrap_or(0), 2)
                };
                let (what, extra) = match kind {
                    0x01 => ("volatile", 0usize),
                    0x02 => ("if (jump)", 0),
                    0x04 => {
                        let cases = usize::from(data);
                        (
                            "choose (jump table)",
                            cases.saturating_add(1).saturating_mul(width),
                        )
                    }
                    0x08 => ("goto (skip)", 0),
                    0x10 => {
                        match stack.pop() {
                            Some(a) => stack.push(format!("SUM({a})")),
                            None => ok = false,
                        }
                        ("sum", 0)
                    }
                    0x20 => ("baxcel", 0),
                    0x40 | 0x41 => ("space", 0),
                    _ => ("unknown", 0),
                };
                detail = format!("{what}, data {data}");
                Some(if v2 { 3usize } else { 4 }.saturating_add(extra))
            }
            0x1a | 0x1b if early => {
                // tSheet / tEndSheet: references between them are on an
                // external sheet, which is not rendered.
                ok = false;
                detail = if base == 0x1a {
                    "external sheet reference begins"
                } else {
                    "external sheet reference ends"
                }
                .to_owned();
                Some(match (base, v2) {
                    (0x1a, true) => 8,
                    (0x1a, false) => 11,
                    (_, true) => 4,
                    _ => 5,
                })
            }
            0x1c => {
                let e = rgce.get(p).copied().unwrap_or(0);
                let name = lookup(ERRORS, e.into()).unwrap_or("#ERROR");
                detail = name.to_owned();
                stack.push(name.to_owned());
                Some(2)
            }
            0x1d => {
                let b = rgce.get(p).copied().unwrap_or(0) != 0;
                detail = if b { "TRUE" } else { "FALSE" }.to_owned();
                stack.push(detail.clone());
                Some(2)
            }
            0x1e => {
                let v = u16_at(0).unwrap_or(0);
                detail = v.to_string();
                stack.push(detail.clone());
                Some(3)
            }
            0x1f => {
                let v = f64::from_bits(u64_le(rgce, p).unwrap_or(0));
                detail = number(v);
                stack.push(detail.clone());
                Some(9)
            }
            0x20 => {
                detail = "constant array (values follow the formula)".to_owned();
                stack.push("{array}".to_owned());
                Some(if v2 { 7 } else { 8 })
            }
            0x21 | 0x22 => {
                // Before BIFF4 the function index is 8-bit.
                let narrow = version <= 3;
                let (argc, index) = if base == 0x21 {
                    let index = if narrow {
                        u16::from(byte(p))
                    } else {
                        u16_at(0).unwrap_or(0)
                    };
                    let argc = function(index).map_or(-1, |(_, a)| a);
                    (argc, index)
                } else {
                    let argc = i8::try_from(rgce.get(p).copied().unwrap_or(0) & 0x7f).unwrap_or(0);
                    let index = if narrow {
                        u16::from(byte(p.saturating_add(1)))
                    } else {
                        u16_at(1).unwrap_or(0) & 0x7fff
                    };
                    (argc, index)
                };
                let fname = function(index)
                    .map_or_else(|| format!("function {index}"), |(n, _)| n.to_owned());
                detail = format!("{fname}, {argc} arguments");
                match usize::try_from(argc) {
                    Ok(n) if n <= stack.len() => {
                        let args = stack.split_off(stack.len().saturating_sub(n));
                        if index == 255 {
                            // The first argument names the user-defined function.
                            let mut it = args.into_iter();
                            let name = it.next().unwrap_or_default();
                            let rest: Vec<String> = it.collect();
                            stack.push(format!("{name}({})", rest.join(",")));
                        } else {
                            stack.push(format!("{fname}({})", args.join(",")));
                        }
                    }
                    _ => ok = false,
                }
                Some(match (base, version <= 3) {
                    (0x21, true) => 2,
                    (0x21, false) => 3,
                    (_, true) => 3,
                    _ => 4,
                })
            }
            0x23 => {
                // A 1-based index: 32-bit in BIFF8, 16-bit with unused bytes
                // before.
                let i = if early {
                    u32::from(u16_at(0).unwrap_or(0))
                } else {
                    u32_le(rgce, p).unwrap_or(0)
                };
                let name = usize::try_from(i)
                    .ok()
                    .and_then(|i| i.checked_sub(1))
                    .and_then(|i| names.defined.get(i))
                    .cloned()
                    .unwrap_or_else(|| format!("name {i}"));
                detail = name.clone();
                stack.push(name);
                Some(match version {
                    2 => 8,
                    3 | 4 => 11,
                    5 => 15,
                    _ => 5,
                })
            }
            0x24 | 0x2c => {
                let (r, c) = if early {
                    let (row, col) = (u16_at(0).unwrap_or(0), byte(p.saturating_add(2)));
                    if base == 0x24 {
                        early_ref(row, col)
                    } else {
                        early_relative(row, col)
                    }
                } else {
                    (u16_at(0).unwrap_or(0), u16_at(2).unwrap_or(0))
                };
                detail = if base == 0x24 {
                    cell(r, c)
                } else {
                    relative(r, c)
                };
                stack.push(detail.clone());
                Some(if early { 4 } else { 5 })
            }
            0x25 | 0x2d => {
                let ((r1, c1), (r2, c2)) = if early {
                    let (row1, row2) = (u16_at(0).unwrap_or(0), u16_at(2).unwrap_or(0));
                    let (col1, col2) = (byte(p.saturating_add(4)), byte(p.saturating_add(5)));
                    if base == 0x25 {
                        (early_ref(row1, col1), early_ref(row2, col2))
                    } else {
                        (early_relative(row1, col1), early_relative(row2, col2))
                    }
                } else {
                    (
                        (u16_at(0).unwrap_or(0), u16_at(4).unwrap_or(0)),
                        (u16_at(2).unwrap_or(0), u16_at(6).unwrap_or(0)),
                    )
                };
                detail = if base == 0x25 {
                    format!("{}:{}", cell(r1, c1), cell(r2, c2))
                } else {
                    format!("{}:{}", relative(r1, c1), relative(r2, c2))
                };
                stack.push(detail.clone());
                Some(if early { 7 } else { 9 })
            }
            0x26..=0x28 if v2 => {
                // BIFF2: four bytes the importers skip.
                detail = "subexpression".to_owned();
                Some(5)
            }
            0x26..=0x28 => {
                detail = format!("subexpression of {} bytes", u16_at(4).unwrap_or(0));
                Some(7)
            }
            0x29 => {
                if v2 {
                    detail = format!("subexpression of {} bytes", byte(p));
                    Some(2)
                } else {
                    detail = format!("subexpression of {} bytes", u16_at(0).unwrap_or(0));
                    Some(3)
                }
            }
            0x2a => {
                stack.push("#REF!".to_owned());
                Some(if early { 4 } else { 5 })
            }
            0x2b => {
                stack.push("#REF!".to_owned());
                Some(if early { 7 } else { 9 })
            }
            0x39..=0x3d if early => None,
            0x39 => {
                let i = u32_le(rgce, p.saturating_add(2)).unwrap_or(0);
                detail = format!("external name {i} (XTI {})", u16_at(0).unwrap_or(0));
                stack.push(format!("[name {i}]"));
                Some(7)
            }
            0x3a | 0x3c => {
                let x = u16_at(0).unwrap_or(0);
                let sheet = sheet(names, x);
                let (r, c) = (u16_at(2).unwrap_or(0), u16_at(4).unwrap_or(0));
                detail = if base == 0x3a {
                    format!("{sheet}!{}", cell(r, c))
                } else {
                    format!("{sheet}!#REF!")
                };
                stack.push(detail.clone());
                Some(7)
            }
            0x3b | 0x3d => {
                let x = u16_at(0).unwrap_or(0);
                let sheet = sheet(names, x);
                let (r1, r2) = (u16_at(2).unwrap_or(0), u16_at(4).unwrap_or(0));
                let (c1, c2) = (u16_at(6).unwrap_or(0), u16_at(8).unwrap_or(0));
                detail = if base == 0x3b {
                    format!("{sheet}!{}:{}", cell(r1, c1), cell(r2, c2))
                } else {
                    format!("{sheet}!#REF!")
                };
                stack.push(detail.clone());
                Some(11)
            }
            _ => None,
        };
        let Some(len) = len else {
            out.push(Token {
                at,
                len: rgce.len().saturating_sub(at),
                name: "unknown token",
                detail: format!("{ptg:#04x}"),
            });
            return (out, None);
        };
        let name = ptg_name(ptg);
        let detail = if class(ptg).is_empty() {
            detail
        } else if detail.is_empty() {
            class(ptg).trim().to_owned()
        } else {
            format!("{detail}{}", class(ptg))
        };
        out.push(Token {
            at,
            len,
            name,
            detail,
        });
        at = at.saturating_add(len);
    }
    let text = if ok && stack.len() == 1 && at == rgce.len() {
        stack.pop()
    } else {
        None
    };
    (out, text)
}

fn sheet(names: &Names, xti: u16) -> String {
    let name = names
        .xti
        .get(usize::from(xti))
        .cloned()
        .unwrap_or_else(|| format!("XTI{xti}"));
    if name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        name
    } else {
        format!("'{}'", name.replace('\'', "''"))
    }
}
