//! Excel workbook streams ([MS-XLS]): the BIFF5 `Book` and BIFF8
//! `Workbook` record streams. The stream is split into substreams (the
//! workbook globals, then one per sheet, each from BOF to EOF); records are
//! named and their fields decoded, CONTINUE records are joined to the record
//! they continue (shared strings, text boxes, drawings), formulas are
//! decoded token by token and rendered as text, and the Office Art drawing
//! data spread over MSODRAWING records is reassembled and dissected.

use std::sync::Arc;

use super::ptg::{self, Names};
use super::rec::{self, K, LE, Spec, StrForm, cell_name, column_name, number, quoted, xl_string};
use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::Fields;
use crate::formats::Input;
use crate::formats::util::fmt::plural;
use crate::formats::util::val::{hex, uint};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::{EnumTable, FlagTable, Value, field, flag, lookup};

/// Bytes of a record read for its summary.
const PEEK: u64 = 256;
/// Characters of a shared string kept for cell summaries.
const STRING_KEEP: usize = 256;

pub const RECORDS: EnumTable = &[
    (0x0006, "FORMULA"),
    (0x000a, "EOF"),
    (0x000c, "CALCCOUNT"),
    (0x000d, "CALCMODE"),
    (0x000e, "PRECISION"),
    (0x000f, "REFMODE"),
    (0x0010, "DELTA"),
    (0x0011, "ITERATION"),
    (0x0012, "PROTECT"),
    (0x0013, "PASSWORD"),
    (0x0014, "HEADER"),
    (0x0015, "FOOTER"),
    (0x0016, "EXTERNCOUNT"),
    (0x0017, "EXTERNSHEET"),
    (0x0018, "NAME"),
    (0x0019, "WINDOWPROTECT"),
    (0x001a, "VERTICALPAGEBREAKS"),
    (0x001b, "HORIZONTALPAGEBREAKS"),
    (0x001c, "NOTE"),
    (0x001d, "SELECTION"),
    (0x0022, "DATEMODE"),
    (0x0023, "EXTERNNAME"),
    (0x0026, "LEFTMARGIN"),
    (0x0027, "RIGHTMARGIN"),
    (0x0028, "TOPMARGIN"),
    (0x0029, "BOTTOMMARGIN"),
    (0x002a, "PRINTHEADERS"),
    (0x002b, "PRINTGRIDLINES"),
    (0x002f, "FILEPASS"),
    (0x0031, "FONT"),
    (0x0033, "PRINTSIZE"),
    (0x003c, "CONTINUE"),
    (0x003d, "WINDOW1"),
    (0x0040, "BACKUP"),
    (0x0041, "PANE"),
    (0x0042, "CODEPAGE"),
    (0x004d, "PLS"),
    (0x0050, "DCON"),
    (0x0051, "DCONREF"),
    (0x0052, "DCONNAME"),
    (0x0055, "DEFCOLWIDTH"),
    (0x0059, "XCT"),
    (0x005a, "CRN"),
    (0x005b, "FILESHARING"),
    (0x005c, "WRITEACCESS"),
    (0x005d, "OBJ"),
    (0x005e, "UNCALCED"),
    (0x005f, "SAVERECALC"),
    (0x0060, "TEMPLATE"),
    (0x0063, "OBJPROTECT"),
    (0x007d, "COLINFO"),
    (0x007f, "IMDATA"),
    (0x0080, "GUTS"),
    (0x0081, "WSBOOL"),
    (0x0082, "GRIDSET"),
    (0x0083, "HCENTER"),
    (0x0084, "VCENTER"),
    (0x0085, "BOUNDSHEET"),
    (0x0086, "WRITEPROT"),
    (0x008c, "COUNTRY"),
    (0x008d, "HIDEOBJ"),
    (0x0090, "SORT"),
    (0x0092, "PALETTE"),
    (0x0097, "SYNC"),
    (0x0098, "LPR"),
    (0x0099, "STANDARDWIDTH"),
    (0x009b, "FILTERMODE"),
    (0x009c, "FNGROUPCOUNT"),
    (0x009d, "AUTOFILTERINFO"),
    (0x009e, "AUTOFILTER"),
    (0x00a0, "SCL"),
    (0x00a1, "SETUP"),
    (0x00ae, "SCENMAN"),
    (0x00af, "SCENARIO"),
    (0x00b0, "SXVIEW"),
    (0x00b1, "SXVD"),
    (0x00b2, "SXVI"),
    (0x00b4, "SXIVD"),
    (0x00b5, "SXLI"),
    (0x00b6, "SXPI"),
    (0x00b8, "DOCROUTE"),
    (0x00b9, "RECIPNAME"),
    (0x00bd, "MULRK"),
    (0x00be, "MULBLANK"),
    (0x00c1, "MMS"),
    (0x00c5, "SXDI"),
    (0x00c6, "SXDB"),
    (0x00c7, "SXFDB"),
    (0x00c8, "SXDBB"),
    (0x00c9, "SXNUM"),
    (0x00ca, "SXBOOL"),
    (0x00cb, "SXERR"),
    (0x00cc, "SXINT"),
    (0x00cd, "SXSTRING"),
    (0x00ce, "SXDTR"),
    (0x00cf, "SXNIL"),
    (0x00d0, "SXTBL"),
    (0x00d1, "SXTBRGIITM"),
    (0x00d2, "SXTBPG"),
    (0x00d3, "OBPROJ"),
    (0x00d5, "SXIDSTM"),
    (0x00d6, "RSTRING"),
    (0x00d7, "DBCELL"),
    (0x00da, "BOOKBOOL"),
    (0x00dc, "PARAMQRY"),
    (0x00dd, "SCENPROTECT"),
    (0x00de, "OLESIZE"),
    (0x00df, "UDDESC"),
    (0x00e0, "XF"),
    (0x00e1, "INTERFACEHDR"),
    (0x00e2, "INTERFACEEND"),
    (0x00e3, "SXVS"),
    (0x00e5, "MERGECELLS"),
    (0x00e9, "BKHIM"),
    (0x00eb, "MSODRAWINGGROUP"),
    (0x00ec, "MSODRAWING"),
    (0x00ed, "MSODRAWINGSELECTION"),
    (0x00ef, "PHONETICINFO"),
    (0x00f0, "SXRULE"),
    (0x00f1, "SXEX"),
    (0x00f2, "SXFILT"),
    (0x00f4, "SXDXF"),
    (0x00f5, "SXITM"),
    (0x00f6, "SXNAME"),
    (0x00f7, "SXSELECT"),
    (0x00f8, "SXPAIR"),
    (0x00f9, "SXFMLA"),
    (0x00fb, "SXFORMAT"),
    (0x00fc, "SST"),
    (0x00fd, "LABELSST"),
    (0x00ff, "EXTSST"),
    (0x0100, "SXVDEX"),
    (0x0103, "SXFORMULA"),
    (0x0122, "SXDBEX"),
    (0x0137, "CHTRINSERT"),
    (0x0138, "CHTRINFO"),
    (0x013b, "CHTRCELLCONTENT"),
    (0x013d, "TABID"),
    (0x0140, "CHTRMOVERANGE"),
    (0x014d, "CHTRINSERTTAB"),
    (0x015f, "LABELRANGES"),
    (0x0160, "USESELFS"),
    (0x0161, "DSF"),
    (0x0162, "XL5MODIFY"),
    (0x0196, "CHTRHEADER"),
    (0x01a5, "FILESHARING2"),
    (0x01a9, "USERBVIEW"),
    (0x01aa, "USERSVIEWBEGIN"),
    (0x01ab, "USERSVIEWEND"),
    (0x01ad, "QSI"),
    (0x01ae, "SUPBOOK"),
    (0x01af, "PROT4REV"),
    (0x01b0, "CONDFMT"),
    (0x01b1, "CF"),
    (0x01b2, "DVAL"),
    (0x01b5, "DCONBIN"),
    (0x01b6, "TXO"),
    (0x01b7, "REFRESHALL"),
    (0x01b8, "HLINK"),
    (0x01ba, "CODENAME"),
    (0x01bb, "SXFDBTYPE"),
    (0x01bc, "PROT4REVPASS"),
    (0x01be, "DV"),
    (0x01c0, "EXCEL9FILE"),
    (0x01c1, "RECALCID"),
    (0x0200, "DIMENSIONS"),
    (0x0201, "BLANK"),
    (0x0203, "NUMBER"),
    (0x0204, "LABEL"),
    (0x0205, "BOOLERR"),
    (0x0207, "STRING"),
    (0x0208, "ROW"),
    (0x020b, "INDEX"),
    (0x0218, "NAME"),
    (0x0221, "ARRAY"),
    (0x0223, "EXTERNNAME"),
    (0x0225, "DEFAULTROWHEIGHT"),
    (0x0231, "FONT"),
    (0x0236, "TABLE"),
    (0x023e, "WINDOW2"),
    (0x027e, "RK"),
    (0x0293, "STYLE"),
    (0x0406, "FORMULA"),
    (0x0409, "BOF"),
    (0x0418, "BIGNAME"),
    (0x041e, "FORMAT"),
    (0x0443, "XF"),
    (0x04bc, "SHRFMLA"),
    (0x0800, "HLINKTOOLTIP"),
    (0x0801, "WEBPUB"),
    (0x0802, "QSISXTAG"),
    (0x0803, "DBQUERYEXT"),
    (0x0804, "EXTSTRING"),
    (0x0805, "TXTQUERY"),
    (0x0806, "QSIR"),
    (0x0807, "QSIF"),
    (0x0809, "BOF"),
    (0x080a, "OLEDBCONN"),
    (0x080b, "WOPT"),
    (0x080c, "SXVIEWEX"),
    (0x080d, "SXTH"),
    (0x080e, "SXPIEX"),
    (0x080f, "SXVDTEX"),
    (0x0810, "SXVIEWEX9"),
    (0x0812, "CONTINUEFRT"),
    (0x0813, "REALTIMEDATA"),
    (0x0850, "CHARTFRTINFO"),
    (0x0851, "FRTWRAPPER"),
    (0x0852, "STARTBLOCK"),
    (0x0853, "ENDBLOCK"),
    (0x0854, "STARTOBJECT"),
    (0x0855, "ENDOBJECT"),
    (0x0856, "CATLAB"),
    (0x0857, "YMULT"),
    (0x0858, "SXVIEWLINK"),
    (0x0859, "PIVOTCHARTBITS"),
    (0x085a, "FRTFONTLIST"),
    (0x0862, "SHEETEXT"),
    (0x0863, "BOOKEXT"),
    (0x0864, "SXADDL"),
    (0x0865, "CRASHRECERR"),
    (0x0866, "HFPICTURE"),
    (0x0867, "FEATHEADR"),
    (0x0868, "FEAT"),
    (0x086a, "DATALABEXT"),
    (0x086b, "DATALABEXTCONTENTS"),
    (0x086c, "CELLWATCH"),
    (0x0871, "FEATHEADR11"),
    (0x0872, "FEAT11"),
    (0x0874, "DROPDOWNOBJIDS"),
    (0x0875, "CONTINUEFRT11"),
    (0x0876, "DCONN"),
    (0x0877, "LIST12"),
    (0x0878, "FEAT12"),
    (0x0879, "CONDFMT12"),
    (0x087a, "CF12"),
    (0x087b, "CFEX"),
    (0x087c, "XFCRC"),
    (0x087d, "XFEXT"),
    (0x087e, "AUTOFILTER12"),
    (0x087f, "CONTINUEFRT12"),
    (0x0884, "MDTINFO"),
    (0x0885, "MDXSTR"),
    (0x0886, "MDXTUPLE"),
    (0x0887, "MDXSET"),
    (0x0888, "MDXPROP"),
    (0x0889, "MDXKPI"),
    (0x088a, "MDB"),
    (0x088b, "PLV"),
    (0x088c, "COMPAT12"),
    (0x088d, "DXF"),
    (0x088e, "TABLESTYLES"),
    (0x088f, "TABLESTYLE"),
    (0x0890, "TABLESTYLEELEMENT"),
    (0x0892, "STYLEEXT"),
    (0x0893, "NAMEPUBLISH"),
    (0x0894, "NAMECMT"),
    (0x0895, "SORTDATA"),
    (0x0896, "THEME"),
    (0x0897, "GUIDTYPELIB"),
    (0x0898, "FNGRP12"),
    (0x0899, "NAMEFNGRP12"),
    (0x089a, "MTRSETTINGS"),
    (0x089b, "COMPRESSPICTURES"),
    (0x089c, "HEADERFOOTER"),
    (0x089d, "CRTLAYOUT12"),
    (0x089e, "CRTMLFRT"),
    (0x089f, "CRTMLFRTCONTINUE"),
    (0x08a3, "FORCEFULLCALCULATION"),
    (0x08a4, "SHAPEPROPSSTREAM"),
    (0x08a5, "TEXTPROPSSTREAM"),
    (0x08a6, "RICHTEXTSTREAM"),
    (0x08a7, "CRTLAYOUT12A"),
    // Chart records
    (0x1001, "UNITS"),
    (0x1002, "CHART"),
    (0x1003, "SERIES"),
    (0x1006, "DATAFORMAT"),
    (0x1007, "LINEFORMAT"),
    (0x1009, "MARKERFORMAT"),
    (0x100a, "AREAFORMAT"),
    (0x100b, "PIEFORMAT"),
    (0x100c, "ATTACHEDLABEL"),
    (0x100d, "SERIESTEXT"),
    (0x1014, "CHARTFORMAT"),
    (0x1015, "LEGEND"),
    (0x1016, "SERIESLIST"),
    (0x1017, "BAR"),
    (0x1018, "LINE"),
    (0x1019, "PIE"),
    (0x101a, "AREA"),
    (0x101b, "SCATTER"),
    (0x101c, "CHARTLINE"),
    (0x101d, "AXIS"),
    (0x101e, "TICK"),
    (0x101f, "VALUERANGE"),
    (0x1020, "CATSERRANGE"),
    (0x1021, "AXISLINEFORMAT"),
    (0x1022, "CHARTFORMATLINK"),
    (0x1024, "DEFAULTTEXT"),
    (0x1025, "TEXT"),
    (0x1026, "FONTX"),
    (0x1027, "OBJECTLINK"),
    (0x1032, "FRAME"),
    (0x1033, "BEGIN"),
    (0x1034, "END"),
    (0x1035, "PLOTAREA"),
    (0x103a, "CHART3D"),
    (0x103c, "PICF"),
    (0x103d, "DROPBAR"),
    (0x103e, "RADAR"),
    (0x103f, "SURF"),
    (0x1040, "RADARAREA"),
    (0x1041, "AXISPARENT"),
    (0x1043, "LEGENDXN"),
    (0x1044, "SHTPROPS"),
    (0x1045, "SERTOCRT"),
    (0x1046, "AXESUSED"),
    (0x1048, "SBASEREF"),
    (0x104a, "SERPARENT"),
    (0x104b, "SERAUXTREND"),
    (0x104e, "IFMTRECORD"),
    (0x104f, "POS"),
    (0x1050, "ALRUNS"),
    (0x1051, "BRAI"),
    (0x105b, "SERAUXERRBAR"),
    (0x105c, "CLRTCLIENT"),
    (0x105d, "SERFMT"),
    (0x105f, "CHART3DBARSHAPE"),
    (0x1060, "FBI"),
    (0x1061, "BOPPOP"),
    (0x1062, "AXCEXT"),
    (0x1063, "DAT"),
    (0x1064, "PLOTGROWTH"),
    (0x1065, "SIINDEX"),
    (0x1066, "GELFRAME"),
    (0x1067, "BOPPOPCUSTOM"),
    (0x1068, "FBI2"),
];

/// Record types only BIFF2–4 have: BIFF2 numbered the cell, BOF and several
/// other records below 0x0100; BIFF3 and BIFF4 renumbered some of them
/// (0x02xx, 0x04xx) as their layouts changed, and BIFF5 again.
const EARLY_RECORDS: EnumTable = &[
    (0x0000, "DIMENSIONS"),
    (0x0001, "BLANK"),
    (0x0002, "INTEGER"),
    (0x0003, "NUMBER"),
    (0x0004, "LABEL"),
    (0x0005, "BOOLERR"),
    (0x0007, "STRING"),
    (0x0008, "ROW"),
    (0x0009, "BOF"),
    (0x000b, "INDEX"),
    (0x001e, "FORMAT"),
    (0x001f, "FORMATCOUNT"),
    (0x0020, "COLUMNDEFAULT"),
    (0x0021, "ARRAY"),
    (0x0024, "COLWIDTH"),
    (0x0025, "DEFAULTROWHEIGHT"),
    (0x0032, "FONT2"),
    (0x003e, "WINDOW2"),
    (0x0043, "XF"),
    (0x0044, "IXFE"),
    (0x0045, "FONTCOLOR"),
    (0x0056, "BUILTINFMTCOUNT"),
    (0x0206, "FORMULA"),
    (0x0209, "BOF"),
    (0x0243, "XF"),
];

/// A record type's name; the BIFF2–4 numbers only in such a stream.
fn record_name(kind: u16, book: &Book) -> Option<&'static str> {
    lookup(RECORDS, kind.into()).or_else(|| {
        if book.early() {
            lookup(EARLY_RECORDS, kind.into())
        } else {
            None
        }
    })
}

const BOF_TYPES: EnumTable = &[
    (0x0005, "workbook globals"),
    (0x0006, "Visual Basic module"),
    (0x0010, "worksheet"),
    (0x0020, "chart"),
    (0x0040, "macro sheet"),
    (0x0100, "workspace"),
];

const BIFF_VERSIONS: EnumTable = &[
    (0x0200, "BIFF2"),
    (0x0300, "BIFF3"),
    (0x0400, "BIFF4"),
    (0x0500, "BIFF5"),
    (0x0600, "BIFF8"),
];

const SHEET_STATES: EnumTable = &[(0, "visible"), (1, "hidden"), (2, "very hidden")];
const SHEET_TYPES: EnumTable = &[
    (0, "worksheet or dialog sheet"),
    (1, "macro sheet"),
    (2, "chart"),
    (6, "VBA module"),
];

const UNDERLINE: EnumTable = &[
    (0x00, "none"),
    (0x01, "single"),
    (0x02, "double"),
    (0x21, "single accounting"),
    (0x22, "double accounting"),
];
const SCRIPT: EnumTable = &[(0, "normal"), (1, "superscript"), (2, "subscript")];
const FONT_FLAGS: FlagTable = &[
    flag(0x0002, "fItalic"),
    flag(0x0008, "fStrikeOut"),
    flag(0x0010, "fOutline"),
    flag(0x0020, "fShadow"),
    flag(0x0040, "fCondense"),
    flag(0x0080, "fExtend"),
];
const FONT_FAMILY: EnumTable = &[
    (0, "not applicable"),
    (1, "Roman"),
    (2, "Swiss"),
    (3, "Modern"),
    (4, "Script"),
    (5, "Decorative"),
];
const WINDOW1_FLAGS: FlagTable = &[
    flag(0x01, "fHidden"),
    flag(0x02, "fIconic"),
    flag(0x08, "fDspHScroll"),
    flag(0x10, "fDspVScroll"),
    flag(0x20, "fBotAdornment"),
    flag(0x40, "fNoAFDateGroup"),
];
const WINDOW2_FLAGS: FlagTable = &[
    flag(0x0001, "fDspFmlaRt"),
    flag(0x0002, "fDspGridRt"),
    flag(0x0004, "fDspRwColRt"),
    flag(0x0008, "fFrozenRt"),
    flag(0x0010, "fDspZerosRt"),
    flag(0x0020, "fDefaultHdr"),
    flag(0x0040, "fRightToLeft"),
    flag(0x0080, "fDspGuts"),
    flag(0x0100, "fFrozenNoSplit"),
    flag(0x0200, "fSelected"),
    flag(0x0400, "fPaged"),
    flag(0x0800, "fSLV"),
];
const ROW_FLAGS: FlagTable = &[
    flag(0x0010, "fCollapsed"),
    flag(0x0020, "fDyZero"),
    flag(0x0040, "fUnsynced"),
    flag(0x0080, "fGhostDirty"),
    flag(0x0100, "reserved (1)"),
];
const COLINFO_FLAGS: FlagTable = &[
    flag(0x0001, "fHidden"),
    flag(0x0002, "fUserSet"),
    flag(0x0004, "fBestFit"),
    flag(0x0008, "fPhonetic"),
    flag(0x1000, "fCollapsed"),
];
const FORMULA_FLAGS: FlagTable = &[
    flag(0x0001, "fAlwaysCalc"),
    flag(0x0004, "fFill"),
    flag(0x0008, "fShrFmla"),
    flag(0x0020, "fClearErrors"),
];
const XF_TYPE_PROT: FlagTable = &[
    flag(0x0001, "fLocked"),
    flag(0x0002, "fHidden"),
    flag(0x0004, "fStyle"),
    flag(0x0008, "f123Prefix"),
];
const HALIGN: EnumTable = &[
    (0, "general"),
    (1, "left"),
    (2, "center"),
    (3, "right"),
    (4, "fill"),
    (5, "justify"),
    (6, "center across selection"),
    (7, "distributed"),
];
const VALIGN: EnumTable = &[
    (0, "top"),
    (1, "center"),
    (2, "bottom"),
    (3, "justify"),
    (4, "distributed"),
];
const DEFROW_FLAGS: FlagTable = &[
    flag(0x1, "fUnsynced"),
    flag(0x2, "fDyZero"),
    flag(0x4, "fExAsc"),
    flag(0x8, "fExDsc"),
];
const WSBOOL_FLAGS: FlagTable = &[
    flag(0x0001, "fShowAutoBreaks"),
    flag(0x0010, "fDialog"),
    flag(0x0020, "fApplyStyles"),
    flag(0x0040, "fRowSumsBelow"),
    flag(0x0080, "fColSumsRight"),
    flag(0x0100, "fFitToPage"),
    flag(0x0400, "fSyncHoriz"),
    flag(0x0800, "fSyncVert"),
    flag(0x1000, "fAltExprEval"),
    flag(0x2000, "fAltFormulaEntry"),
];
const SETUP_FLAGS: FlagTable = &[
    flag(0x0001, "fLeftToRight"),
    flag(0x0002, "fPortrait"),
    flag(0x0004, "fNoPls"),
    flag(0x0008, "fNoColor"),
    flag(0x0010, "fDraft"),
    flag(0x0020, "fNotes"),
    flag(0x0040, "fNoOrient"),
    flag(0x0080, "fUsePage"),
    flag(0x0200, "fEndNotes"),
    field(0x0c00, 0x0400, "iErrors=blank"),
    field(0x0c00, 0x0800, "iErrors=dash"),
    field(0x0c00, 0x0c00, "iErrors=N/A"),
];
const NAME_FLAGS: FlagTable = &[
    flag(0x0001, "fHidden"),
    flag(0x0002, "fFunc"),
    flag(0x0004, "fOB"),
    flag(0x0008, "fProc"),
    flag(0x0010, "fCalcExp"),
    flag(0x0020, "fBuiltin"),
    flag(0x1000, "fBig"),
    flag(0x2000, "fPublished"),
    flag(0x4000, "fWorkbookParam"),
];
const NOTE_FLAGS: FlagTable = &[
    flag(0x0002, "fShow"),
    flag(0x0080, "fRwHidden"),
    flag(0x0100, "fColHidden"),
];
const OBJ_TYPES: EnumTable = &[
    (0x00, "Group"),
    (0x01, "Line"),
    (0x02, "Rectangle"),
    (0x03, "Oval"),
    (0x04, "Arc"),
    (0x05, "Chart"),
    (0x06, "Text"),
    (0x07, "Button"),
    (0x08, "Picture"),
    (0x09, "Polygon"),
    (0x0b, "Checkbox"),
    (0x0c, "Radio button"),
    (0x0d, "Edit box"),
    (0x0e, "Label"),
    (0x0f, "Dialog box"),
    (0x10, "Spin control"),
    (0x11, "Scrollbar"),
    (0x12, "List"),
    (0x13, "Group box"),
    (0x14, "Dropdown list"),
    (0x19, "Note"),
    (0x1e, "Office Art object"),
];
const OBJ_SUBRECORDS: EnumTable = &[
    (0x00, "ftEnd"),
    (0x04, "ftMacro"),
    (0x05, "ftButton"),
    (0x06, "ftGmo"),
    (0x07, "ftCf"),
    (0x08, "ftPioGrbit"),
    (0x09, "ftPictFmla"),
    (0x0a, "ftCbls"),
    (0x0b, "ftRbo"),
    (0x0c, "ftSbs"),
    (0x0d, "ftNts"),
    (0x0e, "ftSbsFmla"),
    (0x0f, "ftGboData"),
    (0x10, "ftEdoData"),
    (0x11, "ftRboData"),
    (0x12, "ftCblsData"),
    (0x13, "ftLbsData"),
    (0x14, "ftCblsFmla"),
    (0x15, "ftCmo"),
];
const CMO_FLAGS: FlagTable = &[
    flag(0x0001, "fLocked"),
    flag(0x0004, "fDefaultSize"),
    flag(0x0008, "fPublished"),
    flag(0x0010, "fPrint"),
    flag(0x0080, "fDisabled"),
    flag(0x0100, "fUIObj"),
    flag(0x0200, "fRecalcObj"),
    flag(0x1000, "fRecalcObjAlways"),
];
const STYLES: EnumTable = &[
    (0, "Normal"),
    (1, "RowLevel"),
    (2, "ColLevel"),
    (3, "Comma"),
    (4, "Currency"),
    (5, "Percent"),
    (6, "Comma [0]"),
    (7, "Currency [0]"),
    (8, "Hyperlink"),
    (9, "Followed Hyperlink"),
];
const BUILTIN_FORMATS: EnumTable = &[
    (0, "General"),
    (1, "0"),
    (2, "0.00"),
    (3, "#,##0"),
    (4, "#,##0.00"),
    (9, "0%"),
    (10, "0.00%"),
    (11, "0.00E+00"),
    (12, "# ?/?"),
    (13, "# ??/??"),
    (14, "m/d/yy"),
    (15, "d-mmm-yy"),
    (16, "d-mmm"),
    (17, "mmm-yy"),
    (18, "h:mm AM/PM"),
    (19, "h:mm:ss AM/PM"),
    (20, "h:mm"),
    (21, "h:mm:ss"),
    (22, "m/d/yy h:mm"),
    (37, "#,##0 ;(#,##0)"),
    (38, "#,##0 ;[Red](#,##0)"),
    (39, "#,##0.00;(#,##0.00)"),
    (40, "#,##0.00;[Red](#,##0.00)"),
    (45, "mm:ss"),
    (46, "[h]:mm:ss"),
    (47, "mmss.0"),
    (48, "##0.0E+0"),
    (49, "@"),
];

// ---------------------------------------------------------------------------
// Fixed layouts

const EMPTY: Spec = &[];

fn spec(kind: u16, biff8: bool) -> Option<Spec> {
    let s: Spec = match kind {
        0x000a | 0x00e2 | 0x01c0 => EMPTY,
        0x01b7 => &[("fRefreshAll", K::Bool16)],
        0x0160 => &[("fUsesElfs", K::Bool16)],
        0x0063 | 0x00dd => &[("fLock", K::Bool16)],
        0x000c => &[("cIter", K::U16)],
        0x000d => &[(
            "fAutoRecalc",
            K::E16(&[
                (0, "manual"),
                (1, "automatic"),
                (2, "automatic except tables"),
                (0xffff, "manual"),
            ]),
        )],
        0x000e => &[("fFullPrec", K::Bool16)],
        0x000f => &[("fRefA1", K::E16(&[(0, "R1C1"), (1, "A1")]))],
        0x0010 => &[("numDelta", K::F64)],
        0x0011 => &[("fIter", K::Bool16)],
        0x0012 | 0x0019 | 0x0086 | 0x01af => &[("fLock", K::Bool16)],
        0x0013 | 0x01bc => &[("wPassword", K::H16)],
        0x0022 => &[("f1904DateSystem", K::Bool16)],
        0x0026..=0x0029 => &[("num (inches)", K::F64)],
        0x002a | 0x002b | 0x0082 | 0x0083 | 0x0084 => &[("Flag", K::Bool16)],
        0x0040 => &[("fBackup", K::Bool16)],
        0x0042 => &[("cv (code page)", K::U16)],
        0x0055 => &[("cchdefColWidth", K::U16)],
        0x005f => &[("fSaveRecalc", K::Bool16)],
        0x0080 => &[
            ("dxRwGut", K::U16),
            ("dyColGut", K::U16),
            ("iLevelRwMac", K::U16),
            ("iLevelColMac", K::U16),
        ],
        0x0081 => &[("Flags", K::F16(WSBOOL_FLAGS))],
        0x008c => &[("iCountryDef", K::U16), ("iCountryWinIni", K::U16)],
        0x008d => &[(
            "hideObj",
            K::E16(&[(0, "show all"), (1, "placeholders"), (2, "hide all")]),
        )],
        0x0099 => &[("cw (1/256 character)", K::U16)],
        0x009c => &[("cFnGroup", K::U16)],
        0x00a0 => &[("nscl", K::I16), ("dscl", K::I16)],
        0x00a1 => &[
            ("iPaperSize", K::U16),
            ("iScale", K::U16),
            ("iPageStart", K::I16),
            ("iFitWidth", K::U16),
            ("iFitHeight", K::U16),
            ("Flags", K::F16(SETUP_FLAGS)),
            ("iRes", K::U16),
            ("iVRes", K::U16),
            ("numHdr (inches)", K::F64),
            ("numFtr (inches)", K::F64),
            ("iCopies", K::U16),
        ],
        0x00c1 => &[("caitm", K::U8), ("cditm", K::U8)],
        0x00da => &[("Flags", K::H16)],
        0x00e1 => {
            if biff8 {
                &[("cv (code page)", K::U16)]
            } else {
                EMPTY
            }
        }
        0x0161 => &[("fDSF", K::Bool16)],
        0x01c1 => &[("rt", K::H16), ("reserved", K::U16), ("dwBuild", K::U32)],
        0x0200 => {
            if biff8 {
                &[
                    ("rwMic", K::Row32),
                    ("rwMac", K::Row32),
                    ("colMic", K::Col),
                    ("colMac", K::Col),
                    ("reserved", K::U16),
                ]
            } else {
                &[
                    ("rwMic", K::Row),
                    ("rwMac", K::Row),
                    ("colMic", K::Col),
                    ("colMac", K::Col),
                    ("reserved", K::U16),
                ]
            }
        }
        0x0201 => &[("rw", K::Row), ("col", K::Col), ("ixfe", K::U16)],
        0x0203 => &[
            ("rw", K::Row),
            ("col", K::Col),
            ("ixfe", K::U16),
            ("num", K::F64),
        ],
        0x0205 => &[
            ("rw", K::Row),
            ("col", K::Col),
            ("ixfe", K::U16),
            ("bBoolErr", K::U8),
            ("fError", K::Bool8),
        ],
        0x027e => &[
            ("rw", K::Row),
            ("col", K::Col),
            ("ixfe", K::U16),
            ("RK", K::Rk),
        ],
        0x00fd => &[
            ("rw", K::Row),
            ("col", K::Col),
            ("ixfe", K::U16),
            ("isst", K::U32),
        ],
        0x0208 => &[
            ("rw", K::Row),
            ("colMic", K::Col),
            ("colMac", K::Col),
            ("miyRw", K::Twips),
            ("reserved1", K::U16),
            ("unused1", K::U16),
            ("Flags", K::F16(ROW_FLAGS)),
            ("ixfe / flags", K::H16),
        ],
        0x0225 => &[("Flags", K::F16(DEFROW_FLAGS)), ("miyRw", K::ITwips)],
        0x003d => &[
            ("xWn", K::I16),
            ("yWn", K::I16),
            ("dxWn", K::U16),
            ("dyWn", K::U16),
            ("Flags", K::F16(WINDOW1_FLAGS)),
            ("itabCur", K::U16),
            ("itabFirst", K::U16),
            ("ctabSel", K::U16),
            ("wTabRatio", K::U16),
        ],
        0x023e => {
            if biff8 {
                &[
                    ("Flags", K::F16(WINDOW2_FLAGS)),
                    ("rwTop", K::Row),
                    ("colLeft", K::Col),
                    ("icvHdr", K::U16),
                    ("reserved", K::U16),
                    ("wScaleSLV", K::U16),
                    ("wScaleNormal", K::U16),
                    ("unused", K::U32),
                ]
            } else {
                &[
                    ("Flags", K::F16(WINDOW2_FLAGS)),
                    ("rwTop", K::Row),
                    ("colLeft", K::Col),
                    ("rgbHdr", K::H32),
                ]
            }
        }
        0x0041 => &[
            ("x", K::U16),
            ("y", K::U16),
            ("rwTop", K::Row),
            ("colLeft", K::Col),
            ("pnnAcct", K::U8),
            ("reserved", K::U8),
        ],
        0x007d => &[
            ("colFirst", K::Col),
            ("colLast", K::Col),
            ("coldx (1/256 character)", K::U16),
            ("ixfe", K::U16),
            ("Flags", K::F16(COLINFO_FLAGS)),
            ("reserved", K::U16),
        ],
        0x0014 | 0x0015 | 0x01ba => {
            if biff8 {
                &[("Text", K::XlStr)]
            } else {
                &[("Text", K::Str8)]
            }
        }
        // STRING: BIFF3–5 byte strings have a 16-bit count.
        0x0207 => {
            if biff8 {
                &[("Text", K::XlStr)]
            } else {
                &[("Text", K::Str16)]
            }
        }
        0x0204 => {
            if biff8 {
                &[
                    ("rw", K::Row),
                    ("col", K::Col),
                    ("ixfe", K::U16),
                    ("Text", K::XlStr),
                ]
            } else {
                &[
                    ("rw", K::Row),
                    ("col", K::Col),
                    ("ixfe", K::U16),
                    ("Text", K::Str16),
                ]
            }
        }
        0x041e => {
            if biff8 {
                &[("ifmt", K::U16), ("stFormat", K::XlStr)]
            } else {
                &[("ifmt", K::U16), ("stFormat", K::Str8)]
            }
        }
        0x0031 => {
            if biff8 {
                &[
                    ("dyHeight", K::Twips),
                    ("Flags", K::F16(FONT_FLAGS)),
                    ("icv", K::U16),
                    ("bls (weight)", K::U16),
                    ("sss", K::E16(SCRIPT)),
                    ("uls", K::E8(UNDERLINE)),
                    ("bFamily", K::E8(FONT_FAMILY)),
                    ("bCharSet", K::E8(super::word::CHARSETS)),
                    ("unused", K::U8),
                    ("fontName", K::XlStr8),
                ]
            } else {
                &[
                    ("dyHeight", K::Twips),
                    ("Flags", K::F16(FONT_FLAGS)),
                    ("icv", K::U16),
                    ("bls (weight)", K::U16),
                    ("sss", K::E16(SCRIPT)),
                    ("uls", K::E8(UNDERLINE)),
                    ("bFamily", K::E8(FONT_FAMILY)),
                    ("bCharSet", K::E8(super::word::CHARSETS)),
                    ("unused", K::U8),
                    ("fontName", K::Str8),
                ]
            }
        }
        0x0085 => {
            if biff8 {
                &[
                    ("lbPlyPos", K::H32),
                    ("hsState", K::E8(SHEET_STATES)),
                    ("dt", K::E8(SHEET_TYPES)),
                    ("stName", K::XlStr8),
                ]
            } else {
                &[
                    ("lbPlyPos", K::H32),
                    ("hsState", K::E8(SHEET_STATES)),
                    ("dt", K::E8(SHEET_TYPES)),
                    ("stName", K::Str8),
                ]
            }
        }
        0x01ae => EMPTY,
        0x00d7 => &[("dbRtrw", K::U32)],
        0x01b8 => &[
            ("rwFirst", K::Row),
            ("rwLast", K::Row),
            ("colFirst", K::Col),
            ("colLast", K::Col),
            ("hlinkClsid", K::Guid),
        ],
        _ => return None,
    };
    Some(s)
}

// ---------------------------------------------------------------------------
// Workbook context

/// What cell summaries and formulas need from the globals substream.
#[derive(Default)]
pub struct Book {
    pub biff8: bool,
    /// 2, 3 or 4 for a standalone Excel 2.x–4.0 stream, 5 or 8 for a
    /// compound-file workbook; 0 when there was no BOF.
    pub version: u8,
    pub strings: Vec<String>,
    pub names: Names,
    pub codepage: u16,
    pub date1904: bool,
}

impl Book {
    /// A BIFF2–4 stream, whose records have their own layouts.
    fn early(&self) -> bool {
        matches!(self.version, 2..=4)
    }

    /// The version whose formulas [`ptg::tokens_for`] decodes.
    fn formula_version(&self) -> Option<u8> {
        if self.biff8 {
            Some(8)
        } else if matches!(self.version, 2..=5) {
            Some(self.version)
        } else {
            None
        }
    }
}

/// One record header, as walked.
#[derive(Clone, Copy)]
struct Rec {
    kind: u16,
    span: Span,
}

impl Rec {
    fn body(&self) -> Span {
        self.span.tail(4)
    }
}

/// Reads the next record header at `pos` within `stream`.
async fn next_rec(cx: &Cx, stream: Span, pos: u64) -> Result<Option<Rec>> {
    if pos.saturating_add(4) > stream.len {
        return Ok(None);
    }
    let head = cx.read(stream.sub(pos, 4)).await?;
    let kind = u16_le(&head, 0).unwrap_or(0);
    let len = u64::from(u16_le(&head, 2).unwrap_or(0));
    Ok(Some(Rec {
        kind,
        span: stream.sub(pos, len.saturating_add(4)),
    }))
}

/// The bodies of the CONTINUE records following `pos` (the record after
/// the one being continued).
async fn continues(cx: &Cx, stream: Span, mut pos: u64) -> Result<Vec<Span>> {
    let mut out = Vec::new();
    while let Some(r) = next_rec(cx, stream, pos).await? {
        if r.kind != 0x003c {
            break;
        }
        out.push(r.body());
        pos = pos.saturating_add(r.span.len);
    }
    Ok(out)
}

/// The workbook context, parsed once from the globals substream.
async fn book(cx: &Cx, stream: Span) -> Arc<Book> {
    if let Some(found) = cx.cached::<Book>(stream, "biff-book") {
        return found;
    }
    let book = Arc::new(load_book(cx, stream).await.unwrap_or_default());
    cx.cache(stream, "biff-book", book.clone());
    book
}

async fn load_book(cx: &Cx, stream: Span) -> Result<Book> {
    let mut book = Book {
        codepage: 1252,
        ..Book::default()
    };
    let mut pos = 0u64;
    let mut sheets = Vec::new();
    let mut xti: Vec<(u16, i16)> = Vec::new();
    let mut supbooks = 0u16;
    let mut self_book = None;
    while let Some(r) = next_rec(cx, stream, pos).await? {
        let data = cx.read_avail(r.body().sub(0, 0x2020)).await?;
        match r.kind {
            0x0809 => {
                book.biff8 = u16_le(&data, 0) == Some(0x0600);
                if book.version == 0 {
                    book.version = if book.biff8 { 8 } else { 5 };
                }
            }
            0x0009 | 0x0209 | 0x0409 if book.version == 0 => {
                book.version = match r.kind {
                    0x0009 => 2,
                    0x0209 => 3,
                    _ => 4,
                };
            }
            0x0018 | 0x0218 if book.early() => {
                // BIFF2: five header bytes; BIFF3–4: six, with 16-bit flags.
                let (flags, cch, at) = if r.kind == 0x0018 {
                    (0u16, data.get(3).copied().unwrap_or(0), 5usize)
                } else {
                    (
                        u16_le(&data, 0).unwrap_or(0),
                        data.get(3).copied().unwrap_or(0),
                        6usize,
                    )
                };
                let name = if flags & 0x20 != 0 {
                    ptg::builtin_name(data.get(at).copied().unwrap_or(0))
                } else {
                    data.get(at..at.saturating_add(cch.into()))
                        .map(|raw| rec::codepage_text(book.codepage, raw))
                        .unwrap_or_default()
                };
                book.names.defined.push(name);
            }
            0x0042 => book.codepage = u16_le(&data, 0).unwrap_or(1252),
            0x0022 => book.date1904 = u16_le(&data, 0) == Some(1),
            0x0085 => {
                let form = if book.biff8 {
                    StrForm::Wide8
                } else {
                    StrForm::Bytes8
                };
                sheets.push(
                    xl_string(&data, 6, form)
                        .map(|(s, _)| s)
                        .unwrap_or_default(),
                );
            }
            0x01ae => {
                if u16_le(&data, 2) == Some(0x0401) {
                    self_book = Some(supbooks);
                }
                supbooks = supbooks.saturating_add(1);
            }
            0x0017 if book.biff8 => {
                let n = usize::from(u16_le(&data, 0).unwrap_or(0));
                for i in 0..n {
                    let at = 2usize.saturating_add(i.saturating_mul(6));
                    let (Some(sb), Some(first)) =
                        (u16_le(&data, at), u16_le(&data, at.saturating_add(2)))
                    else {
                        break;
                    };
                    xti.push((sb, first.cast_signed()));
                }
            }
            0x0018 if book.biff8 => {
                let flags = u16_le(&data, 0).unwrap_or(0);
                let cch = usize::from(data.get(3).copied().unwrap_or(0));
                let name = if flags & 0x20 != 0 {
                    ptg::builtin_name(data.get(15).copied().unwrap_or(0))
                } else {
                    xl_string(&data, 14, StrForm::Flags(cch))
                        .map(|(s, _)| s)
                        .unwrap_or_default()
                };
                book.names.defined.push(name);
            }
            0x0018 if book.version == 5 => {
                book.names
                    .defined
                    .push(name5(&data, book.codepage).unwrap_or_default());
            }
            0x00fc if book.biff8 => {
                let mut parts = vec![r.body()];
                parts.extend(continues(cx, stream, pos.saturating_add(r.span.len)).await?);
                book.strings = sst_strings(cx, &parts, STRING_KEEP)
                    .await?
                    .into_iter()
                    .map(|(s, ..)| s)
                    .collect();
            }
            0x000a => break,
            _ => {}
        }
        pos = pos.saturating_add(r.span.len);
    }
    book.names.tabs = sheets.clone();
    book.names.xti = xti
        .into_iter()
        .map(|(sb, first)| {
            if Some(sb) == self_book {
                usize::try_from(first)
                    .ok()
                    .and_then(|i| sheets.get(i).cloned())
                    .unwrap_or_else(|| format!("sheet {first}"))
            } else {
                format!("[{sb}]sheet {first}")
            }
        })
        .collect();
    Ok(book)
}

// ---------------------------------------------------------------------------
// Shared strings

/// Reads strings from SST data split across a record and its CONTINUE
/// records: (text, start, length) with offsets into the concatenation.
/// When a string's characters cross into a CONTINUE record, that record
/// starts with a new flags byte.
async fn sst_strings(cx: &Cx, parts: &[Span], keep: usize) -> Result<Vec<(String, u64, u64)>> {
    let mut data = Vec::new();
    let mut bounds = Vec::new();
    for p in parts {
        cx.checkpoint().await;
        bounds.push(data.len());
        data.extend(cx.read_avail(*p).await?);
    }
    let unique = to_usize(u32_le(&data, 4).unwrap_or(0).into());
    let mut out = Vec::new();
    let mut pos = 8usize;
    for i in 0..unique {
        if i.is_multiple_of(128) {
            cx.checkpoint().await;
        }
        let Some((text, end)) = sst_string(&data, &bounds, pos, keep) else {
            break;
        };
        out.push((text, to_u64(pos), to_u64(end.saturating_sub(pos))));
        pos = end;
    }
    Ok(out)
}

/// One XLUnicodeRichExtendedString at `pos`; returns its text (at most
/// `keep` characters) and the position after it.
fn sst_string(
    data: &[u8],
    bounds: &[usize],
    mut pos: usize,
    keep: usize,
) -> Option<(String, usize)> {
    let cch = usize::from(u16_le(data, pos)?);
    let mut flags = *data.get(pos.checked_add(2)?)?;
    pos = pos.checked_add(3)?;
    let mut runs = 0usize;
    let mut ext = 0usize;
    if flags & 0x08 != 0 {
        runs = usize::from(u16_le(data, pos)?);
        pos = pos.checked_add(2)?;
    }
    if flags & 0x04 != 0 {
        ext = to_usize(u32_le(data, pos)?.into());
        pos = pos.checked_add(4)?;
    }
    let mut left = cch;
    let mut text = String::new();
    let mut kept = 0usize;
    while left > 0 {
        let next = bounds
            .iter()
            .copied()
            .find(|&b| b > pos)
            .unwrap_or(data.len());
        let width = if flags & 1 != 0 { 2 } else { 1 };
        let fit = next.saturating_sub(pos).checked_div(width).unwrap_or(0);
        let take = left.min(fit);
        let raw = data.get(pos..pos.checked_add(take.checked_mul(width)?)?)?;
        if kept < keep {
            let s = if width == 2 {
                crate::text::utf16(raw, LE)
            } else {
                crate::text::latin1(raw)
            };
            kept = kept.saturating_add(take);
            text.push_str(&s);
        }
        pos = pos.checked_add(take.checked_mul(width)?)?;
        left = left.saturating_sub(take);
        if left > 0 {
            if pos >= data.len() || take == 0 && pos != next {
                return None;
            }
            // A CONTINUE record restarts with the flags byte.
            flags = *data.get(pos)?;
            pos = pos.checked_add(1)?;
        }
    }
    pos = pos.checked_add(runs.checked_mul(4)?)?.checked_add(ext)?;
    if pos > data.len() {
        return None;
    }
    if text.chars().count() > keep {
        text = text.chars().take(keep).collect();
    }
    Some((text, pos))
}

// ---------------------------------------------------------------------------
// The stream walk

/// A BIFF5 or BIFF8 workbook stream.
pub async fn workbook(cx: &Cx, input: Input, stream: Span) -> Result<()> {
    let mut pos = 0u64;
    let mut sheets: Vec<(u32, String, u8)> = Vec::new();
    let mut count = 0usize;
    let mut biff8 = true;
    let mut summary_sheets = Vec::new();
    loop {
        let Some(bof) = next_rec(cx, stream, pos).await? else {
            break;
        };
        if !matches!(bof.kind, 0x0809 | 0x0409 | 0x0209 | 0x0009) {
            // Not at a BOF: trailing padding (zeros) or junk.
            let rest = stream.tail(pos);
            let probe = cx.read_avail(rest.sub(0, 4096)).await?;
            let node = Node::new("Padding").span(rest);
            cx.push(if probe.iter().all(|&b| b == 0) {
                node.summary(format!("{} zero bytes after the last substream", rest.len))
            } else {
                node.summary(format!("{} bytes after the last substream", rest.len))
                    .diag(Diagnostic::warning("data after the last EOF record"))
            })
            .await;
            break;
        }
        let head = cx.read_avail(bof.body().sub(0, 8)).await?;
        let version = u16_le(&head, 0).unwrap_or(0);
        let dt = u16_le(&head, 2).unwrap_or(0);
        if count == 0 {
            biff8 = version == 0x0600;
        }
        // Walk to the matching EOF (nested BOFs, e.g. charts in sheets, nest).
        let start = pos;
        let mut depth = 0u32;
        let mut records = 0u64;
        let mut dims = None;
        loop {
            let Some(r) = next_rec(cx, stream, pos).await? else {
                break;
            };
            records = records.saturating_add(1);
            pos = pos.saturating_add(r.span.len);
            cx.progress_in(stream, r.span.offset);
            match r.kind {
                0x0809 | 0x0409 | 0x0209 | 0x0009 => depth = depth.saturating_add(1),
                0x000a => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        break;
                    }
                }
                0x0085 if count == 0 => {
                    let data = cx.read_avail(r.body().sub(0, 300)).await?;
                    let form = if biff8 {
                        StrForm::Wide8
                    } else {
                        StrForm::Bytes8
                    };
                    let name = xl_string(&data, 6, form)
                        .map(|(s, _)| s)
                        .unwrap_or_default();
                    sheets.push((
                        u32_le(&data, 0).unwrap_or(0),
                        name,
                        data.get(5).copied().unwrap_or(0),
                    ));
                }
                0x0200 if depth == 1 && dims.is_none() => {
                    let data = cx.read_avail(r.body()).await?;
                    dims = dimensions(&data, biff8);
                }
                _ => {}
            }
        }
        let span = stream.sub(start, pos.saturating_sub(start));
        let kind = lookup(BOF_TYPES, dt.into()).unwrap_or("substream");
        let name = if dt == 0x0005 {
            "Globals".to_owned()
        } else {
            match sheets.iter().find(|(at, ..)| u64::from(*at) == start) {
                Some((_, n, _)) => {
                    summary_sheets.push(n.clone());
                    format!("Sheet {}", quoted(n, 64))
                }
                None => format!("Substream at {start:#x}"),
            }
        };
        let mut summary = format!(
            "{kind}, {}, {records} records",
            lookup(BIFF_VERSIONS, version.into()).unwrap_or("BIFF?")
        );
        if let Some(d) = dims {
            summary = format!("{summary}, cells {d}");
        }
        cx.push(
            Node::new(name)
                .span(span)
                .summary(summary)
                .lazy(substream, (input, stream, span)),
        )
        .await;
        count = count.saturating_add(1);
    }
    let shown: Vec<String> = summary_sheets
        .iter()
        .take(6)
        .map(|s| quoted(s, 32))
        .collect();
    cx.annotate(format!(
        "Excel {} workbook, {} sheets: {}",
        if biff8 {
            "97–2003 (BIFF8)"
        } else {
            "5.0/95 (BIFF5)"
        },
        sheets.len(),
        shown.join(", ")
    ));
    Ok(())
}

/// "A1:D9" from a DIMENSIONS record.
fn dimensions(data: &[u8], biff8: bool) -> Option<String> {
    let (r1, r2, at) = if biff8 {
        (u32_le(data, 0)?, u32_le(data, 4)?, 8)
    } else {
        (u32::from(u16_le(data, 0)?), u32::from(u16_le(data, 2)?), 4)
    };
    let c1 = u32::from(u16_le(data, at)?);
    let c2 = u32::from(u16_le(data, at.saturating_add(2))?);
    if r2 <= r1 || c2 <= c1 {
        return Some("none".to_owned());
    }
    Some(format!(
        "{}:{}",
        cell_name(c1, r1),
        cell_name(c2.saturating_sub(1), r2.saturating_sub(1))
    ))
}

/// The records of one substream, paged; the Office Art drawing spread over
/// its MSODRAWING records follows them.
async fn substream(cx: Cx, (input, stream, span): (Input, Span, Span)) -> Result<()> {
    let book = book(&cx, stream).await;
    let mut pos = span.offset.saturating_sub(stream.offset);
    let end = span.end().saturating_sub(stream.offset);
    let mut drawing: Vec<Span> = Vec::new();
    let mut continued = 0u16;
    while pos < end {
        let Some(r) = next_rec(&cx, stream, pos).await? else {
            break;
        };
        let next = pos.saturating_add(r.span.len);
        let body_len = r.span.len.saturating_sub(4);
        // Records whose data CONTINUE records extend.
        let parts = match r.kind {
            0x00fc | 0x01b6 | 0x00eb | 0x005d | 0x001c | 0x0018 | 0x00ef => {
                let mut p = vec![r.body()];
                p.extend(continues(&cx, stream, next).await?);
                p
            }
            _ => vec![r.body()],
        };
        if matches!(r.kind, 0x00ec | 0x00eb) {
            drawing.extend(parts.iter().copied());
        }
        if r.kind != 0x003c {
            continued = r.kind;
        }
        let data = cx.read_avail(r.body().sub(0, PEEK)).await?;
        let name = record_name(r.kind, &book)
            .map_or_else(|| format!("Record {:#06x}", r.kind), str::to_owned);
        let mut node = Node::new(name).span(r.span).value(hex(r.kind, 16));
        let summary = if r.kind == 0x003c {
            Some(format!(
                "continues {}",
                record_name(continued, &book).unwrap_or("the previous record")
            ))
        } else {
            describe(&cx, r.kind, &data, &book, &parts).await
        };
        node = node.summary(summary.unwrap_or_else(|| format!("{body_len} bytes")));
        if r.span.len < body_len.saturating_add(4) || r.span.end() > stream.end() {
            node = node.diag(Diagnostic::truncated(r.span, r.span.len));
        }
        cx.progress_in(stream, r.span.offset);
        cx.push(node.lazy(record, (stream, r.span, r.kind, Arc::new(parts))))
            .await;
        pos = next;
    }
    if !drawing.is_empty() {
        let joined = cx.add_pieces(
            Origin {
                parent: span,
                transform: "biff-msodrawing",
            },
            drawing,
        )?;
        cx.push(
            Node::new("Drawing (Office Art)")
                .span(joined)
                .summary(format!(
                    "{} bytes joined from the MSODRAWING records",
                    joined.len
                ))
                .lazy(super::officeart::records_at, (input, joined)),
        )
        .await;
    }
    Ok(())
}

/// A record's one-line summary.
async fn describe(cx: &Cx, kind: u16, data: &[u8], book: &Book, parts: &[Span]) -> Option<String> {
    if book.early() {
        let len = parts.first().map_or(0, |p| p.len);
        if let Some(s) = early_describe(kind, data, len, book) {
            return Some(s);
        }
        if !early_shared(kind) {
            return None;
        }
    }
    let cell = |d: &[u8]| -> Option<String> {
        Some(cell_name(u16_le(d, 2)?.into(), u16_le(d, 0)?.into()))
    };
    let s = match kind {
        0x0809 | 0x0409 | 0x0209 | 0x0009 => format!(
            "{}, {}",
            lookup(BIFF_VERSIONS, u16_le(data, 0)?.into()).unwrap_or("BIFF?"),
            lookup(BOF_TYPES, u16_le(data, 2)?.into()).unwrap_or("unknown type")
        ),
        0x0085 => {
            let form = if book.biff8 {
                StrForm::Wide8
            } else {
                StrForm::Bytes8
            };
            let (name, _) = xl_string(data, 6, form)?;
            format!(
                "{}, {}, BOF at {:#x}",
                quoted(&name, 40),
                lookup(SHEET_TYPES, (*data.get(5)?).into()).unwrap_or("?"),
                u32_le(data, 0)?
            )
        }
        0x00fc => format!(
            "{} unique strings, {} references",
            u32_le(data, 4)?,
            u32_le(data, 0)?
        ),
        0x00ff => format!("index every {} strings", u16_le(data, 0)?),
        0x00fd => {
            let i = to_usize(u32_le(data, 6)?.into());
            match book.strings.get(i) {
                Some(s) => format!("{} = {}", cell(data)?, quoted(s, 60)),
                None => format!("{} = string {i}", cell(data)?),
            }
        }
        0x0203 => format!(
            "{} = {}",
            cell(data)?,
            number(f64::from_bits(u64_le(data, 6)?))
        ),
        0x027e => format!("{} = {}", cell(data)?, number(rec::rk(u32_le(data, 6)?))),
        0x0201 => format!("{} (blank)", cell(data)?),
        0x0205 => {
            let v = *data.get(6)?;
            let text = if data.get(7) == Some(&1) {
                lookup(ptg::ERRORS, v.into()).unwrap_or("#ERROR").to_owned()
            } else if v != 0 {
                "TRUE".to_owned()
            } else {
                "FALSE".to_owned()
            };
            format!("{} = {text}", cell(data)?)
        }
        0x0204 => {
            let form = if book.biff8 {
                StrForm::Wide16
            } else {
                StrForm::Bytes16
            };
            let (s, _) = xl_string(data, 6, form)?;
            format!("{} = {}", cell(data)?, quoted(&s, 60))
        }
        0x00bd | 0x00be => {
            let row = u16_le(data, 0)?;
            let first = u16_le(data, 2)?;
            let total = parts.first().map_or(0, |p| p.len);
            let last = u16_le(data, to_usize(total.saturating_sub(2))).unwrap_or(first);
            format!(
                "{}:{} ({} cells)",
                cell_name(first.into(), row.into()),
                cell_name(last.into(), row.into()),
                last.saturating_sub(first).saturating_add(1)
            )
        }
        0x0006 => {
            let cce = to_usize(u16_le(data, 20)?.into());
            let rgce = data.get(22..22usize.saturating_add(cce))?;
            let text = book
                .formula_version()
                .and_then(|v| ptg::tokens_for(rgce, &book.names, v).1);
            let value = formula_value(data)?;
            match text {
                Some(t) => format!("{} = {t} → {value}", cell(data)?),
                None => format!("{} = ({cce}-byte formula) → {value}", cell(data)?),
            }
        }
        0x0208 => {
            let h = u16_le(data, 6)? & 0x7fff;
            format!(
                "row {}, columns {}–{}, {}",
                u32::from(u16_le(data, 0)?).saturating_add(1),
                column_name(u16_le(data, 2)?.into()),
                column_name(u16_le(data, 4)?.saturating_sub(1).into()),
                rec::points(h.into())
            )
        }
        0x0200 => format!("cells {}", dimensions(data, book.biff8)?),
        0x0042 => format!("code page {}", u16_le(data, 0)?),
        0x0022 => if u16_le(data, 0)? == 1 {
            "1904 date system"
        } else {
            "1900 date system"
        }
        .to_owned(),
        0x0031 => {
            let form = if book.biff8 {
                StrForm::Wide8
            } else {
                StrForm::Bytes8
            };
            let (name, _) = xl_string(data, 14, form)?;
            let weight = u16_le(data, 6)?;
            let flags = u16_le(data, 2)?;
            format!(
                "{}, {}{}{}",
                quoted(&name, 40),
                rec::points(u16_le(data, 0)?.into()),
                if weight >= 700 { ", bold" } else { "" },
                if flags & 2 != 0 { ", italic" } else { "" }
            )
        }
        0x041e => {
            let form = if book.biff8 {
                StrForm::Wide16
            } else {
                StrForm::Bytes8
            };
            let (s, _) = xl_string(data, 2, form)?;
            format!("format {}: {}", u16_le(data, 0)?, quoted(&s, 60))
        }
        0x00e0 => {
            let fmt = u16_le(data, 2)?;
            let flags = u16_le(data, 4)?;
            let fmt_name = lookup(BUILTIN_FORMATS, fmt.into())
                .map_or_else(|| format!("format {fmt}"), |n| format!("{n:?}"));
            format!(
                "{} XF, font {}, {fmt_name}",
                if flags & 4 != 0 { "style" } else { "cell" },
                u16_le(data, 0)?
            )
        }
        0x0293 => {
            let ixfe = u16_le(data, 0)?;
            if ixfe & 0x8000 != 0 {
                format!(
                    "built-in {:?}, XF {}",
                    lookup(STYLES, (*data.get(2)?).into()).unwrap_or("style"),
                    ixfe & 0xfff
                )
            } else {
                let form = if book.biff8 {
                    StrForm::Wide16
                } else {
                    StrForm::Bytes8
                };
                let (s, _) = xl_string(data, 2, form)?;
                format!("{}, XF {}", quoted(&s, 40), ixfe & 0xfff)
            }
        }
        0x00e5 => format!("{} merged ranges", u16_le(data, 0)?),
        0x007d => format!(
            "columns {}–{}, width {}",
            column_name(u16_le(data, 0)?.into()),
            column_name(u16_le(data, 2)?.into()),
            f64::from(u16_le(data, 4)?) / 256.0
        ),
        0x005c => {
            let form = if book.biff8 {
                StrForm::Wide16
            } else {
                StrForm::Bytes8
            };
            match xl_string(data, 0, form) {
                Some((s, used)) if used <= data.len() => quoted(s.trim_end(), 60),
                _ => quoted(crate::text::latin1(data).trim_end(), 60),
            }
        }
        0x0014 | 0x0015 | 0x01ba => {
            if data.is_empty() {
                return Some("empty".to_owned());
            }
            let form = if book.biff8 {
                StrForm::Wide16
            } else {
                StrForm::Bytes8
            };
            quoted(&xl_string(data, 0, form)?.0, 60)
        }
        0x0018 if book.biff8 => {
            let flags = u16_le(data, 0)?;
            let cch = usize::from(*data.get(3)?);
            let name = if flags & 0x20 != 0 {
                ptg::builtin_name(*data.get(15)?)
            } else {
                xl_string(data, 14, StrForm::Flags(cch))?.0
            };
            let cce = usize::from(u16_le(data, 4)?);
            let at = 15usize.saturating_add(cch.saturating_mul(
                if data.get(14).is_some_and(|f| f & 1 != 0) {
                    2
                } else {
                    1
                },
            ));
            let at = if flags & 0x20 != 0 { 16 } else { at };
            let formula = data
                .get(at..at.saturating_add(cce))
                .and_then(|r| ptg::tokens(r, &book.names).1);
            match formula {
                Some(f) => format!("{name} = {f}"),
                None => name,
            }
        }
        0x01ae => match u16_le(data, 2)? {
            0x0401 => format!("this workbook, {} sheets", u16_le(data, 0)?),
            0x3a01 => "add-in functions".to_owned(),
            _ => {
                let (s, _) = xl_string(data, 2, StrForm::Wide16)?;
                format!("external workbook {}", quoted(&s, 60))
            }
        },
        0x0017 if book.biff8 => format!("{} references", u16_le(data, 0)?),
        0x0017 => extern_sheet(&xl_string(data, 0, StrForm::Bytes8)?.0),
        0x0016 => format!("{} EXTERNSHEET records", u16_le(data, 0)?),
        0x0018 if book.version == 5 => {
            let name = name5(data, book.codepage)?;
            let cch = usize::from(*data.get(3)?);
            let flags = u16_le(data, 0)?;
            let cce = usize::from(u16_le(data, 4)?);
            let at = 14usize.saturating_add(if flags & 0x20 != 0 { 1 } else { cch });
            let formula = data
                .get(at..at.saturating_add(cce))
                .and_then(|r| ptg::tokens_for(r, &book.names, 5).1);
            match formula {
                Some(f) => format!("{name} = {f}"),
                None => name,
            }
        }
        0x013d => format!("{} sheet IDs", data.len() / 2),
        0x005d => {
            let ot = u16_le(data, 4)?;
            format!(
                "{} {}",
                lookup(OBJ_TYPES, ot.into()).unwrap_or("object"),
                u16_le(data, 6)?
            )
        }
        0x001c => format!("comment at {}, object {}", cell(data)?, u16_le(data, 6)?),
        0x01b6 => {
            let text = txo_text(cx, parts).await;
            format!("text box: {}", quoted(&text, 60))
        }
        0x00ec | 0x00eb => format!(
            "{} bytes of Office Art",
            parts.iter().map(|p| p.len).sum::<u64>()
        ),
        0x0092 => format!("{} colors", u16_le(data, 0)?),
        0x01c1 => format!("calculated by build {}", u32_le(data, 4)?),
        0x0207 => {
            let form = if book.biff8 {
                StrForm::Wide16
            } else {
                StrForm::Bytes16
            };
            quoted(&xl_string(data, 0, form)?.0, 60)
        }
        0x04bc => format!(
            "shared formula for rows {}–{}",
            u32::from(u16_le(data, 0)?).saturating_add(1),
            u32::from(u16_le(data, 2)?).saturating_add(1)
        ),
        0x01b8 => format!(
            "hyperlink on {}",
            cell_name(u16_le(data, 4)?.into(), u16_le(data, 0)?.into())
        ),
        0x003d => format!("active sheet {}", u16_le(data, 10)?),
        0x023e => {
            let f = u16_le(data, 0)?;
            if f & 0x0200 != 0 {
                "selected sheet"
            } else {
                "sheet window"
            }
            .to_owned()
        }
        0x020b => {
            let n = data.len().saturating_sub(16) / 4;
            format!("{n} row blocks")
        }
        0x00d7 => format!("{} row offsets", data.len().saturating_sub(4) / 2),
        k if (0x0850..=0x08ff).contains(&k) => {
            format!("future record, type {:#06x}", u16_le(data, 0)?)
        }
        _ => return None,
    };
    Some(s)
}

/// The cached value of a FORMULA record.
fn formula_value(data: &[u8]) -> Option<String> {
    formula_result(data.get(6..14)?)
}

/// A FORMULA record's 8-byte cached result.
fn formula_result(raw: &[u8]) -> Option<String> {
    if u16_le(raw, 6)? == 0xffff {
        Some(match raw.first()? {
            0 => "string (next record)".to_owned(),
            1 => if raw.get(2)? != &0 { "TRUE" } else { "FALSE" }.to_owned(),
            2 => lookup(ptg::ERRORS, (*raw.get(2)?).into())
                .unwrap_or("#ERROR")
                .to_owned(),
            3 => "empty string".to_owned(),
            t => format!("cached value type {t}"),
        })
    } else {
        Some(number(f64::from_bits(u64_le(raw, 0)?)))
    }
}

/// The text of a TXO record: the first CONTINUE holds the characters.
async fn txo_text(cx: &Cx, parts: &[Span]) -> String {
    let Some(first) = parts.first() else {
        return String::new();
    };
    let Ok(head) = cx.read_avail(first.sub(0, 18)).await else {
        return String::new();
    };
    let cch = usize::from(u16_le(&head, 10).unwrap_or(0));
    let Some(text) = parts.get(1) else {
        return String::new();
    };
    let Ok(data) = cx.read_avail(text.sub(0, 1 + 2 * 512)).await else {
        return String::new();
    };
    xl_string(&data, 0, StrForm::Flags(cch.min(512)))
        .map(|(s, _)| s)
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Record fields

async fn record(
    cx: Cx,
    (stream, span, kind, parts): (Stream, Span, u16, Arc<Vec<Span>>),
) -> Result<()> {
    let book = book(&cx, stream).await;
    cx.emit(Node::new("Type").span(span.sub(0, 2)).value(Value::Enum {
        raw: kind.into(),
        bits: 16,
        name: record_name(kind, &book),
    }));
    cx.emit(
        Node::new("Length")
            .span(span.sub(2, 2))
            .value(uint(span.len.saturating_sub(4), 16)),
    );
    let body = span.tail(4);
    if body.len == 0 {
        return Ok(());
    }
    let block = cx.block(body).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    let biff8 = book.biff8;
    // BIFF2–4 records with layouts of their own (and those without a
    // decoder) are done here; the rest share the BIFF5 layout.
    let early_done = book.early() && early_fields(&mut f, kind, &book)?;
    match kind {
        _ if early_done => {}
        0x0809 | 0x0409 => bof(&mut f)?,
        0x00fc if biff8 => {
            f.u32("cstTotal")
                .desc("References to shared strings in the workbook")
                .emit()?;
            f.u32("cstUnique").emit()?;
            f.seek(body.len);
            cx.emit(
                Node::new("Strings")
                    .lazy(sst_list, parts.clone())
                    .summary(format!("spread over {} records", parts.len())),
            );
        }
        0x00ff => {
            f.u16("dsst").desc("Strings per bucket").emit()?;
            let mut i = 0u32;
            while f.remaining() >= 8 {
                f.node(
                    Node::new(format!("Bucket {i}"))
                        .span(f.peek_span(8))
                        .summary("stream offset of the bucket's first string"),
                );
                f.u32("ib").emit()?;
                f.u16("cbOffset").emit()?;
                f.u16("reserved").emit()?;
                i = i.saturating_add(1);
            }
        }
        0x0006 => formula(&mut f, &book, true)?,
        0x0221 | 0x04bc => {
            f.u16("rwFirst").emit()?;
            f.u16("rwLast").emit()?;
            f.u8("colFirst").emit()?;
            f.u8("colLast").emit()?;
            if kind == 0x0221 {
                f.u16("Flags").hex().emit()?;
                f.u32("chn").emit()?;
            } else {
                f.u8("reserved").emit()?;
                f.u8("cUse").emit()?;
            }
            rgce(&mut f, &book)?;
        }
        0x00bd => {
            f.u16("rw").emit()?;
            let first = f.u16("colFirst").emit()?;
            let n = f.remaining().saturating_sub(2) / 6;
            for i in 0..n {
                let col = u32::from(first).saturating_add(u32::try_from(i).unwrap_or(0));
                let at = to_usize(f.pos());
                let v = u32_le(&block.data, at.saturating_add(2)).unwrap_or(0);
                f.node(
                    Node::new(format!("Cell {}", column_name(col)))
                        .span(f.peek_span(6))
                        .value(Value::Float(rec::rk(v)))
                        .summary(format!("XF {}", u16_le(&block.data, at).unwrap_or(0))),
                );
                f.skip(6);
            }
            f.u16("colLast").emit()?;
        }
        0x00be => {
            f.u16("rw").emit()?;
            f.u16("colFirst").emit()?;
            while f.remaining() > 2 {
                f.u16("ixfe").emit()?;
            }
            f.u16("colLast").emit()?;
        }
        0x00e0 if biff8 => xf(&mut f)?,
        0x0092 => {
            let n = f.u16("ccv").emit()?;
            for _ in 0..n {
                f.u32("Color")
                    .with(|&v, node| {
                        node.summary(format!(
                            "#{:02x}{:02x}{:02x}",
                            v & 0xff,
                            (v >> 8) & 0xff,
                            (v >> 16) & 0xff
                        ))
                    })
                    .emit()?;
            }
        }
        0x00e5 => {
            let n = f.u16("cmcs").emit()?;
            for _ in 0..n {
                ref8(&mut f, "Range")?;
            }
        }
        0x001d => {
            f.u8("pnn").emit()?;
            f.u16("rwAct").emit()?;
            f.u16("colAct").emit()?;
            f.u16("irefAct").emit()?;
            let n = f.u16("cref").emit()?;
            for _ in 0..n {
                let at = to_usize(f.pos());
                let d = &block.data;
                let summary = format!(
                    "{}:{}",
                    cell_name(
                        d.get(at.saturating_add(4)).copied().unwrap_or(0).into(),
                        u16_le(d, at).unwrap_or(0).into()
                    ),
                    cell_name(
                        d.get(at.saturating_add(5)).copied().unwrap_or(0).into(),
                        u16_le(d, at.saturating_add(2)).unwrap_or(0).into()
                    )
                );
                f.bytes("RefU", 6).with(|_, n| n.summary(summary)).emit()?;
            }
        }
        0x013d => {
            while f.remaining() >= 2 {
                f.u16("Sheet ID").emit()?;
            }
        }
        0x020b if biff8 => {
            f.u32("reserved").emit()?;
            f.u32("rwMic").emit()?;
            f.u32("rwMac").emit()?;
            f.u32("ibXF")
                .hex()
                .desc("Stream offset of the DEFCOLWIDTH record")
                .emit()?;
            while f.remaining() >= 4 {
                f.u32("DBCELL offset").hex().emit()?;
            }
        }
        0x00d7 => {
            f.u32("dbRtrw")
                .desc("Offset back to the first ROW record of the block")
                .emit()?;
            while f.remaining() >= 2 {
                f.u16("Cell offset").emit()?;
            }
        }
        0x0017 if biff8 => {
            let n = f.u16("cXTI").emit()?;
            for i in 0..n {
                let name = book
                    .names
                    .xti
                    .get(usize::from(i))
                    .cloned()
                    .unwrap_or_default();
                f.bytes("XTI", 6).with(|_, n| n.summary(name)).emit()?;
            }
        }
        0x01ae => {
            let ctab = f.u16("ctab").emit()?;
            let marker = f
                .u16("cch")
                .hex()
                .with(|&v, n| {
                    n.summary(match v {
                        0x0401 => "self-reference".to_owned(),
                        0x3a01 => "add-in".to_owned(),
                        n => format!("{n}-character path"),
                    })
                })
                .get()?;
            let _ = ctab;
            if marker != 0x0401 && marker != 0x3a01 {
                f.seek(2);
                rec::field(&mut f, "virtPath", K::XlStr)?;
                for _ in 0..ctab {
                    rec::field(&mut f, "Sheet name", K::XlStr)?;
                }
            } else {
                f.seek(2);
                f.u16("cch").hex().emit()?;
            }
        }
        0x0018 if biff8 => name_record(&mut f, &book)?,
        0x0018 if book.version == 5 => name_record5(&mut f, &book)?,
        0x0016 => {
            f.u16("cxals")
                .desc("EXTERNSHEET records that follow")
                .emit()?;
        }
        0x0017 => {
            f.u8("cch").emit()?;
            let at = to_usize(f.pos());
            let raw = f.block().data.get(at..).unwrap_or_default().to_vec();
            let text = extern_sheet(&rec::codepage_text(book.codepage, &raw));
            f.bytes("rgch", to_u64(raw.len()))
                .with(|_, n| n.summary(text))
                .desc("Encoded document and sheet name")
                .emit()?;
        }
        0x005d if biff8 => obj(&mut f)?,
        0x001c if biff8 => {
            f.u16("rw").emit()?;
            f.u16("col").emit()?;
            f.u16("Flags").flags(NOTE_FLAGS).emit()?;
            f.u16("idObj").emit()?;
            rec::field(&mut f, "stAuthor", K::XlStr)?;
            if f.remaining() == 1 {
                f.u8("Padding").emit()?;
            }
        }
        0x01b6 => {
            f.u16("Flags")
                .with(|&v, n| {
                    n.summary(format!(
                        "horizontal {}, vertical {}",
                        rec::bits(v.into(), 1, 3),
                        rec::bits(v.into(), 4, 3)
                    ))
                })
                .emit()?;
            f.u16("rot").emit()?;
            f.bytes("controlInfo", 6).emit()?;
            f.u16("cchText").emit()?;
            f.u16("cbRuns").emit()?;
            f.u16("ifntEmpty").emit()?;
            let rest = f.remaining();
            if rest > 0 {
                f.bytes("fmla", rest).emit()?;
            }
            if parts.len() > 1 {
                let text = txo_text(&cx, &parts).await;
                cx.emit(
                    Node::new("Text")
                        .span(parts.get(1).copied().unwrap_or(body))
                        .value(Value::Text(text))
                        .summary("in the following CONTINUE record"),
                );
            }
            if let Some(runs) = parts.get(2) {
                cx.emit(
                    Node::new("Formatting runs")
                        .span(*runs)
                        .lazy(txo_runs, *runs),
                );
            }
        }
        0x0293 => {
            let ixfe = f
                .u16("ixfe")
                .with(|&v, n| {
                    n.summary(format!(
                        "XF {}{}",
                        v & 0xfff,
                        if v & 0x8000 != 0 { ", built-in" } else { "" }
                    ))
                })
                .emit()?;
            if ixfe & 0x8000 != 0 {
                f.u8("istyBuiltIn").enumeration(STYLES).emit()?;
                f.u8("iLevel").emit()?;
            } else {
                rec::field(&mut f, "user", if biff8 { K::XlStr } else { K::Str8 })?;
            }
        }
        0x005c => {
            // Padded with spaces to 112 bytes; some writers omit the count.
            let form = if biff8 {
                StrForm::Wide16
            } else {
                StrForm::Bytes8
            };
            match xl_string(&block.data, 0, form).filter(|(_, used)| to_u64(*used) <= body.len) {
                Some(_) => rec::field(&mut f, "userName", if biff8 { K::XlStr } else { K::Str8 })?,
                None => {
                    let text = crate::text::latin1(&block.data);
                    f.node(
                        Node::new("userName")
                            .span(body)
                            .value(Value::Text(text.trim_end().to_owned()))
                            .desc("Not a counted string: the raw padded text"),
                    );
                    f.seek(body.len);
                }
            }
            let rest = f.remaining();
            if rest > 0 {
                f.bytes("Padding", rest)
                    .desc("Spaces up to 112 bytes")
                    .emit()?;
            }
        }
        0x001a | 0x001b => page_breaks(&mut f, biff8)?,
        0x00eb | 0x00ec => {
            let n = f.remaining();
            f.node(
                Node::new("Office Art data")
                    .span(f.peek_span(n))
                    .summary("decoded in the substream's Drawing node"),
            );
            f.skip(n);
        }
        0x003c => {
            let n = f.remaining();
            f.node(
                Node::new("Continued data")
                    .span(f.peek_span(n))
                    .summary("decoded with the record it continues"),
            );
            f.skip(n);
        }
        k if (0x0850..=0x08ff).contains(&k) => {
            f.u16("rt").hex().emit()?;
            f.u16("grbitFrt").hex().emit()?;
            f.bytes("reserved", 8).emit()?;
        }
        _ => {
            if let Some(s) = spec(kind, biff8) {
                rec::layout(&mut f, &s)?;
            }
        }
    }
    let rest = body.len.saturating_sub(f.pos());
    if rest > 0 && f.pos() < body.len {
        cx.emit(
            Node::new(if f.pos() == 0 {
                "Data"
            } else {
                "Remaining data"
            })
            .span(body.tail(f.pos()))
            .summary(format!("{rest} bytes")),
        );
    }
    Ok(())
}

/// HORIZONTALPAGEBREAKS, VERTICALPAGEBREAKS: a count, then the breaks
/// (BIFF8: the row or column and the range it spans; before: the row or
/// column only).
fn page_breaks(f: &mut Fields<'_>, biff8: bool) -> Result<()> {
    let n = f.u16("cbrk").emit()?;
    for _ in 0..n {
        if biff8 {
            if f.remaining() < 6 {
                break;
            }
            f.bytes("Break", 6)
                .desc("Row or column before which the break occurs, then the range it spans")
                .emit()?;
        } else {
            if f.remaining() < 2 {
                break;
            }
            f.u16("Break")
                .desc("Row or column before which the break occurs")
                .emit()?;
        }
    }
    Ok(())
}

type Stream = Span;

/// Decoded formula tokens: offset, length, name and detail.
type Tokens = Arc<Vec<(usize, usize, &'static str, String)>>;

fn bof(f: &mut Fields<'_>) -> Result<()> {
    f.u16("vers").hex().enumeration(BIFF_VERSIONS).emit()?;
    f.u16("dt").enumeration(BOF_TYPES).emit()?;
    f.u16("rupBuild")
        .desc("Build of the application that wrote the file")
        .emit()?;
    f.u16("rupYear").emit()?;
    if f.remaining() >= 8 {
        f.u32("Flags (bfh)")
            .hex()
            .desc("Platforms and application versions that have edited the file")
            .emit()?;
        f.u32("verLowestBiff / verLastXLSaved").hex().emit()?;
    }
    Ok(())
}

fn ref8(f: &mut Fields<'_>, name: &'static str) -> Result<()> {
    let at = to_usize(f.pos());
    let d = &f.block().data;
    let summary = format!(
        "{}:{}",
        cell_name(
            u16_le(d, at.saturating_add(4)).unwrap_or(0).into(),
            u16_le(d, at).unwrap_or(0).into()
        ),
        cell_name(
            u16_le(d, at.saturating_add(6)).unwrap_or(0).into(),
            u16_le(d, at.saturating_add(2)).unwrap_or(0).into()
        )
    );
    f.bytes(name, 8).with(|_, n| n.summary(summary)).emit()?;
    Ok(())
}

fn formula(f: &mut Fields<'_>, book: &Book, cell: bool) -> Result<()> {
    if cell {
        f.u16("rw")
            .with(|&v, n| n.summary(format!("row {}", u32::from(v).saturating_add(1))))
            .emit()?;
        f.u16("col")
            .with(|&v, n| n.summary(format!("column {}", column_name(v.into()))))
            .emit()?;
        f.u16("ixfe").emit()?;
        let at = to_usize(f.pos());
        let summary = formula_value(
            f.block()
                .data
                .get(at.saturating_sub(6)..)
                .unwrap_or_default(),
        );
        f.bytes("val", 8)
            .with(|_, n| n.summary(summary.unwrap_or_default()))
            .desc(
                "Cached result: an IEEE double, or a typed value marked by 0xFFFF in the top bytes",
            )
            .emit()?;
        f.u16("Flags").flags(FORMULA_FLAGS).emit()?;
        f.u32("chn").desc("Reserved (calculation chain)").emit()?;
    }
    rgce(f, book)
}

/// CellParsedFormula: a 16-bit size and the tokens.
fn rgce(f: &mut Fields<'_>, book: &Book) -> Result<()> {
    let cce = f.u16("cce").emit()?;
    rgce_tokens(f, book, cce, true)
}

/// The `cce` bytes of tokens, decoded when the version's are; with `extra`,
/// the bytes after them are the tokens' extra data.
fn rgce_tokens(f: &mut Fields<'_>, book: &Book, cce: u16, extra: bool) -> Result<()> {
    let at = to_usize(f.pos());
    let span = f.peek_span(cce.into());
    let data = f
        .block()
        .data
        .get(at..at.saturating_add(usize::from(cce)))
        .unwrap_or_default()
        .to_vec();
    let Some(version) = book.formula_version() else {
        f.bytes("rgce", cce.into()).emit()?;
        return Ok(());
    };
    let (tokens, text) = ptg::tokens_for(&data, &book.names, version);
    let mut node = Node::new("rgce").span(span);
    if let Some(t) = &text {
        node = node.value(Value::Text(format!("={t}")));
    }
    node = node.summary(format!("{} tokens", tokens.len()));
    f.node(
        node.lazy(
            token_nodes,
            (
                span,
                Arc::new(
                    tokens
                        .into_iter()
                        .map(|t| (t.at, t.len, t.name, t.detail))
                        .collect::<Vec<_>>(),
                ),
            ),
        ),
    );
    f.skip(cce.into());
    let rest = f.remaining();
    if extra && rest > 0 {
        f.bytes("rgcb", rest)
            .desc("Extra data of the tokens (array constants)")
            .emit()?;
    }
    Ok(())
}

async fn token_nodes(cx: Cx, (span, tokens): (Span, Tokens)) -> Result<()> {
    let data = cx.read_avail(span).await?;
    for (at, len, name, detail) in tokens.iter() {
        let ptg = data.get(*at).copied().unwrap_or(0);
        let mut node = Node::new(*name)
            .span(span.sub(to_u64(*at), to_u64(*len)))
            .value(hex(ptg, 8));
        if !detail.is_empty() {
            node = node.summary(detail.clone());
        }
        cx.push(node).await;
    }
    Ok(())
}

fn xf(f: &mut Fields<'_>) -> Result<()> {
    f.u16("ifnt").emit()?;
    f.u16("ifmt")
        .with(|&v, n| match lookup(BUILTIN_FORMATS, v.into()) {
            Some(s) => n.summary(format!("{s:?}")),
            None => n,
        })
        .emit()?;
    f.u16("Type and protection")
        .flags(XF_TYPE_PROT)
        .with(|&v, n| n.summary(format!("parent XF {}", v >> 4)))
        .emit()?;
    f.u8("Alignment")
        .with(|&v, n| {
            n.summary(format!(
                "{}, {}{}",
                lookup(HALIGN, (v & 7).into()).unwrap_or("?"),
                lookup(VALIGN, ((v >> 4) & 7).into()).unwrap_or("?"),
                if v & 8 != 0 { ", wrap" } else { "" }
            ))
        })
        .emit()?;
    f.u8("trot")
        .desc("Rotation in degrees (255: vertical text)")
        .emit()?;
    f.u8("Indent and direction")
        .with(|&v, n| n.summary(format!("indent {}, reading order {}", v & 0xf, v >> 6)))
        .emit()?;
    f.u8("Used attributes")
        .hex()
        .desc("fAtrNum, fAtrFnt, fAtrAlc, fAtrBdr, fAtrPat, fAtrProt (bits 2–7)")
        .emit()?;
    f.u32("Borders 1")
        .hex()
        .with(|&v, n| {
            n.summary(format!(
                "left {}, right {}, top {}, bottom {}",
                v & 0xf,
                (v >> 4) & 0xf,
                (v >> 8) & 0xf,
                (v >> 12) & 0xf
            ))
        })
        .emit()?;
    f.u32("Borders 2").hex().emit()?;
    f.u16("Fill")
        .with(|&v, n| {
            n.summary(format!(
                "foreground {}, background {}",
                v & 0x7f,
                (v >> 7) & 0x7f
            ))
        })
        .emit()?;
    Ok(())
}

fn name_record(f: &mut Fields<'_>, book: &Book) -> Result<()> {
    let flags = f.u16("Flags").flags(NAME_FLAGS).emit()?;
    f.u8("chKey").emit()?;
    let cch = f.u8("cch").emit()?;
    let cce = f.u16("cce").emit()?;
    f.u16("reserved3").emit()?;
    f.u16("itab")
        .desc("1-based sheet index for a local name, 0 for a global one")
        .emit()?;
    f.bytes("reserved4-7", 4).emit()?;
    let at = to_usize(f.pos());
    let decoded = if flags & 0x20 != 0 {
        f.block()
            .data
            .get(at.saturating_add(1))
            .map(|&c| (ptg::builtin_name(c), 2usize))
    } else {
        xl_string(&f.block().data, at, StrForm::Flags(cch.into()))
    };
    if let Some((name, used)) = decoded {
        let used = to_u64(used);
        f.node(
            Node::new("Name")
                .span(f.peek_span(used))
                .value(Value::Text(name)),
        );
        f.skip(used);
    }
    let rest = f.remaining();
    let cce = u64::from(cce).min(rest);
    let at = to_usize(f.pos());
    let data = f
        .block()
        .data
        .get(at..at.saturating_add(to_usize(cce)))
        .unwrap_or_default()
        .to_vec();
    let (tokens, text) = ptg::tokens(&data, &book.names);
    let span = f.peek_span(cce);
    let mut node = Node::new("rgce")
        .span(span)
        .summary(format!("{} tokens", tokens.len()));
    if let Some(t) = text {
        node = node.value(Value::Text(format!("={t}")));
    }
    f.node(
        node.lazy(
            token_nodes,
            (
                span,
                Arc::new(
                    tokens
                        .into_iter()
                        .map(|t| (t.at, t.len, t.name, t.detail))
                        .collect::<Vec<_>>(),
                ),
            ),
        ),
    );
    f.skip(cce);
    Ok(())
}

/// The name of a BIFF5 NAME record (its built-in code with fBuiltin).
fn name5(data: &[u8], codepage: u16) -> Option<String> {
    let flags = u16_le(data, 0)?;
    let cch = usize::from(*data.get(3)?);
    Some(if flags & 0x20 != 0 {
        ptg::builtin_name(*data.get(14)?)
    } else {
        rec::codepage_text(codepage, data.get(14..14usize.saturating_add(cch))?)
    })
}

/// BIFF5 NAME: flags, shortcut, name and formula lengths, the EXTERNSHEET
/// and sheet indices, four description lengths, the name (8-bit) and the
/// formula.
fn name_record5(f: &mut Fields<'_>, book: &Book) -> Result<()> {
    let flags = f.u16("Flags").flags(NAME_FLAGS).emit()?;
    f.u8("chKey").emit()?;
    let cch = f.u8("cch").emit()?;
    let cce = f.u16("cce").emit()?;
    f.u16("ixals")
        .desc("EXTERNSHEET index of a local name's sheet")
        .emit()?;
    f.u16("itab")
        .desc("1-based sheet index for a local name, 0 for a global one")
        .emit()?;
    f.u8("cchCustMenu").emit()?;
    f.u8("cchDescription").emit()?;
    f.u8("cchHelptopic").emit()?;
    f.u8("cchStatustext").emit()?;
    let used = if flags & 0x20 != 0 { 1 } else { u64::from(cch) };
    if let Some(name) = name5(&f.block().data, book.codepage) {
        f.node(
            Node::new("Name")
                .span(f.peek_span(used))
                .value(Value::Text(name)),
        );
    }
    f.skip(used);
    rgce_tokens(f, book, cce, false)
}

/// An EXTERNSHEET record's encoded name: a leading code says what it is.
fn extern_sheet(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some('\u{3}') => format!("sheet {} of this workbook", quoted(chars.as_str(), 60)),
        Some('\u{2}') => format!("sheet {} of this document", quoted(chars.as_str(), 60)),
        Some('\u{4}') => "this workbook (add-in functions)".to_owned(),
        Some('\u{1}') => format!("external document {}", quoted(chars.as_str(), 60)),
        _ => quoted(s, 60),
    }
}

/// OBJ: a list of sub-records ending with ftEnd.
fn obj(f: &mut Fields<'_>) -> Result<()> {
    let mut ot = 0u16;
    while f.remaining() >= 4 {
        let at = to_usize(f.pos());
        let data = &f.block().data;
        let ft = u16_le(data, at).unwrap_or(0);
        let mut cb = u64::from(u16_le(data, at.saturating_add(2)).unwrap_or(0));
        if ft == 0x13 {
            // ftLbsData's size field is not its size; the rest is its data.
            cb = f.remaining().saturating_sub(4);
        }
        let span = f.peek_span(cb.saturating_add(4));
        let name = lookup(OBJ_SUBRECORDS, ft.into()).unwrap_or("unknown sub-record");
        let mut node = Node::new(name).span(span).value(hex(ft, 16));
        if ft == 0x15 {
            ot = u16_le(data, at.saturating_add(4)).unwrap_or(0);
            node = node
                .summary(format!(
                    "{} {}",
                    lookup(OBJ_TYPES, ot.into()).unwrap_or("object"),
                    u16_le(data, at.saturating_add(6)).unwrap_or(0)
                ))
                .lazy(cmo_node, span);
        } else if ft == 0x0d {
            node = node.summary("note: GUID and shared-note flag");
        }
        f.node(node);
        f.skip(cb.saturating_add(4));
        if ft == 0 {
            break;
        }
    }
    let _ = ot;
    let rest = f.remaining();
    if rest > 0 {
        f.bytes("Padding", rest).emit()?;
    }
    Ok(())
}

async fn cmo_node(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u16("ft").hex().emit()?;
    f.u16("cb").emit()?;
    f.u16("ot").enumeration(OBJ_TYPES).emit()?;
    f.u16("id").emit()?;
    f.u16("Flags").flags(CMO_FLAGS).emit()?;
    f.bytes("unused", 12).emit()?;
    Ok(())
}

async fn txo_runs(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    for (i, c) in data.as_chunks::<8>().0.iter().enumerate() {
        let ich = u16::from_le_bytes([c[0], c[1]]);
        let ifnt = u16::from_le_bytes([c[2], c[3]]);
        cx.push(
            Node::new(format!("Run {i}"))
                .span(span.sub(to_u64(i).saturating_mul(8), 8))
                .value(uint(ich, 16))
                .summary(format!("from character {ich}, font {ifnt}")),
        )
        .await;
    }
    Ok(())
}

/// The shared strings, paged, over the SST and its CONTINUE records joined.
async fn sst_list(cx: Cx, parts: Arc<Vec<Span>>) -> Result<()> {
    let Some(first) = parts.first() else {
        return Ok(());
    };
    let joined = cx.add_pieces(
        Origin {
            parent: *first,
            transform: "biff-continue",
        },
        parts.to_vec(),
    )?;
    let strings = sst_strings(&cx, &parts, 4096).await?;
    cx.set_count(Count::Exact(to_u64(strings.len())));
    for (i, (text, at, len)) in strings.into_iter().enumerate() {
        cx.push(
            Node::new(format!("String {i}"))
                .span(joined.sub(at, len))
                .value(Value::Text(text)),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// BIFF2–4: standalone Excel 2.x–4.0 streams
//
// Layouts from the OpenOffice.org "Microsoft Excel File Format"
// documentation, checked against LibreOffice's importer: BIFF2 cell records
// carry three attribute bytes where later versions have an XF index, BIFF2
// counts and flags are often 8-bit where BIFF3–4 have 16 bits, and BIFF3–4
// FORMULA, ARRAY and NAME records lack the fields BIFF5 added.

/// BIFF2–4 font attributes.
const EARLY_FONT_FLAGS: FlagTable = &[
    flag(0x0001, "fBold"),
    flag(0x0002, "fItalic"),
    flag(0x0004, "fUnderline"),
    flag(0x0008, "fStrikeOut"),
    flag(0x0010, "fOutline"),
    flag(0x0020, "fShadow"),
];

const USED_ATTRIBUTES: &str =
    "Attribute groups (bits 2–7: number format, font, alignment, borders, background, protection)";

/// Records whose BIFF2–4 layout is the BIFF5 one, decoded by the shared
/// code.
fn early_shared(kind: u16) -> bool {
    matches!(
        kind,
        0x000a
            | 0x000c..=0x0015
            | 0x0019
            | 0x001d
            | 0x0022
            | 0x0026..=0x002b
            | 0x003c
            | 0x0040
            | 0x0042
            | 0x0055
            | 0x005c
            | 0x005f
            | 0x0063
            | 0x007d
            | 0x0080..=0x0084
            | 0x008c
            | 0x008d
            | 0x0092
            | 0x0099
            | 0x00a0
            | 0x0200
            | 0x0201
            | 0x0203..=0x0205
            | 0x0208
            | 0x0225
            | 0x023e
            | 0x027e
            | 0x0293
    )
}

/// The value of a BOOLERR cell.
fn bool_err(value: u8, error: bool) -> String {
    if error {
        lookup(ptg::ERRORS, value.into())
            .unwrap_or("#ERROR")
            .to_owned()
    } else if value != 0 {
        "TRUE".to_owned()
    } else {
        "FALSE".to_owned()
    }
}

/// "row 3, columns A–D, 12.75 pt" for a ROW record (BIFF2 and BIFF3–4 put
/// these fields at the same offsets).
fn row_summary(data: &[u8]) -> Option<String> {
    let h = u16_le(data, 6)? & 0x7fff;
    Some(format!(
        "row {}, columns {}–{}, {}",
        u32::from(u16_le(data, 0)?).saturating_add(1),
        column_name(u16_le(data, 2)?.into()),
        column_name(u16_le(data, 4)?.saturating_sub(1).into()),
        rec::points(h.into())
    ))
}

/// The summary of a BIFF2–4 record laid out differently from BIFF5 (`len`
/// is the body's full length; `data` may be its start only).
fn early_describe(kind: u16, data: &[u8], len: u64, book: &Book) -> Option<String> {
    let cell =
        || -> Option<String> { Some(cell_name(u16_le(data, 2)?.into(), u16_le(data, 0)?.into())) };
    let bytes8 = |at: usize| xl_string(data, at, StrForm::Bytes8).map(|(s, _)| s);
    let s = match kind {
        0x0009 | 0x0209 | 0x0409 => format!(
            "BIFF{}, {}",
            match kind {
                0x0009 => 2,
                0x0209 => 3,
                _ => 4,
            },
            lookup(BOF_TYPES, u16_le(data, 2)?.into()).unwrap_or("unknown type")
        ),
        0x0000 => format!("cells {}", dimensions(data, false)?),
        0x0001 => format!("{} (blank)", cell()?),
        0x0002 => format!("{} = {}", cell()?, u16_le(data, 7)?),
        0x0003 => format!("{} = {}", cell()?, number(f64::from_bits(u64_le(data, 7)?))),
        0x0004 => format!("{} = {}", cell()?, quoted(&bytes8(7)?, 60)),
        0x0005 => format!(
            "{} = {}",
            cell()?,
            bool_err(*data.get(7)?, data.get(8) == Some(&1))
        ),
        0x0006 | 0x0206 | 0x0406 => {
            let (result, cce, at) = if kind == 0x0006 {
                (data.get(7..15)?, usize::from(*data.get(16)?), 17usize)
            } else {
                (data.get(6..14)?, usize::from(u16_le(data, 16)?), 18)
            };
            let value = formula_result(result)?;
            let text = data
                .get(at..at.saturating_add(cce))
                .and_then(|rgce| ptg::tokens_for(rgce, &book.names, book.version).1);
            match text {
                Some(t) => format!("{} = {t} → {value}", cell()?),
                None => format!("{} = ({cce}-byte formula) → {value}", cell()?),
            }
        }
        0x0007 => quoted(&bytes8(0)?, 60),
        0x0207 => quoted(&xl_string(data, 0, StrForm::Bytes16)?.0, 60),
        0x0008 => row_summary(data)?,
        0x000b | 0x020b => {
            let head = if kind == 0x000b { 8 } else { 12 };
            format!("{} row blocks", len.saturating_sub(head) / 4)
        }
        0x0016 => format!("{} external references", u16_le(data, 0)?),
        0x0017 => quoted(&bytes8(0)?, 60),
        0x0018 | 0x0218 => {
            let (flags, cch, cce, at) = if kind == 0x0018 {
                (
                    0u16,
                    usize::from(*data.get(3)?),
                    usize::from(*data.get(4)?),
                    5usize,
                )
            } else {
                (
                    u16_le(data, 0)?,
                    usize::from(*data.get(3)?),
                    usize::from(u16_le(data, 4)?),
                    6,
                )
            };
            let name = if flags & 0x20 != 0 {
                ptg::builtin_name(*data.get(at)?)
            } else {
                rec::codepage_text(book.codepage, data.get(at..at.saturating_add(cch))?)
            };
            let start = at.saturating_add(cch);
            let formula = data
                .get(start..start.saturating_add(cce))
                .and_then(|r| ptg::tokens_for(r, &book.names, book.version).1);
            match formula {
                Some(f) => format!("{name} = {f}"),
                None => name,
            }
        }
        0x001a | 0x001b => format!("{} breaks", u16_le(data, 0)?),
        0x001c => {
            let text = xl_string(data, 4, StrForm::Bytes16)
                .map(|(s, _)| s)
                .unwrap_or_default();
            if u16_le(data, 0)? == 0xffff {
                format!("comment continued: {}", quoted(&text, 60))
            } else {
                format!("comment at {}: {}", cell()?, quoted(&text, 60))
            }
        }
        0x001e => format!("format {}", quoted(&bytes8(0)?, 60)),
        0x041e => format!("format {}", quoted(&bytes8(2)?, 60)),
        0x001f => format!("{} formats", u16_le(data, 0)?),
        0x0056 => format!("{} built-in formats", u16_le(data, 0)?),
        0x0020 => format!(
            "default attributes of columns {}–{}",
            column_name(u16_le(data, 0)?.into()),
            column_name(u16_le(data, 2)?.saturating_sub(1).into())
        ),
        0x0021 | 0x0221 => format!(
            "array formula in {}:{}",
            cell_name((*data.get(4)?).into(), u16_le(data, 0)?.into()),
            cell_name((*data.get(5)?).into(), u16_le(data, 2)?.into())
        ),
        0x0024 => format!(
            "columns {}–{}, width {}",
            column_name((*data.first()?).into()),
            column_name((*data.get(1)?).into()),
            f64::from(u16_le(data, 2)?) / 256.0
        ),
        0x0025 => format!(
            "default row height {}",
            rec::points((u16_le(data, 0)? & 0x7fff).into())
        ),
        0x0031 | 0x0231 => {
            let name = bytes8(if kind == 0x0031 { 4 } else { 6 })?;
            let flags = u16_le(data, 2)?;
            format!(
                "{}, {}{}{}",
                quoted(&name, 40),
                rec::points(u16_le(data, 0)?.into()),
                if flags & 1 != 0 { ", bold" } else { "" },
                if flags & 2 != 0 { ", italic" } else { "" }
            )
        }
        0x003d => format!(
            "window {}×{} twips{}",
            u16_le(data, 4)?,
            u16_le(data, 6)?,
            if data.get(8).is_some_and(|&h| h != 0) {
                ", hidden"
            } else {
                ""
            }
        ),
        0x003e => "sheet window".to_owned(),
        0x0041 => format!(
            "panes from {}",
            cell_name(u16_le(data, 6)?.into(), u16_le(data, 4)?.into())
        ),
        0x0043 => format!("XF, font {}, format {}", data.first()?, data.get(2)? & 0x3f),
        0x0243 | 0x0443 => format!(
            "{} XF, font {}, format {}",
            if data.get(2)? & 4 != 0 {
                "style"
            } else {
                "cell"
            },
            data.first()?,
            data.get(1)?
        ),
        0x0044 => format!("XF {}", u16_le(data, 0)?),
        0x0045 => format!("color {}", u16_le(data, 0)?),
        0x00a1 => format!(
            "paper size {}, scale {}%",
            u16_le(data, 0)?,
            u16_le(data, 2)?
        ),
        _ => return None,
    };
    Some(s)
}

/// The fields of a BIFF2–4 record laid out differently from BIFF5. Returns
/// false for the records that share the BIFF5 layout; records without a
/// decoder are left as data.
fn early_fields(f: &mut Fields<'_>, kind: u16, book: &Book) -> Result<bool> {
    if early_shared(kind) {
        return Ok(false);
    }
    match kind {
        0x0009 | 0x0209 | 0x0409 => {
            f.u16("vers").hex().emit()?;
            f.u16("dt").enumeration(BOF_TYPES).emit()?;
            if f.remaining() >= 2 {
                f.u16("unused").emit()?;
            }
        }
        0x0000 => {
            let s: Spec = &[
                ("rwMic", K::Row),
                ("rwMac", K::Row),
                ("colMic", K::Col),
                ("colMac", K::Col),
            ];
            rec::layout(f, &s)?;
        }
        0x0001..=0x0006 => {
            early_cell(f, true)?;
            match kind {
                0x0002 => {
                    f.u16("w").emit()?;
                }
                0x0003 => {
                    f.f64("num").emit()?;
                }
                0x0004 => rec::field(f, "Text", K::Str8)?,
                0x0005 => {
                    f.u8("bBoolErr").emit()?;
                    rec::field(f, "fError", K::Bool8)?;
                }
                0x0006 => early_formula(f, book, true)?,
                _ => {}
            }
        }
        0x0206 | 0x0406 => {
            early_cell(f, false)?;
            early_formula(f, book, false)?;
        }
        0x0007 => rec::field(f, "Text", K::Str8)?,
        0x0207 => rec::field(f, "Text", K::Str16)?,
        0x0008 => {
            rec::field(f, "rw", K::Row)?;
            rec::field(f, "colMic", K::Col)?;
            rec::field(f, "colMac", K::Col)?;
            f.u16("miyRw")
                .with(|&v, n| {
                    let height = rec::points((v & 0x7fff).into());
                    n.summary(if v & 0x8000 != 0 {
                        format!("{height}, default height")
                    } else {
                        height
                    })
                })
                .emit()?;
            f.u16("reserved").emit()?;
            let attrs = f
                .u8("fAttr")
                .with(|&v, n| n.value(Value::Bool(v != 0)))
                .desc("Default cell attributes follow")
                .emit()?;
            f.u16("Offset to the row's cells").emit()?;
            if attrs != 0 && f.remaining() >= 3 {
                attributes(f)?;
            }
        }
        0x000b | 0x020b => {
            f.u32("reserved").emit()?;
            rec::field(f, "rwMic", K::Row)?;
            f.u16("rwMac").desc("One past the last row").emit()?;
            if kind == 0x020b {
                f.u32("ib").hex().emit()?;
            }
            while f.remaining() >= 4 {
                f.u32("Offset").hex().emit()?;
            }
        }
        0x0016 => {
            f.u16("cxals")
                .desc("EXTERNSHEET records that follow")
                .emit()?;
        }
        0x0017 => rec::field(f, "Encoded file name", K::Str8)?,
        0x0018 | 0x0218 => early_name(f, book, kind == 0x0018)?,
        0x001a | 0x001b => page_breaks(f, false)?,
        0x001c => {
            rec::field(f, "rw", K::Row)?;
            rec::field(f, "col", K::Col)?;
            rec::field(f, "Text", K::Str16)?;
        }
        0x001e => rec::field(f, "stFormat", K::Str8)?,
        0x041e => {
            f.u16("ifmt")
                .desc("Undefined in BIFF4: formats are numbered in record order")
                .emit()?;
            rec::field(f, "stFormat", K::Str8)?;
        }
        0x001f => {
            f.u16("cFormat").emit()?;
        }
        0x0056 => {
            f.u16("cBuiltInFormats").emit()?;
        }
        0x0020 => {
            rec::field(f, "colMic", K::Col)?;
            rec::field(f, "colMac", K::Col)?;
            while f.remaining() >= 3 {
                attributes(f)?;
            }
        }
        0x0021 | 0x0221 => {
            rec::field(f, "rwFirst", K::Row)?;
            rec::field(f, "rwLast", K::Row)?;
            rec::field(f, "colFirst", K::Col8)?;
            rec::field(f, "colLast", K::Col8)?;
            let cce = if kind == 0x0021 {
                f.u8("Flags").hex().emit()?;
                u16::from(f.u8("cce").emit()?)
            } else {
                f.u16("Flags").hex().emit()?;
                f.u16("cce").emit()?
            };
            rgce_tokens(f, book, cce, true)?;
        }
        0x0024 => {
            rec::field(f, "colFirst", K::Col8)?;
            rec::field(f, "colLast", K::Col8)?;
            f.u16("coldx (1/256 character)").emit()?;
        }
        0x0025 => {
            f.u16("miyRw")
                .with(|&v, n| n.summary(rec::points((v & 0x7fff).into())))
                .emit()?;
        }
        0x0031 | 0x0231 => {
            rec::field(f, "dyHeight", K::Twips)?;
            f.u16("Flags").flags(EARLY_FONT_FLAGS).emit()?;
            if kind == 0x0231 {
                f.u16("icv").emit()?;
            }
            rec::field(f, "fontName", K::Str8)?;
        }
        0x003d => {
            let s: Spec = &[
                ("xWn", K::I16),
                ("yWn", K::I16),
                ("dxWn", K::U16),
                ("dyWn", K::U16),
                ("fHidden", K::Bool8),
            ];
            rec::layout(f, &s)?;
        }
        0x003e => {
            let s: Spec = &[
                ("fDspFmla", K::Bool8),
                ("fDspGrid", K::Bool8),
                ("fDspRwCol", K::Bool8),
                ("fFrozen", K::Bool8),
                ("fDspZeros", K::Bool8),
                ("rwTop", K::Row),
                ("colLeft", K::Col),
                ("fDefaultHdr", K::Bool8),
                ("rgbHdr", K::H32),
            ];
            rec::layout(f, &s)?;
        }
        0x0041 => {
            let s: Spec = &[
                ("x", K::U16),
                ("y", K::U16),
                ("rwTop", K::Row),
                ("colLeft", K::Col),
                ("pnnAcct", K::U8),
            ];
            rec::layout(f, &s)?;
        }
        0x0043 => {
            f.u8("ifnt").emit()?;
            f.u8("reserved").emit()?;
            f.u8("Format and protection")
                .with(|&v, n| {
                    n.summary(format!(
                        "format {}{}{}",
                        v & 0x3f,
                        if v & 0x40 != 0 { ", locked" } else { "" },
                        if v & 0x80 != 0 { ", hidden" } else { "" }
                    ))
                })
                .emit()?;
            f.u8("Alignment and borders")
                .with(|&v, n| n.summary(early_borders(v)))
                .emit()?;
        }
        0x0243 | 0x0443 => early_xf(f, kind == 0x0443)?,
        0x0044 => {
            f.u16("ixfe").emit()?;
        }
        0x0045 => {
            f.u16("icv").emit()?;
        }
        0x00a1 => {
            let s: Spec = &[
                ("iPaperSize", K::U16),
                ("iScale", K::U16),
                ("iPageStart", K::I16),
                ("iFitWidth", K::U16),
                ("iFitHeight", K::U16),
                ("Flags", K::H16),
            ];
            rec::layout(f, &s)?;
        }
        _ => {}
    }
    Ok(true)
}

/// The cell address, then BIFF2's three attribute bytes or BIFF3–4's XF
/// index.
fn early_cell(f: &mut Fields<'_>, v2: bool) -> Result<()> {
    rec::field(f, "rw", K::Row)?;
    rec::field(f, "col", K::Col)?;
    if v2 {
        attributes(f)
    } else {
        f.u16("ixfe").emit()?;
        Ok(())
    }
}

/// BIFF2 cell attributes: XF index and protection, number format and
/// font, alignment and borders.
fn attributes(f: &mut Fields<'_>) -> Result<()> {
    let at = to_usize(f.pos());
    let d = &f.block().data;
    let b = |i: usize| d.get(at.saturating_add(i)).copied().unwrap_or(0);
    let (a, n, s) = (b(0), b(1), b(2));
    let summary = format!(
        "XF {}, format {}, font {}, {}{}{}",
        a & 0x3f,
        n & 0x3f,
        n >> 6,
        early_borders(s),
        if a & 0x40 != 0 { ", locked" } else { "" },
        if a & 0x80 != 0 {
            ", formula hidden"
        } else {
            ""
        }
    );
    f.bytes("rgbAttr", 3)
        .with(|_, node| node.summary(summary))
        .emit()?;
    Ok(())
}

/// BIFF2 alignment, borders and shading (one byte).
fn early_borders(v: u8) -> String {
    let mut parts = vec![lookup(HALIGN, (v & 7).into()).unwrap_or("?").to_owned()];
    for (bit, name) in [
        (0x08u8, "left border"),
        (0x10, "right border"),
        (0x20, "top border"),
        (0x40, "bottom border"),
        (0x80, "shaded"),
    ] {
        if v & bit != 0 {
            parts.push(name.to_owned());
        }
    }
    parts.join(", ")
}

/// A BIFF2–4 FORMULA record after the cell: the cached result, flags and
/// tokens (BIFF2: 8-bit flags and size).
fn early_formula(f: &mut Fields<'_>, book: &Book, v2: bool) -> Result<()> {
    let at = to_usize(f.pos());
    let summary = f
        .block()
        .data
        .get(at..at.saturating_add(8))
        .and_then(formula_result);
    f.bytes("val", 8)
        .with(|_, n| n.summary(summary.unwrap_or_default()))
        .desc("Cached result: an IEEE double, or a typed value marked by 0xFFFF in the top bytes")
        .emit()?;
    let cce = if v2 {
        f.u8("Flags").hex().emit()?;
        u16::from(f.u8("cce").emit()?)
    } else {
        f.u16("Flags").hex().emit()?;
        f.u16("cce").emit()?
    };
    rgce_tokens(f, book, cce, true)
}

/// BIFF2 NAME (five header bytes, as LibreOffice reads them) and BIFF3–4
/// NAME (six): flags, shortcut, name and formula lengths, the name, the
/// formula.
fn early_name(f: &mut Fields<'_>, book: &Book, v2: bool) -> Result<()> {
    let (flags, cch, cce) = if v2 {
        f.u8("Flags").hex().emit()?;
        f.u8("reserved").emit()?;
        f.u8("chKey").emit()?;
        let cch = f.u8("cch").emit()?;
        let cce = f.u8("cce").emit()?;
        (0u16, cch, u16::from(cce))
    } else {
        let flags = f.u16("Flags").flags(NAME_FLAGS).emit()?;
        f.u8("chKey").emit()?;
        let cch = f.u8("cch").emit()?;
        let cce = f.u16("cce").emit()?;
        (flags, cch, cce)
    };
    let at = to_usize(f.pos());
    let used = usize::from(cch);
    let data = &f.block().data;
    let name = if flags & 0x20 != 0 {
        data.get(at).map(|&c| ptg::builtin_name(c))
    } else {
        data.get(at..at.saturating_add(used))
            .map(|raw| rec::codepage_text(book.codepage, raw))
    };
    if let Some(name) = name {
        f.node(
            Node::new("Name")
                .span(f.peek_span(to_u64(used)))
                .value(Value::Text(name)),
        );
        f.skip(to_u64(used));
    }
    rgce_tokens(f, book, cce, false)
}

/// BIFF3 (0x0243) and BIFF4 (0x0443) XF records: twelve bytes, the
/// alignment and used-attribute bytes swapped between them.
fn early_xf(f: &mut Fields<'_>, v4: bool) -> Result<()> {
    f.u8("ifnt").emit()?;
    f.u8("ifmt")
        .desc("Index of the FORMAT record, in record order")
        .emit()?;
    if v4 {
        f.u16("Type and protection")
            .flags(XF_TYPE_PROT)
            .with(|&v, n| n.summary(format!("parent XF {}", v >> 4)))
            .emit()?;
        f.u8("Alignment")
            .with(|&v, n| {
                n.summary(format!(
                    "{}, {}{}",
                    lookup(HALIGN, (v & 7).into()).unwrap_or("?"),
                    lookup(VALIGN, ((v >> 4) & 3).into()).unwrap_or("?"),
                    if v & 8 != 0 { ", wrap" } else { "" }
                ))
            })
            .emit()?;
        f.u8("Used attributes").hex().desc(USED_ATTRIBUTES).emit()?;
    } else {
        f.u8("Type and protection").flags(XF_TYPE_PROT).emit()?;
        f.u8("Used attributes").hex().desc(USED_ATTRIBUTES).emit()?;
        f.u16("Alignment and parent")
            .with(|&v, n| {
                n.summary(format!(
                    "{}{}, parent XF {}",
                    lookup(HALIGN, (v & 7).into()).unwrap_or("?"),
                    if v & 8 != 0 { ", wrap" } else { "" },
                    v >> 4
                ))
            })
            .emit()?;
    }
    f.u16("Fill")
        .with(|&v, n| {
            n.summary(format!(
                "pattern {}, foreground {}, background {}",
                v & 0x3f,
                (v >> 6) & 0x1f,
                v >> 11
            ))
        })
        .emit()?;
    f.u32("Borders").hex().emit()?;
    Ok(())
}

/// A standalone BIFF2–4 stream (Excel 2.x–4.0): a worksheet, chart or
/// macro sheet, or a BIFF4 workbook of several; its records are listed like
/// a BIFF5/8 substream's.
pub async fn early_stream(cx: Cx, input: Input) -> Result<()> {
    let stream = input.span;
    let book = book(&cx, stream).await;
    let head = cx.read_avail(stream.sub(0, 8)).await?;
    let dt = u16_le(&head, 6).unwrap_or(0);
    let (mut records, mut cells, mut fonts) = (0u64, 0u64, 0u64);
    let mut dims = None;
    let mut pos = 0u64;
    while let Some(r) = next_rec(&cx, stream, pos).await? {
        records = records.saturating_add(1);
        match r.kind {
            0x0001..=0x0006 | 0x0201 | 0x0203..=0x0206 | 0x027e | 0x0406 => {
                cells = cells.saturating_add(1);
            }
            0x0031 | 0x0231 => fonts = fonts.saturating_add(1),
            0x0000 | 0x0200 if dims.is_none() => {
                let data = cx.read_avail(r.body().sub(0, 16)).await?;
                dims = dimensions(&data, false);
            }
            _ => {}
        }
        cx.progress_in(stream, r.span.offset);
        pos = pos.saturating_add(r.span.len.max(4));
    }
    let kind = if dt == 0x0100 {
        "workbook"
    } else {
        lookup(BOF_TYPES, dt.into()).unwrap_or("document")
    };
    let mut summary = format!(
        "Excel {} {kind} (BIFF{}), {records} records, {cells} cells, {}",
        match book.version {
            2 => "2.x",
            3 => "3.0",
            _ => "4.0",
        },
        book.version,
        plural(fonts, "font")
    );
    if let Some(d) = dims {
        summary = format!("{summary}, used range {d}");
    }
    cx.annotate(summary);
    substream(cx, (input, stream, stream)).await
}
