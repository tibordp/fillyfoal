//! Names of file node types, object classes (JCIDs) and properties.
//!
//! File node IDs are from [MS-ONESTORE]. JCIDs and property IDs are from
//! [MS-ONE], from memory; they agree with the tables of pyOneNote (an
//! independent reader). Property IDs are full 32-bit values: the low 26 bits
//! are the ID, bits 26..31 the data type (so the type is part of the name),
//! bit 31 the value of a Boolean property, which is masked off for lookups.

use crate::value::EnumTable;

pub const FILE_NODE_IDS: EnumTable = &[
    (0x004, "ObjectSpaceManifestRootFND"),
    (0x008, "ObjectSpaceManifestListReferenceFND"),
    (0x00C, "ObjectSpaceManifestListStartFND"),
    (0x010, "RevisionManifestListReferenceFND"),
    (0x014, "RevisionManifestListStartFND"),
    (0x01B, "RevisionManifestStart4FND"),
    (0x01C, "RevisionManifestEndFND"),
    (0x01E, "RevisionManifestStart6FND"),
    (0x01F, "RevisionManifestStart7FND"),
    (0x021, "GlobalIdTableStartFNDX"),
    (0x022, "GlobalIdTableStart2FND"),
    (0x024, "GlobalIdTableEntryFNDX"),
    (0x025, "GlobalIdTableEntry2FNDX"),
    (0x026, "GlobalIdTableEntry3FNDX"),
    (0x028, "GlobalIdTableEndFNDX"),
    (0x02D, "ObjectDeclarationWithRefCountFNDX"),
    (0x02E, "ObjectDeclarationWithRefCount2FNDX"),
    (0x041, "ObjectRevisionWithRefCountFNDX"),
    (0x042, "ObjectRevisionWithRefCount2FNDX"),
    (0x059, "RootObjectReference2FNDX"),
    (0x05A, "RootObjectReference3FND"),
    (0x05C, "RevisionRoleDeclarationFND"),
    (0x05D, "RevisionRoleAndContextDeclarationFND"),
    (0x072, "ObjectDeclarationFileData3RefCountFND"),
    (0x073, "ObjectDeclarationFileData3LargeRefCountFND"),
    (0x07C, "ObjectDataEncryptionKeyV2FNDX"),
    (0x084, "ObjectInfoDependencyOverridesFND"),
    (0x08C, "DataSignatureGroupDefinitionFND"),
    (0x090, "FileDataStoreListReferenceFND"),
    (0x094, "FileDataStoreObjectReferenceFND"),
    (0x0A4, "ObjectDeclaration2RefCountFND"),
    (0x0A5, "ObjectDeclaration2LargeRefCountFND"),
    (0x0B0, "ObjectGroupListReferenceFND"),
    (0x0B4, "ObjectGroupStartFND"),
    (0x0B8, "ObjectGroupEndFND"),
    (0x0C2, "HashedChunkDescriptor2FND"),
    (0x0C4, "ReadOnlyObjectDeclaration2RefCountFND"),
    (0x0C5, "ReadOnlyObjectDeclaration2LargeRefCountFND"),
    (0x0FF, "ChunkTerminatorFND"),
];

pub const STP_FORMATS: EnumTable = &[
    (0, "8 bytes, uncompressed"),
    (1, "4 bytes, uncompressed"),
    (2, "2 bytes, compressed (×8)"),
    (3, "4 bytes, compressed (×8)"),
];

pub const CB_FORMATS: EnumTable = &[
    (0, "4 bytes, uncompressed"),
    (1, "8 bytes, uncompressed"),
    (2, "1 byte, compressed (×8)"),
    (3, "2 bytes, compressed (×8)"),
];

pub const BASE_TYPES: EnumTable = &[
    (0, "no reference"),
    (1, "reference to data"),
    (2, "reference to a file node list"),
];

pub const ROOT_ROLES: EnumTable = &[
    (1, "default content"),
    (2, "metadata"),
    (4, "version metadata"),
];

pub const JCIDS: EnumTable = &[
    (0x0002_0001, "jcidPersistablePropertyContainerForTOC"),
    (
        0x0012_0001,
        "jcidReadOnlyPersistablePropertyContainerForAuthor",
    ),
    (0x0006_0007, "jcidSectionNode"),
    (0x0006_0008, "jcidPageSeriesNode"),
    (0x0006_000B, "jcidPageNode"),
    (0x0006_000C, "jcidOutlineNode"),
    (0x0006_000D, "jcidOutlineElementNode"),
    (0x0006_000E, "jcidRichTextOENode"),
    (0x0006_0011, "jcidImageNode"),
    (0x0006_0012, "jcidNumberListNode"),
    (0x0006_0019, "jcidOutlineGroup"),
    (0x0006_0022, "jcidTableNode"),
    (0x0006_0023, "jcidTableRowNode"),
    (0x0006_0024, "jcidTableCellNode"),
    (0x0006_002C, "jcidTitleNode"),
    (0x0002_0030, "jcidPageMetaData"),
    (0x0002_0031, "jcidSectionMetaData"),
    (0x0006_0035, "jcidEmbeddedFileNode"),
    (0x0006_0037, "jcidPageManifestNode"),
    (0x0002_0038, "jcidConflictPageMetaData"),
    (0x0006_003C, "jcidVersionHistoryContent"),
    (0x0006_003D, "jcidVersionProxy"),
    (0x0012_0043, "jcidNoteTagSharedDefinitionContainer"),
    (0x0002_0044, "jcidRevisionMetaData"),
    (0x0002_0046, "jcidVersionHistoryMetaData"),
    (0x0012_004D, "jcidParagraphStyleObject"),
];

pub const JCID_RICH_TEXT: u32 = 0x0006_000E;
pub const JCID_IMAGE: u32 = 0x0006_0011;
pub const JCID_TITLE: u32 = 0x0006_002C;
pub const JCID_EMBEDDED_FILE: u32 = 0x0006_0035;

/// JCID flag bits above the 16-bit index.
pub const JCID_IS_BINARY: u32 = 1 << 16;
pub const JCID_IS_PROPERTY_SET: u32 = 1 << 17;
pub const JCID_IS_GRAPH_NODE: u32 = 1 << 18;
pub const JCID_IS_FILE_DATA: u32 = 1 << 19;
pub const JCID_IS_READ_ONLY: u32 = 1 << 20;

pub const PROPERTY_TYPES: EnumTable = &[
    (0x01, "NoData"),
    (0x02, "Bool"),
    (0x03, "OneByteOfData"),
    (0x04, "TwoBytesOfData"),
    (0x05, "FourBytesOfData"),
    (0x06, "EightBytesOfData"),
    (0x07, "FourBytesOfLengthFollowedByData"),
    (0x08, "ObjectID"),
    (0x09, "ArrayOfObjectIDs"),
    (0x0A, "ObjectSpaceID"),
    (0x0B, "ArrayOfObjectSpaceIDs"),
    (0x0C, "ContextID"),
    (0x0D, "ArrayOfContextIDs"),
    (0x10, "ArrayOfPropertyValues"),
    (0x11, "PropertyValue"),
];

/// How a property's data is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Integer (or opaque bytes) as stored.
    Plain,
    /// UTF-16LE text.
    Utf16,
    /// Text in the section's ANSI code page (shown as Windows-1252).
    Ansi,
    /// A GUID.
    Guid,
    /// Seconds since 1980-01-01 UTC.
    Time32,
    /// Windows FILETIME.
    FileTime,
    /// IEEE single (half-inch units for layout properties).
    Float,
    /// A COLORREF (0x00BBGGRR) or `0xFFFFFFFF` for automatic.
    Color,
}

pub const RICH_EDIT_TEXT_UNICODE: u32 = 0x1C00_1C22;
pub const TEXT_EXTENDED_ASCII: u32 = 0x1C00_3498;
pub const CACHED_TITLE_STRING: u32 = 0x1C00_1CF3;
pub const CACHED_TITLE_STRING_FROM_PAGE: u32 = 0x1C00_1D3C;
pub const PICTURE_CONTAINER: u32 = 0x2000_1C3F;
pub const EMBEDDED_FILE_CONTAINER: u32 = 0x2000_1D9B;
pub const EMBEDDED_FILE_NAME: u32 = 0x1C00_1D9C;
pub const SOURCE_FILEPATH: u32 = 0x1C00_1D9D;
pub const IMAGE_FILENAME: u32 = 0x1C00_1DD7;
pub const IMAGE_ALT_TEXT: u32 = 0x1C00_1E58;
pub const CHILD_GRAPH_SPACE_ELEMENT_NODES: u32 = 0x2C00_1D63;
pub const WEB_PICTURE_CONTAINER: u32 = 0x2000_34C8;
pub const PAGE_LEVEL: u32 = 0x1400_1DFF;

/// Object references that are not part of the content tree (styles,
/// authors, tag definitions, formatting runs, file data).
pub const NOT_CHILDREN: &[u32] = &[
    PICTURE_CONTAINER,
    EMBEDDED_FILE_CONTAINER,
    WEB_PICTURE_CONTAINER,
    0x2000_342C, // ParagraphStyle
    0x2000_1D78, // AuthorOriginal
    0x2000_1D79, // AuthorMostRecent
    0x2000_3488, // NoteTagDefinitionOid
    0x2400_1E13, // TextRunFormatting
    0x2400_3458, // TextRunDataObject
    0x2400_3442, // MetaDataObjectsAboveGraphSpace
    0x2400_1C26, // ListNodes
];

/// Timestamp properties shown on a page.
pub const PAGE_TIMES: &[u32] = &[0x1800_1C65, 0x1400_1D09, 0x1400_1D7A, 0x1800_1D77];

pub const PROPERTIES: &[(u32, &str, Kind)] = &[
    (0x0800_1C00, "LayoutTightLayout", Kind::Plain),
    (0x1400_1C01, "PageWidth", Kind::Float),
    (0x1400_1C02, "PageHeight", Kind::Float),
    (0x0C00_1C03, "OutlineElementChildLevel", Kind::Plain),
    (0x0800_1C04, "Bold", Kind::Plain),
    (0x0800_1C05, "Italic", Kind::Plain),
    (0x0800_1C06, "Underline", Kind::Plain),
    (0x0800_1C07, "Strikethrough", Kind::Plain),
    (0x0800_1C08, "Superscript", Kind::Plain),
    (0x0800_1C09, "Subscript", Kind::Plain),
    (0x1C00_1C0A, "Font", Kind::Utf16),
    (0x1000_1C0B, "FontSize", Kind::Plain),
    (0x1400_1C0C, "FontColor", Kind::Color),
    (0x1400_1C0D, "Highlight", Kind::Color),
    (0x1C00_1C12, "RgOutlineIndentDistance", Kind::Plain),
    (0x0C00_1C13, "BodyTextAlignment", Kind::Plain),
    (0x1400_1C14, "OffsetFromParentHoriz", Kind::Float),
    (0x1400_1C15, "OffsetFromParentVert", Kind::Float),
    (0x1C00_1C1A, "NumberListFormat", Kind::Utf16),
    (0x1400_1C1B, "LayoutMaxWidth", Kind::Float),
    (0x1400_1C1C, "LayoutMaxHeight", Kind::Float),
    (0x2400_1C1F, "ContentChildNodes", Kind::Plain),
    (0x2400_1C20, "ElementChildNodes", Kind::Plain),
    (0x0800_1E1E, "EnableHistory", Kind::Plain),
    (RICH_EDIT_TEXT_UNICODE, "RichEditTextUnicode", Kind::Utf16),
    (0x2400_1C26, "ListNodes", Kind::Plain),
    (0x1C00_1C30, "NotebookManagementEntityGuid", Kind::Guid),
    (0x0800_1C34, "OutlineElementRTL", Kind::Plain),
    (0x1400_1C3B, "LanguageID", Kind::Plain),
    (0x1400_1C3E, "LayoutAlignmentInParent", Kind::Plain),
    (PICTURE_CONTAINER, "PictureContainer", Kind::Plain),
    (0x1400_1C4C, "PageMarginTop", Kind::Float),
    (0x1400_1C4D, "PageMarginBottom", Kind::Float),
    (0x1400_1C4E, "PageMarginLeft", Kind::Float),
    (0x1400_1C4F, "PageMarginRight", Kind::Float),
    (0x1C00_1C52, "ListFont", Kind::Utf16),
    (0x1800_1C65, "TopologyCreationTimeStamp", Kind::FileTime),
    (0x1400_1C84, "LayoutAlignmentSelf", Kind::Plain),
    (0x0800_1C87, "IsTitleTime", Kind::Plain),
    (0x0800_1C88, "IsBoilerText", Kind::Plain),
    (0x1400_1C8B, "PageSize", Kind::Plain),
    (0x0800_1C8E, "PortraitPage", Kind::Plain),
    (0x0800_1C91, "EnforceOutlineStructure", Kind::Plain),
    (0x0800_1C92, "EditRootRTL", Kind::Plain),
    (0x0800_1CB2, "CannotBeSelected", Kind::Plain),
    (0x0800_1CB4, "IsTitleText", Kind::Plain),
    (0x0800_1CB5, "IsTitleDate", Kind::Plain),
    (0x1400_1CB7, "ListRestart", Kind::Plain),
    (0x0800_1CBD, "IsLayoutSizeSetByUser", Kind::Plain),
    (0x1400_1CCB, "ListSpacingMu", Kind::Float),
    (0x1400_1CDB, "LayoutOutlineReservedWidth", Kind::Float),
    (0x0800_1CDC, "LayoutResolveChildCollisions", Kind::Plain),
    (0x0800_1CDE, "IsReadOnly", Kind::Plain),
    (0x1400_1CEC, "LayoutMinimumOutlineWidth", Kind::Float),
    (0x1400_1CF1, "LayoutCollisionPriority", Kind::Plain),
    (CACHED_TITLE_STRING, "CachedTitleString", Kind::Utf16),
    (0x0800_1CF9, "DescendantsCannotBeMoved", Kind::Plain),
    (0x1000_1CFE, "RichEditTextLangID", Kind::Plain),
    (0x0800_1CFF, "LayoutTightAlignment", Kind::Plain),
    (0x0C00_1D01, "Charset", Kind::Plain),
    (0x1400_1D09, "CreationTimeStamp", Kind::Time32),
    (0x0800_1D0C, "Deletable", Kind::Plain),
    (0x1000_1D0E, "ListMSAAIndex", Kind::Plain),
    (0x1400_1D0F, "PageMarginOriginX", Kind::Float),
    (0x1400_1D10, "PageMarginOriginY", Kind::Float),
    (0x0800_1D13, "IsBackground", Kind::Plain),
    (0x1400_1D24, "IRecordMedia", Kind::Plain),
    (
        CACHED_TITLE_STRING_FROM_PAGE,
        "CachedTitleStringFromPage",
        Kind::Utf16,
    ),
    (0x1400_1D57, "RowCount", Kind::Plain),
    (0x1400_1D58, "ColumnCount", Kind::Plain),
    (0x0800_1D5E, "TableBordersVisible", Kind::Plain),
    (0x2400_1D5F, "StructureElementChildNodes", Kind::Plain),
    (
        CHILD_GRAPH_SPACE_ELEMENT_NODES,
        "ChildGraphSpaceElementNodes",
        Kind::Plain,
    ),
    (0x1C00_1D66, "TableColumnWidths", Kind::Plain),
    (0x1C00_1D75, "Author", Kind::Utf16),
    (0x1800_1D77, "LastModifiedTimeStamp", Kind::FileTime),
    (0x2000_1D78, "AuthorOriginal", Kind::Plain),
    (0x2000_1D79, "AuthorMostRecent", Kind::Plain),
    (0x1400_1D7A, "LastModifiedTime", Kind::Time32),
    (0x0800_1D7C, "IsConflictPage", Kind::Plain),
    (0x1C00_1D7D, "TableColumnsLocked", Kind::Plain),
    (0x1400_1D82, "SchemaRevisionInOrderToRead", Kind::Plain),
    (0x0800_1D96, "IsConflictObjectForRender", Kind::Plain),
    (
        EMBEDDED_FILE_CONTAINER,
        "EmbeddedFileContainer",
        Kind::Plain,
    ),
    (EMBEDDED_FILE_NAME, "EmbeddedFileName", Kind::Utf16),
    (SOURCE_FILEPATH, "SourceFilepath", Kind::Utf16),
    (0x1C00_1D9E, "ConflictingUserName", Kind::Utf16),
    (IMAGE_FILENAME, "ImageFilename", Kind::Utf16),
    (0x0800_1DDB, "IsConflictObjectForSelection", Kind::Plain),
    (0x1C00_1DE9, "IsDeletedGraphSpaceContent", Kind::Plain),
    (PAGE_LEVEL, "PageLevel", Kind::Plain),
    (0x1C00_1E12, "TextRunIndex", Kind::Plain),
    (0x2400_1E13, "TextRunFormatting", Kind::Plain),
    (0x0800_1E14, "Hyperlink", Kind::Plain),
    (0x0C00_1E15, "UnderlineType", Kind::Plain),
    (0x0800_1E16, "Hidden", Kind::Plain),
    (0x0800_1E19, "HyperlinkProtected", Kind::Plain),
    (0x1C00_1E20, "WzHyperlinkUrl", Kind::Utf16),
    (0x0800_1E22, "TextRunIsEmbeddedObject", Kind::Plain),
    (0x1400_1E26, "CellShadingColor", Kind::Color),
    (IMAGE_ALT_TEXT, "ImageAltText", Kind::Utf16),
    (0x0800_3401, "MathFormatting", Kind::Plain),
    (0x2000_342C, "ParagraphStyle", Kind::Plain),
    (0x1400_342E, "ParagraphSpaceBefore", Kind::Float),
    (0x1400_342F, "ParagraphSpaceAfter", Kind::Float),
    (0x1400_3430, "ParagraphLineSpacingExact", Kind::Float),
    (0x2400_3442, "MetaDataObjectsAboveGraphSpace", Kind::Plain),
    (0x2400_3458, "TextRunDataObject", Kind::Plain),
    (0x4000_3499, "TextRunData", Kind::Plain),
    (0x1C00_345A, "ParagraphStyleId", Kind::Utf16),
    (0x0800_3462, "HasVersionPages", Kind::Plain),
    (0x1000_3463, "ActionItemType", Kind::Plain),
    (0x1000_3464, "NoteTagShape", Kind::Plain),
    (0x1400_3465, "NoteTagHighlightColor", Kind::Color),
    (0x1400_3466, "NoteTagTextColor", Kind::Color),
    (0x1400_3467, "NoteTagPropertyStatus", Kind::Plain),
    (0x1C00_3468, "NoteTagLabel", Kind::Utf16),
    (0x1400_346B, "TaskTagDueDate", Kind::Time32),
    (0x1400_346E, "NoteTagCreated", Kind::Time32),
    (0x1400_346F, "NoteTagCompleted", Kind::Time32),
    (0x1000_3470, "ActionItemStatus", Kind::Plain),
    (0x0C00_3473, "ActionItemSchemaVersion", Kind::Plain),
    (0x0800_3476, "ReadingOrderRTL", Kind::Plain),
    (0x0C00_3477, "ParagraphAlignment", Kind::Plain),
    (
        0x3400_347B,
        "VersionHistoryGraphSpaceContextNodes",
        Kind::Plain,
    ),
    (0x1400_3480, "DisplayedPageNumber", Kind::Plain),
    (0x1C00_348A, "NextStyle", Kind::Utf16),
    (0x2000_3488, "NoteTagDefinitionOid", Kind::Plain),
    (0x0400_3489, "NoteTagStates", Kind::Plain),
    (TEXT_EXTENDED_ASCII, "TextExtendedAscii", Kind::Ansi),
    (0x1C00_349B, "SectionDisplayName", Kind::Utf16),
    (WEB_PICTURE_CONTAINER, "WebPictureContainer14", Kind::Plain),
    (0x1400_34CB, "ImageUploadState", Kind::Plain),
    (0x1400_34CD, "PictureWidth", Kind::Float),
    (0x1400_34CE, "PictureHeight", Kind::Float),
];

/// Name and display kind of a property (`raw` with or without the Boolean
/// value bit).
pub fn property(raw: u32) -> Option<(&'static str, Kind)> {
    let key = raw & 0x7FFF_FFFF;
    PROPERTIES
        .iter()
        .find(|(id, _, _)| *id == key)
        .map(|(_, name, kind)| (*name, *kind))
}
