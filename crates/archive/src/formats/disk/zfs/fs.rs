//! A pool's datasets and their contents: the DSL directory tree in the
//! meta object set (filesystems, volumes and snapshots, as `zfs list -t
//! all` names them), ZPL directories and files with their system
//! attributes, and volumes' data.

use std::collections::HashMap;
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::formats::disk::{PieceList, content_node, size};
use crate::formats::util::arcutil::unix_mode;
use crate::formats::util::fmt::plural;
use crate::formats::util::val;
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Time, Value, flag};

use super::dmu::{
    Bp, Dnode, OS_ZPL, OS_ZVOL, Objset, PoolRef, USED_BYTES, ZapValue, bits, lookup, word, word16,
    word32, zap,
};

/// Dataset and directory nesting followed.
const MAX_DEPTH: usize = 64;

/// One dataset: its full name, its object in the MOS and its kind.
struct Dataset {
    name: String,
    obj: u64,
    snapshot: bool,
}

/// `dsl_dir_phys_t` and `dsl_dataset_phys_t` fields used here.
const DD_HEAD_DATASET: usize = 8;
const DD_CHILD_DIR_ZAP: usize = 32;
const DS_SNAPNAMES_ZAP: usize = 32;
const DS_CREATION_TIME: usize = 48;
const DS_REFERENCED: usize = 72;
const DS_BP: usize = 128;

/// Lists the pool's datasets, from the meta object set the uberblock's
/// root block pointer leads to.
pub(super) async fn datasets(cx: Cx, (pool, root, name): (PoolRef, Bp, String)) -> Result<()> {
    let mos = Objset::read(&cx, &pool, &root).await?;
    let objdir = mos.dnode(&cx, &pool, 1).await?;
    let dir = zap(&cx, &pool, &objdir).await?;
    let root_dir = lookup(&dir, "root_dataset")
        .ok_or_else(|| Diagnostic::malformed("no root_dataset in the object directory"))?;
    // Depth first, children by name, as `zfs list` orders them.
    let mut found = Vec::new();
    let mut stack = vec![(name, root_dir, 0usize)];
    while let Some((name, dd_obj, depth)) = stack.pop() {
        cx.checkpoint().await;
        let dd = mos.dnode(&cx, &pool, dd_obj).await?;
        let head = word(&dd.bonus, DD_HEAD_DATASET, dd.le).unwrap_or(0);
        if head != 0 {
            found.push(Dataset {
                name: name.clone(),
                obj: head,
                snapshot: false,
            });
            let ds = mos.dnode(&cx, &pool, head).await?;
            let snaps = word(&ds.bonus, DS_SNAPNAMES_ZAP, ds.le).unwrap_or(0);
            if snaps != 0 {
                let mut list = zap(&cx, &pool, &mos.dnode(&cx, &pool, snaps).await?).await?;
                list.sort_by(|a, b| a.0.cmp(&b.0));
                for (snap, v) in list {
                    found.push(Dataset {
                        name: format!("{name}@{snap}"),
                        obj: v.first().unwrap_or(0),
                        snapshot: true,
                    });
                }
            }
        }
        let children = word(&dd.bonus, DD_CHILD_DIR_ZAP, dd.le).unwrap_or(0);
        if children == 0 || depth >= MAX_DEPTH {
            continue;
        }
        let mut list = zap(&cx, &pool, &mos.dnode(&cx, &pool, children).await?).await?;
        // `$MOS`, `$FREE` and `$ORIGIN` are the pool's own bookkeeping.
        list.retain(|(k, _)| !k.starts_with('$'));
        list.sort_by(|a, b| b.0.cmp(&a.0));
        for (child, v) in list {
            stack.push((
                format!("{name}/{child}"),
                v.first().unwrap_or(0),
                depth.saturating_add(1),
            ));
        }
    }
    cx.set_count(Count::Exact(to_u64(found.len())));
    for d in found {
        cx.push(dataset_node(&cx, &pool, &mos, d).await).await;
    }
    Ok(())
}

async fn dataset_node(cx: &Cx, pool: &PoolRef, mos: &Objset, d: Dataset) -> Node {
    let node = Node::new(d.name);
    let ds = match mos.dnode(cx, pool, d.obj).await {
        Ok(ds) => ds,
        Err(e) => return node.diag(e),
    };
    let node = node.span(ds.bonus_span);
    let Some(bp) = Bp::parse(
        &ds.bonus,
        DS_BP,
        ds.le,
        ds.bonus_span.sub(to_u64(DS_BP), 128),
    ) else {
        return node.diag(Diagnostic::malformed("short dataset"));
    };
    let referenced = word(&ds.bonus, DS_REFERENCED, ds.le).unwrap_or(0);
    let created = word(&ds.bonus, DS_CREATION_TIME, ds.le).unwrap_or(0);
    let os = match Objset::read(cx, pool, &bp).await {
        Ok(os) => os,
        Err(e) => return node.diag(e),
    };
    let kind = match (os.ty, d.snapshot) {
        (_, true) => "snapshot",
        (OS_ZPL, _) => "filesystem",
        (OS_ZVOL, _) => "volume",
        _ => "dataset",
    };
    let node = node.summary(format!(
        "{kind}, {} referenced, created {}",
        size(referenced),
        Time::utc(i64::try_from(created).unwrap_or(0))
    ));
    match os.ty {
        OS_ZPL => node.lazy(filesystem, (pool.clone(), Arc::new(os))),
        OS_ZVOL => node.lazy(volume, (pool.clone(), Arc::new(os))),
        _ => node,
    }
}

/// A volume: object 1 holds its data, object 2 (a ZAP) its size.
async fn volume(cx: Cx, (pool, os): (PoolRef, Arc<Objset>)) -> Result<()> {
    let props = zap(&cx, &pool, &os.dnode(&cx, &pool, 2).await?).await?;
    let len = lookup(&props, "size").unwrap_or(0);
    let data = os.dnode(&cx, &pool, 1).await?;
    let content = object_content(&cx, &pool, &data, len).await?;
    cx.annotate(size(len));
    cx.emit(content_node(&pool.input, content));
    Ok(())
}

/// A ZPL file system's state: its object set and system attribute layout.
struct Zpl {
    pool: PoolRef,
    os: Objset,
    sa: Option<Sa>,
}

type ZplRef = Arc<Zpl>;

/// System attributes (`sa.c`): names and lengths by number, and layouts
/// (lists of attribute numbers) by number.
struct Sa {
    attrs: HashMap<u64, (String, u64)>,
    layouts: HashMap<u64, Vec<u64>>,
}

const SA_MAGIC: u32 = 0x2f_505a;
/// Bonus types: system attributes, and the older fixed `znode_phys_t`.
const BONUS_SA: u8 = 44;
const BONUS_ZNODE: u8 = 17;

impl Sa {
    async fn read(cx: &Cx, zpl: &Objset, pool: &PoolRef, master: u64) -> Result<Sa> {
        let entries = zap(cx, pool, &zpl.dnode(cx, pool, master).await?).await?;
        let mut attrs = HashMap::new();
        if let Some(reg) = lookup(&entries, "REGISTRY") {
            for (name, v) in zap(cx, pool, &zpl.dnode(cx, pool, reg).await?).await? {
                let v = v.first().unwrap_or(0);
                attrs.insert(bits(v, 0, 16), (name, bits(v, 24, 16)));
            }
        }
        let mut layouts = HashMap::new();
        if let Some(lay) = lookup(&entries, "LAYOUTS") {
            for (name, v) in zap(cx, pool, &zpl.dnode(cx, pool, lay).await?).await? {
                if let Ok(n) = name.parse::<u64>() {
                    layouts.insert(n, v.ints);
                }
            }
        }
        Ok(Sa { attrs, layouts })
    }

    /// The attributes in an SA buffer (a bonus or spill block): name, span
    /// and bytes, in layout order.
    fn parse(&self, buf: &[u8], at: Span, le: bool, out: &mut Vec<Attr>) -> Option<()> {
        if word32(buf, 0, le)? != SA_MAGIC {
            return None;
        }
        let info = word16(buf, 4, le)?;
        let layout = self.layouts.get(&u64::from(info & 0x3ff))?;
        let mut pos = usize::from((info >> 10) & 0x3f).saturating_mul(8);
        // Variable-length attributes' sizes follow the layout word.
        let mut var = 6usize;
        for &num in layout {
            let (name, len) = self.attrs.get(&num)?;
            let len = if *len == 0 {
                let l = word16(buf, var, le)?;
                var = var.saturating_add(2);
                usize::from(l)
            } else {
                to_usize(*len)
            };
            let data = buf.get(pos..pos.checked_add(len)?)?.to_vec();
            out.push(Attr {
                name: name.clone(),
                span: at.sub(to_u64(pos), to_u64(len)),
                data,
            });
            pos = pos.checked_add(len.checked_next_multiple_of(8)?)?;
        }
        Some(())
    }
}

/// One system attribute of a file.
#[derive(Clone)]
struct Attr {
    name: String,
    span: Span,
    data: Vec<u8>,
}

/// What a file's attributes say, as far as listing it goes.
#[derive(Clone, Default)]
struct Inode {
    attrs: Vec<Attr>,
    mode: u64,
    size: u64,
    symlink: Option<Vec<u8>>,
}

impl Zpl {
    /// Object `obj`'s attributes: system attributes (bonus, then spill
    /// block) or an old-style `znode_phys_t`.
    async fn inode(&self, cx: &Cx, dn: &Dnode) -> Result<Inode> {
        let le = dn.le;
        let mut attrs = Vec::new();
        match (dn.bonustype, &self.sa) {
            (BONUS_SA, Some(sa)) => {
                sa.parse(&dn.bonus, dn.bonus_span, le, &mut attrs)
                    .ok_or_else(|| Diagnostic::malformed("undecodable system attributes"))?;
                if let Some(spill) = dn.spill {
                    let (span, data) = self.pool.meta(cx, &spill).await?;
                    sa.parse(&data, span, spill.le(), &mut attrs);
                }
            }
            (BONUS_ZNODE, _) => {
                for (name, at, len) in ZNODE {
                    if let Some(data) = dn.bonus.get(*at..at.saturating_add(*len)) {
                        attrs.push(Attr {
                            name: (*name).to_owned(),
                            span: dn.bonus_span.sub(to_u64(*at), to_u64(*len)),
                            data: data.to_vec(),
                        });
                    }
                }
            }
            (other, _) => {
                return Err(Diagnostic::unsupported(format!("bonus type {other}")));
            }
        }
        let num = |name: &str| {
            attrs
                .iter()
                .find(|a| a.name == name)
                .and_then(|a| word(&a.data, 0, le))
        };
        let mode = num("ZPL_MODE").unwrap_or(0);
        let size = num("ZPL_SIZE").unwrap_or(0);
        let mut symlink = attrs
            .iter()
            .find(|a| a.name == "ZPL_SYMLINK")
            .map(|a| a.data.clone());
        if symlink.is_none() && mode & 0o170_000 == 0o120_000 {
            // Old-style: after the znode in the bonus buffer if it fits,
            // otherwise in the object's data.
            symlink = Some(
                match dn.bonus.get(264..264usize.saturating_add(to_usize(size))) {
                    Some(t)
                        if dn.bonustype == BONUS_ZNODE
                            && dn.maxblkid == 0
                            && dn.bps.iter().all(Bp::is_hole) =>
                    {
                        t.to_vec()
                    }
                    _ => dn.read(cx, &self.pool, 0, size.min(4096)).await?,
                },
            );
        }
        Ok(Inode {
            attrs,
            mode,
            size,
            symlink,
        })
    }
}

/// `znode_phys_t` fields (bonus type 17), as the equivalent system
/// attributes: name, offset, length.
const ZNODE: &[(&str, usize, usize)] = &[
    ("ZPL_ATIME", 0, 16),
    ("ZPL_MTIME", 16, 16),
    ("ZPL_CTIME", 32, 16),
    ("ZPL_CRTIME", 48, 16),
    ("ZPL_GEN", 64, 8),
    ("ZPL_MODE", 72, 8),
    ("ZPL_SIZE", 80, 8),
    ("ZPL_PARENT", 88, 8),
    ("ZPL_LINKS", 96, 8),
    ("ZPL_XATTR", 104, 8),
    ("ZPL_RDEV", 112, 8),
    ("ZPL_FLAGS", 120, 8),
    ("ZPL_UID", 128, 8),
    ("ZPL_GID", 136, 8),
];

/// A ZPL file system: the master node's `ROOT` directory.
async fn filesystem(cx: Cx, (pool, os): (PoolRef, Arc<Objset>)) -> Result<()> {
    let master = zap(&cx, &pool, &os.dnode(&cx, &pool, 1).await?).await?;
    let root = lookup(&master, "ROOT")
        .ok_or_else(|| Diagnostic::malformed("no ROOT in the master node"))?;
    let sa = match lookup(&master, "SA_ATTRS") {
        Some(obj) => Some(Sa::read(&cx, &os, &pool, obj).await?),
        None => None,
    };
    let zpl = Arc::new(Zpl {
        pool,
        os: (*os).clone(),
        sa,
    });
    directory(
        cx,
        DirState {
            zpl,
            obj: root,
            path: Path::new(),
        },
    )
    .await
}

#[derive(Clone)]
struct DirState {
    zpl: ZplRef,
    obj: u64,
    path: Path,
}

/// `DT_*` types, in a directory entry's top four bits.
const DT_TYPES: EnumTable = &[
    (1, "FIFO"),
    (2, "character device"),
    (4, "directory"),
    (6, "block device"),
    (8, "file"),
    (10, "symbolic link"),
    (12, "socket"),
];

fn kind(mode: u64) -> &'static str {
    match mode & 0o170_000 {
        0o040_000 => "directory",
        0o100_000 => "file",
        0o120_000 => "symbolic link",
        0o010_000 => "FIFO",
        0o020_000 => "character device",
        0o060_000 => "block device",
        0o140_000 => "socket",
        _ => "object",
    }
}

/// Lists a directory: its attributes, then its entries by name.
async fn directory(cx: Cx, st: DirState) -> Result<()> {
    let zpl = st.zpl.clone();
    let pool = &zpl.pool;
    let dn = zpl.os.dnode(&cx, pool, st.obj).await?;
    cx.emit(attributes_node(&cx, &zpl, &dn).await);
    let mut entries = zap(&cx, pool, &dn).await?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    cx.set_count(Count::Exact(to_u64(entries.len()).saturating_add(1)));
    for (name, v) in entries {
        cx.push(entry_node(&cx, &st, name, &v).await).await;
    }
    Ok(())
}

async fn entry_node(cx: &Cx, st: &DirState, name: String, v: &ZapValue) -> Node {
    let raw = v.first().unwrap_or(0);
    let obj = bits(raw, 0, 48);
    let dt = bits(raw, 60, 4);
    let node = Node::new(name);
    let zpl = &st.zpl;
    let dn = match zpl.os.dnode(cx, &zpl.pool, obj).await {
        Ok(dn) => dn,
        Err(e) => return node.summary(format!("object {obj}")).diag(e),
    };
    let node = node.span(dn.span);
    let inode = match zpl.inode(cx, &dn).await {
        Ok(i) => i,
        Err(e) => {
            let what = crate::value::lookup(DT_TYPES, dt).unwrap_or("object");
            return node.summary(format!("{what}, object {obj}")).diag(e);
        }
    };
    let what = kind(inode.mode);
    if inode.mode & 0o170_000 == 0o040_000 {
        return match st.path.enter(obj, MAX_DEPTH) {
            Ok(path) => node.summary(format!("{what}, object {obj}")).lazy(
                crate::expander!(self::directory: DirState),
                DirState {
                    zpl: zpl.clone(),
                    obj,
                    path,
                },
            ),
            Err(d) => node.diag(d),
        };
    }
    let summary = match &inode.symlink {
        Some(t) => format!("{what} → {}", String::from_utf8_lossy(t)),
        None => format!("{what}, {}", size(inode.size)),
    };
    node.summary(summary)
        .lazy(file_view, (zpl.clone(), Arc::new(dn), Arc::new(inode)))
}

/// A file: its dnode, attributes and content.
async fn file_view(cx: Cx, (zpl, dn, inode): (ZplRef, Arc<Dnode>, Arc<Inode>)) -> Result<()> {
    cx.emit(dnode_node(&dn));
    cx.emit(attrs_node(&inode, dn.le));
    if let Some(target) = &inode.symlink {
        cx.emit(
            Node::new("Target").value(Value::Text(String::from_utf8_lossy(target).into_owned())),
        );
        return Ok(());
    }
    if inode.mode & 0o170_000 == 0o100_000 {
        let content = object_content(&cx, &zpl.pool, &dn, inode.size).await?;
        cx.emit(content_node(&zpl.pool.input, content));
    }
    Ok(())
}

async fn attributes_node(cx: &Cx, zpl: &Zpl, dn: &Dnode) -> Node {
    match zpl.inode(cx, dn).await {
        Ok(inode) => attrs_node(&inode, dn.le),
        Err(e) => Node::new("Attributes").span(dn.bonus_span).diag(e),
    }
}

/// A dnode's header, summarised.
fn dnode_node(dn: &Dnode) -> Node {
    let blocks = dn.maxblkid.saturating_add(1);
    let used = if dn.flags & USED_BYTES != 0 {
        dn.used
    } else {
        dn.used.saturating_mul(512)
    };
    Node::new(format!("Dnode {}", dn.obj))
        .span(dn.span)
        .summary(format!(
            "{} of {}, {} level{}, {} on disk",
            plural(to_usize(blocks), "block"),
            size(dn.datablksz),
            dn.nlevels,
            if dn.nlevels == 1 { "" } else { "s" },
            size(used)
        ))
}

fn attrs_node(inode: &Inode, le: bool) -> Node {
    let nodes: Vec<Node> = inode.attrs.iter().map(|a| attr_node(a, le)).collect();
    let node = Node::new("Attributes").summary(format!(
        "{}, {}",
        unix_mode(inode.mode),
        plural(nodes.len(), "attribute")
    ));
    match (inode.attrs.first(), inode.attrs.last()) {
        (Some(first), Some(last)) if first.span.source == last.span.source => node
            .span(Span::new(
                first.span.source,
                first.span.offset,
                last.span.end().saturating_sub(first.span.offset),
            ))
            .lazy(crate::formats::util::arcutil::push_nodes, Arc::new(nodes)),
        _ => node.lazy(crate::formats::util::arcutil::push_nodes, Arc::new(nodes)),
    }
}

/// `zfs_znode.h` file flags (`ZFS_*`).
const FILE_FLAGS: FlagTable = &[
    flag(0x1, "XATTR"),
    flag(0x2, "INHERIT_ACE"),
    flag(0x4, "ACL_TRIVIAL"),
    flag(0x8, "ACL_OBJ_ACE"),
    flag(0x10, "ACL_PROTECTED"),
    flag(0x20, "ACL_DEFAULTED"),
    flag(0x40, "ACL_AUTO_INHERIT"),
    flag(0x80, "BONUS_SCANSTAMP"),
    flag(0x100, "NO_EXECS_DENIED"),
    flag(0x1_0000_0000, "READONLY"),
    flag(0x2_0000_0000, "HIDDEN"),
    flag(0x4_0000_0000, "SYSTEM"),
    flag(0x8_0000_0000, "ARCHIVE"),
    flag(0x10_0000_0000, "IMMUTABLE"),
    flag(0x20_0000_0000, "NOUNLINK"),
    flag(0x40_0000_0000, "APPENDONLY"),
    flag(0x80_0000_0000, "NODUMP"),
    flag(0x100_0000_0000, "OPAQUE"),
    flag(0x200_0000_0000, "AV_QUARANTINED"),
    flag(0x400_0000_0000, "AV_MODIFIED"),
    flag(0x800_0000_0000, "REPARSE"),
    flag(0x1000_0000_0000, "OFFLINE"),
    flag(0x2000_0000_0000, "SPARSE"),
    flag(0x4000_0000_0000, "PROJINHERIT"),
    flag(0x8000_0000_0000, "PROJID"),
];

/// ZPL system attributes' titles (`zfs_sa.h`).
const TITLES: &[(&str, &str)] = &[
    ("ZPL_ATIME", "Accessed"),
    ("ZPL_MTIME", "Modified"),
    ("ZPL_CTIME", "Changed"),
    ("ZPL_CRTIME", "Created"),
    ("ZPL_GEN", "Generation (txg)"),
    ("ZPL_MODE", "Mode"),
    ("ZPL_SIZE", "Size"),
    ("ZPL_PARENT", "Parent directory (object)"),
    ("ZPL_LINKS", "Links"),
    ("ZPL_XATTR", "Extended attribute directory (object)"),
    ("ZPL_RDEV", "Device"),
    ("ZPL_FLAGS", "Flags"),
    ("ZPL_UID", "Owner (UID)"),
    ("ZPL_GID", "Group (GID)"),
    ("ZPL_PAD", "Padding"),
    ("ZPL_ZNODE_ACL", "ACL (old style)"),
    ("ZPL_DACL_COUNT", "ACL entries"),
    ("ZPL_SYMLINK", "Symbolic link target"),
    ("ZPL_SCANSTAMP", "Virus scan stamp"),
    ("ZPL_DACL_ACES", "ACL"),
    ("ZPL_DXATTR", "Extended attributes"),
    ("ZPL_PROJID", "Project ID"),
];

/// An attribute's value, by what its name says it holds.
fn attr_node(a: &Attr, le: bool) -> Node {
    let title = TITLES
        .iter()
        .find(|(k, _)| *k == a.name)
        .map_or(a.name.as_str(), |(_, t)| t);
    let node = Node::new(title.to_owned())
        .span(a.span)
        .desc(a.name.clone());
    let n = word(&a.data, 0, le).filter(|_| a.data.len() == 8);
    let time = || {
        let secs = i64::try_from(word(&a.data, 0, le)?).ok()?;
        let nanos = u32::try_from(word(&a.data, 8, le)?).ok()?;
        Some(Value::Timestamp(Time::utc(secs).frac(nanos, 9)))
    };
    let (value, node) = match a.name.as_str() {
        "ZPL_ATIME" | "ZPL_MTIME" | "ZPL_CTIME" | "ZPL_CRTIME" => (time(), node),
        "ZPL_MODE" => (
            n.map(|m| val::oct(m, 64)),
            match n {
                Some(m) => node.summary(unix_mode(m)),
                None => node,
            },
        ),
        "ZPL_SIZE" => (n.map(|s| val::size(s, 64)), node),
        "ZPL_FLAGS" => (n.map(|f| val::flagsv(f, 64, FILE_FLAGS)), node),
        "ZPL_SYMLINK" => (
            Some(Value::Text(String::from_utf8_lossy(&a.data).into_owned())),
            node,
        ),
        _ => (n.map(|v| val::uint(v, 64)), node),
    };
    node.value(value.unwrap_or_else(|| Value::Bytes(a.data.clone())))
}

/// An object's data, `len` bytes: its blocks in order (holes as zeros),
/// each decoded on demand.
async fn object_content(cx: &Cx, pool: &PoolRef, dn: &Dnode, len: u64) -> Result<Span> {
    let bs = dn.datablksz.max(512);
    let mut list = PieceList::new(dn.span);
    let mut blkid = 0u64;
    while list.len() < len && blkid <= dn.maxblkid {
        let want = len.saturating_sub(list.len()).min(bs);
        match dn.block_bp(cx, pool, blkid).await? {
            Some(bp) if !bp.is_hole() => {
                let span = pool.block(cx, &bp).await?;
                list.data(span.sub(0, want));
            }
            _ => list.hole(cx, want)?,
        }
        blkid = blkid.saturating_add(1);
        if blkid.is_multiple_of(256) {
            cx.checkpoint().await;
        }
    }
    if list.len() < len {
        list.hole(cx, len.saturating_sub(list.len()))?;
    }
    list.finish(cx, "zfs-object").await
}
