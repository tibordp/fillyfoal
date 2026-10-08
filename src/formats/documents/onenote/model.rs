//! The object model on top of the revision store: object spaces, their
//! revisions (with dependencies and roles), the objects each revision
//! declares, the file data store, and the pages of a section.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::bytes::{to_u64, u64_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::span::Span;

use super::props::{self, ObjectPropSet, PValue};
use super::store::{ExGuid, Fcr, IdTable, NodeList, Store, parse_guid, read_list};
use super::tables::{
    CACHED_TITLE_STRING, CACHED_TITLE_STRING_FROM_PAGE, CHILD_GRAPH_SPACE_ELEMENT_NODES,
    JCID_TITLE, NOT_CHILDREN, PAGE_LEVEL,
};

/// How deep the content walk follows child references.
const MAX_WALK_DEPTH: u32 = 64;

#[derive(Clone, Debug)]
pub struct Object {
    pub oid: ExGuid,
    pub jcid: u32,
    /// The ObjectSpaceObjectPropSet, for objects that have one.
    pub data: Option<Fcr>,
    /// FileDataReference and Extension of a file data object.
    pub file_ref: Option<String>,
    pub extension: Option<String>,
    pub table: Arc<IdTable>,
    /// The declaring file node.
    pub decl: Span,
    pub node_id: u16,
}

#[derive(Clone, Debug, Default)]
pub struct Revision {
    pub rid: ExGuid,
    pub dependent: ExGuid,
    pub role: u32,
    pub context: ExGuid,
    pub decl: Option<Span>,
    pub objects: Vec<Object>,
    pub roots: Vec<(u32, ExGuid)>,
    pub groups: Vec<(ExGuid, Fcr)>,
}

#[derive(Clone, Debug)]
pub enum Event {
    Revision(usize),
    Role {
        rid: ExGuid,
        role: u32,
        context: ExGuid,
    },
}

#[derive(Clone, Debug, Default)]
pub struct Space {
    pub gosid: ExGuid,
    pub manifest: Option<Fcr>,
    pub revision_list: Option<Fcr>,
    pub revisions: Vec<Revision>,
    pub events: Vec<Event>,
    pub encrypted: bool,
}

/// An object in the file data store.
#[derive(Clone, Debug)]
pub struct DataFile {
    pub guid: [u8; 16],
    pub fcr: Fcr,
}

#[derive(Clone, Debug, Default)]
pub struct Model {
    pub root: Option<ExGuid>,
    pub spaces: Vec<Space>,
    pub file_store: Option<Fcr>,
    pub files: Vec<DataFile>,
    pub diags: Vec<Diagnostic>,
}

/// The objects visible in one revision, inherited along its dependencies.
#[derive(Clone, Debug, Default)]
pub struct View {
    /// oid → (revision, object index).
    pub objects: BTreeMap<ExGuid, (usize, usize)>,
    pub roots: BTreeMap<u32, ExGuid>,
}

impl Space {
    /// Revision index by rid (the first declaration wins).
    async fn rids(&self, cx: &Cx) -> BTreeMap<ExGuid, usize> {
        let mut map = BTreeMap::new();
        for (i, r) in self.revisions.iter().enumerate() {
            if i % 1024 == 1023 {
                cx.checkpoint().await;
            }
            map.entry(r.rid).or_insert(i);
        }
        map
    }

    /// The revision currently holding `role` in the default context.
    pub async fn current(&self, cx: &Cx, role: u32) -> Option<usize> {
        let rids = self.rids(cx).await;
        let mut best = None;
        for (n, event) in self.events.iter().enumerate() {
            if n % 1024 == 1023 {
                cx.checkpoint().await;
            }
            match event {
                Event::Revision(i) => {
                    if let Some(r) = self.revisions.get(*i)
                        && r.role == role
                        && r.context.is_nil()
                    {
                        best = Some(*i);
                    }
                }
                Event::Role {
                    rid,
                    role: r,
                    context,
                } => {
                    if *r == role && context.is_nil() {
                        best = rids.get(rid).copied().or(best);
                    }
                }
            }
        }
        best
    }

    /// The objects and roots of revision `index`, layered over the
    /// revisions it depends on.
    pub async fn view(&self, cx: &Cx, index: Option<usize>) -> View {
        let mut view = View::default();
        let rids = self.rids(cx).await;
        let mut chain = Vec::new();
        let mut on_chain = BTreeSet::new();
        let mut next = index;
        while let Some(i) = next {
            if chain.len() % 1024 == 1023 {
                cx.checkpoint().await;
            }
            if !on_chain.insert(i) {
                break;
            }
            chain.push(i);
            next = self.revisions.get(i).and_then(|r| {
                if r.dependent.is_nil() {
                    None
                } else {
                    rids.get(&r.dependent).copied()
                }
            });
        }
        for &i in chain.iter().rev() {
            let Some(r) = self.revisions.get(i) else {
                continue;
            };
            cx.checkpoint().await;
            for (k, o) in r.objects.iter().enumerate() {
                if k % 1024 == 1023 {
                    cx.checkpoint().await;
                }
                view.objects.insert(o.oid, (i, k));
            }
            for (k, (role, oid)) in r.roots.iter().enumerate() {
                if k % 1024 == 1023 {
                    cx.checkpoint().await;
                }
                view.roots.insert(*role, *oid);
            }
        }
        view
    }

    /// The content view (revision role 1).
    pub async fn content(&self, cx: &Cx) -> View {
        let current = self
            .current(cx, 1)
            .await
            .or_else(|| self.revisions.len().checked_sub(1));
        self.view(cx, current).await
    }

    pub fn object(&self, at: (usize, usize)) -> Option<&Object> {
        self.revisions.get(at.0)?.objects.get(at.1)
    }

    /// A root object of the given root role, looked up in the content
    /// revision and then in the revision holding that role.
    pub async fn root(&self, cx: &Cx, role: u32) -> Option<(&Object, View)> {
        let content = self.content(cx).await;
        let found = content.roots.get(&role).copied();
        let (view, oid) = match found {
            Some(oid) => (content, oid),
            None => {
                let v = self.view(cx, self.current(cx, role).await).await;
                let oid = *v.roots.get(&role)?;
                (v, oid)
            }
        };
        let obj = self.object(*view.objects.get(&oid)?)?;
        Some((obj, view))
    }
}

impl Model {
    pub fn space(&self, gosid: &ExGuid) -> Option<usize> {
        self.spaces.iter().position(|s| s.gosid == *gosid)
    }

    /// The file data store object a FileDataReference names.
    pub fn file(&self, reference: &str) -> Option<&DataFile> {
        let guid = parse_guid(reference.strip_prefix("<ifndf>")?)?;
        self.files.iter().find(|f| f.guid == guid)
    }
}

struct Builder<'a> {
    cx: &'a Cx,
    store: &'a Store,
    seen: BTreeSet<u64>,
    diags: Vec<Diagnostic>,
}

impl Builder<'_> {
    async fn list(&mut self, fcr: Option<Fcr>) -> Option<NodeList> {
        let fcr = fcr.filter(|f| !f.is_null())?;
        if !self.seen.insert(fcr.stp) {
            self.diags.push(Diagnostic::malformed(format!(
                "file node list at {:#x} is referenced more than once",
                fcr.stp
            )));
            return None;
        }
        let list = read_list(self.cx, self.store, fcr).await;
        self.diags.extend(list.diags.iter().cloned());
        Some(list)
    }

    fn object(
        &self,
        node: &super::store::FileNode,
        b: &super::store::Body,
        table: &Arc<IdTable>,
    ) -> Option<Object> {
        let oid = b.oid?.resolve(Some(table))?;
        Some(Object {
            oid,
            jcid: b.jcid.unwrap_or(0),
            data: b
                .fcr
                .filter(|f| !f.is_null() && b.has_property_set(node.hdr.id)),
            file_ref: b.file_ref.clone(),
            extension: b.extension.clone(),
            table: table.clone(),
            decl: node.span,
            node_id: node.hdr.id,
        })
    }

    async fn group(&mut self, fcr: Option<Fcr>, rev: &mut Revision) {
        let Some(list) = self.list(fcr).await else {
            return;
        };
        let file = self.store.file;
        let mut table: Arc<IdTable> = Arc::default();
        let mut building = IdTable::new();
        for (n, node) in list.nodes.iter().enumerate() {
            if n % 256 == 255 {
                self.cx.checkpoint().await;
            }
            let Ok(b) = node.body(file, Some(&table)) else {
                continue;
            };
            match node.hdr.id {
                0x021 | 0x022 => building.clear(),
                0x024 => {
                    if let (Some(i), Some(g)) = (b.index, b.guid) {
                        building.insert(i, g);
                    }
                }
                0x028 => table = Arc::new(building.clone()),
                0x0A4 | 0x0A5 | 0x0C4 | 0x0C5 | 0x072 | 0x073 => {
                    if let Some(o) = self.object(node, &b, &table) {
                        rev.objects.push(o);
                    }
                }
                _ => {}
            }
        }
    }

    async fn revisions(&mut self, space: &mut Space) {
        let Some(list) = self.list(space.revision_list).await else {
            return;
        };
        let file = self.store.file;
        let mut cur: Option<Revision> = None;
        let mut table: Arc<IdTable> = Arc::default();
        let mut building = IdTable::new();
        for (n, node) in list.nodes.iter().enumerate() {
            if n % 256 == 255 {
                self.cx.checkpoint().await;
            }
            let Ok(b) = node.body(file, Some(&table)) else {
                continue;
            };
            match node.hdr.id {
                0x01B | 0x01E | 0x01F => {
                    if let Some(r) = cur.take() {
                        space.events.push(Event::Revision(space.revisions.len()));
                        space.revisions.push(r);
                    }
                    cur = Some(Revision {
                        rid: b.rid.unwrap_or_default(),
                        dependent: b.dependent.unwrap_or_default(),
                        role: b.role.unwrap_or(0),
                        context: b.context.unwrap_or_default(),
                        decl: Some(node.span),
                        ..Revision::default()
                    });
                    table = Arc::default();
                    building.clear();
                }
                0x01C => {
                    if let Some(r) = cur.take() {
                        space.events.push(Event::Revision(space.revisions.len()));
                        space.revisions.push(r);
                    }
                }
                0x05C | 0x05D => space.events.push(Event::Role {
                    rid: b.rid.unwrap_or_default(),
                    role: b.role.unwrap_or(0),
                    context: b.context.unwrap_or_default(),
                }),
                0x07C => space.encrypted = true,
                0x0B0 => {
                    if let (Some(r), Some(fcr)) = (cur.as_mut(), b.fcr) {
                        r.groups.push((b.id.unwrap_or_default(), fcr));
                        self.group(Some(fcr), r).await;
                    }
                }
                0x021 | 0x022 => building.clear(),
                0x024 => {
                    if let (Some(i), Some(g)) = (b.index, b.guid) {
                        building.insert(i, g);
                    }
                }
                0x025 | 0x026 => self.diags.push(
                    Diagnostic::unsupported(
                        "global ID table entries copied from a dependency revision are not resolved",
                    )
                    .at(node.span),
                ),
                0x028 => table = Arc::new(building.clone()),
                0x02D | 0x02E | 0x041 | 0x042 => {
                    if let (Some(r), Some(o)) = (cur.as_mut(), self.object(node, &b, &table)) {
                        r.objects.push(o);
                    }
                }
                0x059 | 0x05A => {
                    if let (Some(r), Some(oid)) =
                        (cur.as_mut(), b.oid.and_then(|o| o.resolve(Some(&table))))
                    {
                        r.roots.push((b.role.unwrap_or(0), oid));
                    }
                }
                _ => {}
            }
        }
        if let Some(r) = cur.take() {
            self.diags.push(Diagnostic::malformed(
                "revision manifest without RevisionManifestEndFND",
            ));
            space.events.push(Event::Revision(space.revisions.len()));
            space.revisions.push(r);
        }
    }
}

/// Builds the model. Never fails: problems are collected in `diags`.
pub async fn build(cx: &Cx, store: &Store) -> Model {
    let mut model = Model::default();
    let mut b = Builder {
        cx,
        store,
        seen: BTreeSet::new(),
        diags: Vec::new(),
    };
    let file = store.file;
    let Some(root) = b.list(Some(store.root)).await else {
        model.diags = b.diags;
        return model;
    };
    for (n, node) in root.nodes.iter().enumerate() {
        if n % 256 == 255 {
            cx.checkpoint().await;
        }
        let Ok(body) = node.body(file, None) else {
            continue;
        };
        match node.hdr.id {
            0x004 => model.root = body.id,
            0x008 => model.spaces.push(Space {
                gosid: body.id.unwrap_or_default(),
                manifest: body.fcr,
                ..Space::default()
            }),
            0x090 => model.file_store = body.fcr,
            _ => {}
        }
    }
    for space in model.spaces.iter_mut() {
        if let Some(list) = b.list(space.manifest).await {
            space.revision_list = list
                .nodes
                .iter()
                .filter(|n| n.hdr.id == 0x010)
                .filter_map(|n| n.body(file, None).ok()?.fcr)
                .next_back();
        }
        b.revisions(space).await;
    }
    if let Some(list) = b.list(model.file_store).await {
        for (n, node) in list.nodes.iter().enumerate() {
            if n % 256 == 255 {
                cx.checkpoint().await;
            }
            if node.hdr.id != 0x094 {
                continue;
            }
            if let Ok(body) = node.body(file, None)
                && let (Some(fcr), Some(guid)) = (body.fcr, body.guid)
            {
                model.files.push(DataFile { guid, fcr });
            }
        }
    }
    model.diags = b.diags;
    model
}

/// Reads an object's property set.
pub async fn property_set(
    cx: &Cx,
    file: Span,
    fcr: Fcr,
) -> Result<(Arc<Vec<u8>>, Arc<ObjectPropSet>, Span)> {
    let span = file.sub_exact(fcr.stp, fcr.cb)?;
    if let (Some(data), Some(ps)) = (
        cx.cached::<Vec<u8>>(span, "onenote-propset-bytes"),
        cx.cached::<ObjectPropSet>(span, "onenote-propset"),
    ) {
        return Ok((data, ps, span));
    }
    let data = Arc::new(cx.read(span).await?);
    let ps = Arc::new(props::parse(&data).map_err(|e| e.at(span))?);
    cx.cache(span, "onenote-propset-bytes", data.clone());
    cx.cache(span, "onenote-propset", ps.clone());
    Ok((data, ps, span))
}

/// The data of a file data store object: (span of FileData, declared size).
pub async fn file_data(cx: &Cx, file: Span, fcr: Fcr) -> Result<Span> {
    let head = cx.read(file.sub_exact(fcr.stp, 36)?).await?;
    let len = u64_le(&head, 16).unwrap_or(0);
    let room = fcr.cb.saturating_sub(36);
    file.sub_exact(fcr.stp.saturating_add(36), len.min(room))
}

/// One object reached by the content walk.
#[derive(Clone, Debug)]
pub struct Visit {
    pub at: (usize, usize),
    pub depth: u32,
    pub data: Option<(Arc<Vec<u8>>, Arc<ObjectPropSet>, Span)>,
}

/// Walks the object graph from `root` depth-first, following the object
/// references of each property set (except styles, authors and file data).
pub async fn walk(
    cx: &Cx,
    file: Span,
    space: &Space,
    view: &View,
    root: ExGuid,
) -> (Vec<Visit>, Vec<Diagnostic>) {
    let mut out = Vec::new();
    let mut diags = Vec::new();
    let mut seen = BTreeSet::new();
    let mut stack = vec![(root, 0u32)];
    while let Some((oid, depth)) = stack.pop() {
        cx.checkpoint().await;
        if depth > MAX_WALK_DEPTH || !seen.insert(oid) {
            continue;
        }
        let Some(&at) = view.objects.get(&oid) else {
            continue;
        };
        let Some(obj) = space.object(at) else {
            continue;
        };
        let data = match obj.data {
            Some(fcr) => match property_set(cx, file, fcr).await {
                Ok(d) => Some(d),
                Err(e) => {
                    diags.push(e);
                    None
                }
            },
            None => None,
        };
        if let Some((_, ps, _)) = &data {
            let mut children = Vec::new();
            for p in &ps.body.props {
                if NOT_CHILDREN.contains(&(p.raw_id & 0x7FFF_FFFF)) {
                    continue;
                }
                if let PValue::Ids {
                    stream: props::Stream::Objects,
                    ids,
                    ..
                } = &p.value
                {
                    children.extend(ids.iter().flatten().filter_map(|c| c.resolve(&obj.table)));
                }
            }
            stack.extend(
                children
                    .into_iter()
                    .rev()
                    .map(|c| (c, depth.saturating_add(1))),
            );
        }
        out.push(Visit { at, depth, data });
    }
    (out, diags)
}

#[derive(Clone, Debug)]
pub struct Page {
    pub space: usize,
    pub title: Option<String>,
    pub level: Option<u64>,
}

/// The pages of a section, in the order of its page series.
pub async fn pages(cx: &Cx, file: Span, model: &Model) -> (Vec<Page>, Vec<Diagnostic>) {
    let mut diags = Vec::new();
    let section = model.root.and_then(|r| model.space(&r));
    let mut order: Vec<usize> = Vec::new();
    let mut ordered = BTreeSet::new();
    if let Some(si) = section
        && let Some(space) = model.spaces.get(si)
    {
        let view = space.content(cx).await;
        if let Some(root) = view.roots.get(&1).copied() {
            let (visits, d) = walk(cx, file, space, &view, root).await;
            diags.extend(d);
            let mut spaces = BTreeMap::new();
            for (i, s) in model.spaces.iter().enumerate() {
                if i % 1024 == 1023 {
                    cx.checkpoint().await;
                }
                spaces.entry(s.gosid).or_insert(i);
            }
            for v in &visits {
                cx.checkpoint().await;
                let (Some((_, ps, _)), Some(obj)) = (&v.data, space.object(v.at)) else {
                    continue;
                };
                if let Some(p) = ps.body.get(CHILD_GRAPH_SPACE_ELEMENT_NODES)
                    && let PValue::Ids { ids, .. } = &p.value
                {
                    for (n, c) in ids.iter().flatten().enumerate() {
                        if n % 1024 == 1023 {
                            cx.checkpoint().await;
                        }
                        if let Some(&i) = c.resolve(&obj.table).and_then(|g| spaces.get(&g))
                            && ordered.insert(i)
                        {
                            order.push(i);
                        }
                    }
                }
            }
        }
    }
    if order.is_empty() {
        order = (0..model.spaces.len())
            .filter(|&i| Some(i) != section)
            .collect();
    }
    let mut pages = Vec::new();
    for i in order {
        cx.checkpoint().await;
        let Some(space) = model.spaces.get(i) else {
            continue;
        };
        let mut page = Page {
            space: i,
            title: None,
            level: None,
        };
        if !space.encrypted {
            if let Some((meta, _)) = space.root(cx, 2).await
                && let Some(fcr) = meta.data
            {
                match property_set(cx, file, fcr).await {
                    Ok((data, ps, _)) => {
                        page.title = ps
                            .body
                            .string(&data, CACHED_TITLE_STRING)
                            .or_else(|| ps.body.string(&data, CACHED_TITLE_STRING_FROM_PAGE));
                        if let Some(p) = ps.body.get(PAGE_LEVEL)
                            && let PValue::Int(v, _) = p.value
                        {
                            page.level = Some(v);
                        }
                    }
                    Err(e) => diags.push(e),
                }
            }
            if page.title.is_none() {
                page.title = title_from_content(cx, file, space).await;
            }
        }
        pages.push(page);
    }
    (pages, diags)
}

/// The text of the page's title node, if it has one.
async fn title_from_content(cx: &Cx, file: Span, space: &Space) -> Option<String> {
    let view = space.content(cx).await;
    let root = *view.roots.get(&1)?;
    let (visits, _) = walk(cx, file, space, &view, root).await;
    let mut in_title: Option<u32> = None;
    let mut parts = Vec::new();
    for v in &visits {
        if in_title.is_some_and(|d| v.depth <= d) {
            break;
        }
        let obj = space.object(v.at)?;
        if obj.jcid == JCID_TITLE {
            in_title = Some(v.depth);
        } else if in_title.is_some()
            && let Some((data, ps, _)) = &v.data
            && let Some((text, _, _)) = ps.body.text(data)
        {
            parts.push(text);
        }
    }
    let title = parts.join(" ");
    (!title.trim().is_empty()).then_some(title)
}

/// The span of `len` bytes at `at` inside a property set read from `span`.
pub fn inner(span: Span, at: usize, len: usize) -> Span {
    span.sub(to_u64(at), to_u64(len))
}
