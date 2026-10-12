//! Science dissectors that walk variable-size records keep their work in
//! proportion to what is shown: a large PLY face list is not walked to list
//! the elements, and shapefile coordinate arrays are listed lazily.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::{Limits, NodeId};

/// Expands `id` by one page of `page` children.
fn page(host: &mut Host, id: NodeId, page: u64) -> Vec<NodeId> {
    host.session.expand_more(id, page);
    host.run();
    host.session.children(id).unwrap().ids.to_vec()
}

fn summary(host: &Host, id: NodeId) -> String {
    host.session
        .node(id)
        .unwrap()
        .summary
        .clone()
        .unwrap_or_default()
}

/// A binary PLY with `faces` triangles and an edge element after them.
fn big_ply(faces: u32) -> Vec<u8> {
    let mut out = format!(
        "ply\nformat binary_little_endian 1.0\nelement vertex 3\nproperty float x\n\
         property float y\nproperty float z\nelement face {faces}\n\
         property list uchar int vertex_indices\nelement edge 1\nproperty int vertex1\n\
         property int vertex2\nend_header\n"
    )
    .into_bytes();
    for v in [[0f32, 0., 0.], [1., 0., 0.], [0., 1., 0.]] {
        for c in v {
            out.extend_from_slice(&c.to_le_bytes());
        }
    }
    for _ in 0..faces {
        out.push(3);
        for i in [0i32, 1, 2] {
            out.extend_from_slice(&i.to_le_bytes());
        }
    }
    out.extend_from_slice(&7i32.to_le_bytes());
    out.extend_from_slice(&9i32.to_le_bytes());
    out
}

#[test]
fn ply_listing_does_not_walk_a_large_face_list() {
    let faces = 200_000;
    let data = big_ply(faces);
    let total = data.len() as u64;
    let mut host = Host::named("big.ply", data, Limits::default());
    let root = host.root;
    let top = page(&mut host, root, 100);
    let names: Vec<String> = top
        .iter()
        .map(|&id| host.session.node(id).unwrap().name.to_string())
        .collect();
    assert_eq!(names, ["Header", "vertex", "face", "edge"]);
    // Listing the elements reads the header, not the 2.6 MB of faces.
    assert!(
        host.bytes_supplied < 256 * 1024,
        "{} of {total} bytes read",
        host.bytes_supplied
    );
    let work = host.session.work_done();
    assert!(work < 20_000, "{work} units to list the elements");

    // The first page of faces reads little more.
    let face = top[2];
    let first = page(&mut host, face, 50);
    assert_eq!(first.len(), 50);
    assert_eq!(summary(&host, first[0]), "vertex_indices=[0 1 2]");
    assert!(host.bytes_supplied < 512 * 1024);

    // The edge element finds its start by walking the faces, in steps.
    let edge = top[3];
    let edges = page(&mut host, edge, 10);
    assert_eq!(edges.len(), 1);
    assert_eq!(summary(&host, edges[0]), "vertex1=7 vertex2=9");
    let span = host.session.node(edges[0]).unwrap().span.unwrap();
    assert_eq!(span.offset + span.len, total);
}

#[test]
fn ply_truncated_face_list_is_reported() {
    let mut data = big_ply(10);
    data.truncate(data.len() - 30);
    let mut host = Host::named("cut.ply", data, Limits::default());
    host.explore_all();
    let text = host.render();
    assert!(
        text.contains("only 8 of 10 records present") || text.contains("truncated"),
        "{text}"
    );
}

/// A shapefile holding one polygon of `points` points in one part.
fn big_shp(points: u32) -> Vec<u8> {
    let content_len = 44 + 4 + 16 * points as usize;
    let file_len = 100 + 8 + content_len;
    let mut out = vec![0u8; 100];
    out[0..4].copy_from_slice(&9994u32.to_be_bytes());
    out[24..28].copy_from_slice(&((file_len / 2) as u32).to_be_bytes());
    out[28..32].copy_from_slice(&1000u32.to_le_bytes());
    out[32..36].copy_from_slice(&5u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&((content_len / 2) as u32).to_be_bytes());
    out.extend_from_slice(&5u32.to_le_bytes());
    for b in [0f64, 0., 1., 1.] {
        out.extend_from_slice(&b.to_le_bytes());
    }
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&points.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    for i in 0..points {
        out.extend_from_slice(&f64::from(i).to_le_bytes());
        out.extend_from_slice(&0.5f64.to_le_bytes());
    }
    out
}

#[test]
fn shapefile_points_are_listed_lazily() {
    let data = big_shp(100_000);
    let mut host = Host::named("big.shp", data, Limits::default());
    let root = host.root;
    let top = page(&mut host, root, 10);
    let records = *top.last().unwrap();
    let recs = page(&mut host, records, 10);
    assert_eq!(recs.len(), 1);
    assert_eq!(summary(&host, recs[0]), "Polygon, 1 part, 100000 points");
    let fields = page(&mut host, recs[0], 100);
    // Decoding the record reads its fixed part, not the 1.6 MB of points.
    assert!(host.bytes_supplied < 256 * 1024, "{}", host.bytes_supplied);
    let points = host.child(recs[0], "Points").unwrap();
    assert_eq!(summary(&host, points), "100000 points");
    assert!(fields.contains(&points));
    let first = page(&mut host, points, 5);
    assert_eq!(first.len(), 5);
    assert_eq!(summary(&host, first[3]), "(3, 0.5)");
    assert!(host.bytes_supplied < 512 * 1024, "{}", host.bytes_supplied);
}

#[test]
fn shapefile_point_count_beyond_the_record_is_rejected_before_reading() {
    let mut data = big_shp(4);
    // Claim four billion points in a record that holds four.
    let at = 100 + 8 + 40;
    data[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    let mut host = Host::named("bad.shp", data, Limits::default());
    host.explore_all();
    let text = host.render();
    assert!(text.contains("truncated"), "{text}");
}
