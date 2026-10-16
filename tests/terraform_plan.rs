//! Terraform saved plans: the ZIP variant's probe when the plan is larger
//! than the probe window.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use fillyfoal::formats::{Head, TAIL_LEN, identify};

/// A large plan pushes every entry after `tfplan` past the head; only the
/// central directory in the tail names them. Simulated with the real
/// `create.tfplan`, its head cut inside the `tfplan` entry's data.
#[test]
fn a_plan_larger_than_the_head_is_still_a_saved_plan() {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/external/terraform-plan/create.tfplan"
    ))
    .unwrap();
    let tail = &data[data.len().saturating_sub(TAIL_LEN as usize)..];
    let name = |head: &[u8]| {
        identify(&Head {
            data: head,
            tail,
            len: 1 << 20,
            len_known: true,
        })
        .map(|f| f.name)
    };
    // The whole file: the second entry is in the head.
    assert_eq!(name(&data), Some("terraform-plan"));
    // The local header and name of `tfplan`, then part of its data.
    assert_eq!(name(&data[..48]), Some("terraform-plan"));
}
