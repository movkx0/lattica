//! Structural durable transition/recovery tests, not cryptographic evidence.
use super::*;

fn prepared_extension(owner: &mut DurableDag) -> (Job, Job, CandidateId) {
    let (prefix, candidate) = candidate(owner, 3);
    // The three-wallet structural prefix has exactly one complete non-root
    // subtree (two legacy wallet wrappers at level 1).
    let job = tree(owner, 3, 0, 1);
    let bytes = job.id().to_bytes().to_vec();
    owner.cache_node(node(&job, &bytes), bytes, 0).unwrap();
    let final_root = tree(owner, 4, 0, DEPTH);
    (prefix, final_root, candidate)
}

#[test]
fn durable_extension_recovery_preserves_scope_and_original_deadline() {
    let temp = Temp::new();
    let mut owner = temp.create();
    let (_, root, candidate) = prepared_extension(&mut owner);
    owner.seal_prefix_extension(candidate, root.id(), [1; 32], 1).unwrap();
    assert_durable(&owner);
    drop(owner);
    let recovery = recover(&temp, 2);
    assert_eq!(recovery.previous_candidates().len(), 1);
    let previous = &recovery.previous_candidates()[0];
    assert_eq!(previous.id, candidate);
    assert_eq!(previous.root, root.id());
    assert_eq!(previous.deadline_ms, 1000);
    assert!(previous.sealed && !previous.cancelled);
    let (mut owner, retained) = recovery.resume_sealed_candidate_with_workspaces(
        |_| panic!("no live attempts"), |_| panic!("no workspaces"), || 900,
        candidate, root.id(), [1; 32]).unwrap();
    // A restart attaches the existing selection under a new recovery identity;
    // only the live transition preserves identity. Neither renews the clock.
    assert_ne!(retained, candidate);
    assert_eq!(owner.sealed_candidate_binding(retained, [1; 32], 999).unwrap(), (root.id(), 1000));
    assert!(owner.sealed_candidate_binding(retained, [1; 32], 1000).is_err());
}

#[test]
fn interrupted_extension_publishes_only_a_complete_old_or_new_candidate_and_poisoning() {
    for stage in [Fault::AfterWrite, Fault::AfterFileSync, Fault::AfterRename, Fault::AfterDirectorySync] {
        let temp = Temp::new();
        let mut owner = temp.create();
        let (prefix, next, candidate) = prepared_extension(&mut owner);
        owner.journal.fault = Some(stage);
        assert!(owner.seal_prefix_extension(candidate, next.id(), [1; 32], 1).is_err());
        assert!(owner.poisoned);
        assert!(owner.seal_prefix_extension(candidate, next.id(), [1; 32], 2).is_err());
        drop(owner);
        let recovery = recover(&temp, 2);
        assert_eq!(recovery.previous_candidates().len(), 1);
        let observed = &recovery.previous_candidates()[0];
        assert_eq!(observed.id, candidate);
        assert_eq!(observed.deadline_ms, 1000);
        assert!(!observed.cancelled);
        assert!((observed.root == prefix.id() && !observed.sealed)
            || (observed.root == next.id() && observed.sealed));
    }
}
