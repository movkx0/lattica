#!/usr/bin/env python3
"""Native snapshot pin/fence contracts using an explicit non-cryptographic stub."""
import copy
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import block_v2_native_shared as N


class StubStore:
    def __init__(self, verifier):
        self.verifier = verifier
        self.view = N.H.View("11" * 32, None, {"height": 9, "anchor": "22" * 32}, 0)
        self.before_commit = lambda: None
        self.commits = 0
        self.history = ()
        self.parent = self.view

    def recover_application(self, candidate, *, expected_parent, expected_generation):
        if (self.history != (candidate,) or expected_parent != self.parent.token
                or expected_generation != self.parent.generation or self.view.generation != 1):
            raise N.H.StaleHead('stub rejected application recovery')
        return self.view, self.parent

    def snapshot(self):
        return self.view, self.history

    def read(self):
        return self.view

    def commit(self, candidate, *, expected_head):
        self.before_commit()
        if self.view.token != expected_head:
            raise N.H.StaleHead("stub compare-and-swap rejected the stale head")
        self.commits += 1
        self.history += (candidate,)
        self.view = N.H.View("33" * 32, "44" * 32, {"height": candidate.height}, 1)
        return self.view


class NativeShared(unittest.TestCase):
    def test_explicit_recovery_recreates_identical_receipt_without_second_commit(self):
        candidate = N.Candidate(*self.args)
        proof = self.fixture / 'root'
        proof.write_bytes(b'stub-root')
        original = candidate.apply(proof, candidate.binding)
        with self.assertRaises(N.H.StaleHead):
            N.Candidate(*self.args)
        recovered = N.Candidate(*self.args, recover_proof=proof, recover_binding=candidate.binding)
        self.assertEqual(recovered.binding, candidate.binding)
        self.assertEqual(recovered.recovered_receipt, original)
        self.assertEqual(recovered.apply(proof, candidate.binding), original)
        self.assertEqual(recovered.verify_application(original, proof, candidate.binding), self.store.view)
        self.assertEqual(self.store.commits, 1)

    def test_application_recovery_rejects_substituted_binding_and_proof(self):
        candidate = N.Candidate(*self.args)
        proof = self.fixture / 'root'
        proof.write_bytes(b'stub-root')
        candidate.apply(proof, candidate.binding)
        wrong = copy.deepcopy(candidate.binding)
        wrong['expected']['root'] = [8] * 4
        with self.assertRaises(N.H.RejectedBlock):
            N.Candidate(*self.args, recover_proof=proof, recover_binding=wrong)
        proof.write_bytes(b'other-root')
        with self.assertRaises(N.H.StaleHead):
            N.Candidate(*self.args, recover_proof=proof, recover_binding=candidate.binding)
        self.assertEqual(self.store.commits, 1)

    def test_recovery_options_still_allow_unpublished_parent_and_require_both_inputs(self):
        candidate = N.Candidate(*self.args)
        proof = self.fixture / 'root'
        proof.write_bytes(b'stub-root')
        recovered = N.Candidate(*self.args, recover_proof=proof, recover_binding=candidate.binding)
        self.assertIsNone(recovered.recovered_application)
        recovered.apply(proof, candidate.binding)
        self.assertEqual(self.store.commits, 1)
        with self.assertRaises(N.H.RejectedBlock):
            N.Candidate(*self.args, recover_proof=proof)

    def test_regular_json_allows_formatting_but_not_duplicate_or_nonfinite_fields(self):
        expected = {"schema_version": 1, "nested": {"height": 10}}
        self.config.write_text(json.dumps(expected, indent=2))
        self.assertEqual(N.read(self.config), expected)
        for invalid in ('{"height":1,"height":2}', '{"height":NaN}', '{"height":Infinity}', '[]'):
            self.config.write_text(invalid)
            with self.assertRaises(N.H.HostStoreError):
                N.read(self.config)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.fixture, journal = root / "fixture", root / "journal"
        self.fixture.mkdir()
        journal.mkdir()
        context = bytes([5] * 32 + [6] * 32)
        registry, genesis = b"stub-registry", b"stub-genesis"
        self.store = StubStore(SimpleNamespace(
            configuration={"verifier": "explicit-non-cryptographic-stub"},
            identity={"kind": "explicit-non-cryptographic-stub"},
            _context=context, _registry=registry, _genesis=genesis,
            _policy=N.H.IssuancePolicy({10: {3: 7}})))
        native = b"LBV2EX01" + context + struct.pack("<QQQQQ", 7, 7, 7, 7, 4)
        self.expected = {"schema_version": 1, "profile": list(context[:32]),
            "chain": list(context[32:]), "root": [7] * 4, "count": 4, "block_height": 10,
            "authorized_issuance": {"3": 7}}
        files = {"complete-body.bin": b"LBV2BD01" + struct.pack("<I", 4) + b"stub",
            "body.json": b"{}", "expected.json": N.H.canonical(self.expected),
            "native-expected.bin": native, "rust-expected.bin": native,
            "host-registry.bin": registry, "genesis.bin": genesis, "height.json": b"262144"}
        files.update({f"key.{i}": f"stub-key-{i}".encode() for i in range(1, 13)})
        files.update({f"wallet.{i}": f"stub-wallet-{i}".encode() for i in range(4)})
        for name, data in files.items():
            (self.fixture / name).write_bytes(data)
        self.manifest = {"record_type": "native_delivery_preparation", "status": "succeeded",
            "host_configuration_sha256": N.H.sha(N.H.canonical(self.store.verifier.configuration)),
            "parent_head_token": self.store.view.token, "parent_tip": None,
            "parent_state": self.store.view.state, "height": 10,
            "sources": [N.D.pin(self.fixture / name) for name in files]}
        self.save_manifest()
        for name, data in {"library": b"stub-library", "registry": registry, "genesis": genesis}.items():
            (root / name).write_bytes(data)
        config = {name: str(root / name) for name in ("library", "registry", "genesis")}
        config.update(profile_id=context[:32].hex(), chain_id=context[32:].hex(),
            issuance_grants={"10": {"3": 7}}, pins=[N.D.pin(root / name) for name in config])
        self.config = root / "host.json"
        self.config.write_bytes(N.H.canonical(config))
        self.args = self.config, journal, self.fixture, 4
        self.addCleanup(patch.stopall)
        patch.object(N, "open_host", return_value=self.store).start()
        patch.object(N, "native_expected", return_value=native).start()

    def save_manifest(self):
        (self.fixture / "manifest.json").write_bytes(N.H.canonical(self.manifest))

    def repin(self, name):
        path = self.fixture / name
        self.manifest["sources"] = [N.D.pin(path) if p["path"] == str(path) else p
                                    for p in self.manifest["sources"]]
        self.save_manifest()

    def test_verified_head_and_native_policy_are_bound_and_application_is_fenced(self):
        candidate = N.Candidate(*self.args)
        self.assertEqual(candidate.binding["head_token"], [0x11] * 32)
        self.assertEqual(candidate.binding["expected"], self.expected)
        proof = self.fixture / "root"
        proof.write_bytes(b"stub-root")
        receipt = candidate.apply(proof, candidate.binding)
        self.assertEqual(receipt["count"], 4)
        self.assertTrue(receipt["durability_confirmed"])
        self.assertEqual(receipt["state"]["height"], 10)
        self.assertEqual(self.store.commits, 1)
        self.assertEqual(candidate.verify_application(receipt, proof, candidate.binding).token, receipt["head_token"])
        for changes in ({"root_sha256": "99" * 32}, {"count": True}, {"state": {}},
                        {"generation": 99}, {"head_token": "99" * 32}):
            with self.assertRaises(N.H.RejectedBlock):
                candidate.verify_application(receipt | changes, proof, candidate.binding)
        with self.assertRaises(N.H.StaleHead):
            candidate.apply(proof, candidate.binding)

    def test_changed_head_is_rejected_before_dispatch(self):
        self.store.view = N.H.View("33" * 32, None, self.store.view.state, 1)
        with self.assertRaises(N.H.StaleHead):
            N.Candidate(*self.args)

    def test_repinning_worker_expectation_cannot_replace_native_height_or_issuance(self):
        for changed in ({"block_height": 11}, {"authorized_issuance": {"3": 8}}, {"root": [8] * 4}):
            with self.subTest(changed=changed):
                (self.fixture / "expected.json").write_bytes(N.H.canonical(self.expected | changed))
                self.repin("expected.json")
                with self.assertRaises(N.H.RejectedBlock):
                    N.Candidate(*self.args)

    def test_missing_or_changed_wallet_pin_is_rejected(self):
        candidate = N.Candidate(*self.args)
        (self.fixture / "wallet.0").write_bytes(b"substituted")
        with self.assertRaises(N.H.RejectedBlock):
            candidate.check(candidate.binding)
        self.manifest["sources"] = [p for p in self.manifest["sources"] if not p["path"].endswith("wallet.0")]
        self.save_manifest()
        with self.assertRaises(N.H.RejectedBlock):
            N.Candidate(*self.args)

    def test_manifest_and_serialized_binding_cannot_change_after_snapshot(self):
        candidate = N.Candidate(*self.args)
        changed = copy.deepcopy(candidate.binding)
        changed["generation"] += 1
        with self.assertRaises(N.H.RejectedBlock):
            candidate.check(changed)
        self.manifest["height"] += 1
        self.save_manifest()
        with self.assertRaises(N.H.RejectedBlock):
            candidate.check(candidate.binding)

    def test_change_between_final_check_and_commit_still_hits_atomic_head_fence(self):
        candidate = N.Candidate(*self.args)
        proof = self.fixture / "root"
        proof.write_bytes(b"stub-root")
        self.store.before_commit = lambda: setattr(self.store, "view",
            N.H.View("55" * 32, None, {"height": 9}, 2))
        with self.assertRaises(N.H.StaleHead):
            candidate.apply(proof, candidate.binding)
        self.assertEqual(self.store.commits, 0)

    def test_indeterminate_publication_is_not_relabelled_as_rejected(self):
        candidate = N.Candidate(*self.args)
        proof = self.fixture / "root"
        proof.write_bytes(b"stub-root")
        def uncertain():
            raise N.H.CommitIndeterminate("test storage uncertainty after publication")
        self.store.before_commit = uncertain
        with self.assertRaises(N.H.CommitIndeterminate):
            candidate.apply(proof, candidate.binding)


if __name__ == "__main__":
    unittest.main()
