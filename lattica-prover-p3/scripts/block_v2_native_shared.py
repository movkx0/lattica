"""Verified native snapshot boundary for the local shared-GPU controller.

The native verifier and journal are the authority. A serialized binding only
identifies their verified snapshot; it cannot establish native delivery alone.
"""
import ctypes
import json
from pathlib import Path
import struct

import block_v2_host_store as H
import block_v2_native_delivery as D


def read(path):
    def invalid_number(_):
        raise ValueError("non-finite JSON number")
    try:
        value = json.loads(Path(path).read_bytes(), object_pairs_hook=H._object,
                           parse_constant=invalid_number)
        if not isinstance(value, dict):
            raise ValueError("native configuration must be an object")
        return value
    except (ValueError, TypeError, UnicodeError) as error:
        raise H.RejectedBlock("invalid native configuration JSON") from error


def check_pins(pins):
    seen = {}
    for source in pins:
        path = Path(source["path"]).resolve(strict=True)
        if (str(path) in seen and seen[str(path)] != source) or D.pin(path) != source:
            raise H.RejectedBlock("native input pin changed or conflicts with another pin")
        seen[str(path)] = source
    return set(seen)


def open_verifier(config_path):
    config = read(config_path)
    present = check_pins(config["pins"])
    required = {str(Path(config[key]).resolve(strict=True)) for key in ("library", "registry", "genesis")}
    if not required <= present:
        raise H.RejectedBlock("native verifier inputs are not pinned")
    grants = config["issuance_grants"]
    if any(str(int(height)) != height or any(str(int(index)) != index for index in row)
           for height, row in grants.items()):
        raise H.RejectedBlock("native issuance policy has ambiguous indices")
    verifier = H.NativeVerifier(
        config["library"], Path(config["registry"]).read_bytes(),
        bytes.fromhex(config["profile_id"]), bytes.fromhex(config["chain_id"]),
        Path(config["genesis"]).read_bytes(),
        H.IssuancePolicy({int(height): {int(index): value for index, value in row.items()}
                         for height, row in grants.items()}))
    return verifier


def open_host(config_path, journal):
    return H.Store(journal, open_verifier(config_path))


def native_expected(verifier, complete_body):
    derive = verifier._lib.lattica_v2_research_body_expected_v1
    derive.argtypes = [ctypes.c_void_p, ctypes.c_size_t] * 3
    derive.restype = ctypes.c_int32
    context = ctypes.create_string_buffer(verifier._context)
    body = ctypes.create_string_buffer(complete_body)
    expected = ctypes.create_string_buffer(112)
    if derive(context, 64, body, len(complete_body), expected, 112) != 0:
        raise H.RejectedBlock("native candidate expectation derivation failed")
    return expected.raw


class Candidate:
    def __init__(self, config_path, journal, fixture, count, *, prefix=False,
                 recover_proof=None, recover_binding=None):
        self.prefix = prefix
        self.recovered_application = None
        self.recovered_receipt = None
        if (recover_proof is None) != (recover_binding is None) or (prefix and recover_proof is not None):
            raise H.RejectedBlock('application recovery requires a sealed proof and original binding')
        if type(count) is not int or not 1 <= count <= 64:
            raise H.RejectedBlock("native candidate count must be an integer in 1..64")
        self.config_path = Path(config_path).resolve(strict=True)
        self.journal = Path(journal).resolve(strict=True)
        self.fixture = Path(fixture).resolve(strict=True)
        self.config_pin = D.pin(self.config_path)
        self.store = open_host(self.config_path, self.journal)
        self.manifest_path = self.fixture / "manifest.json"
        self.manifest_pin = D.pin(self.manifest_path)
        manifest = read(self.manifest_path)
        self.pins = read(self.config_path)["pins"] + manifest["sources"]
        present = check_pins(self.pins)
        required = {str(self.fixture / name) for name in (
            "complete-body.bin", "body.json", "expected.json", "native-expected.bin",
            "rust-expected.bin", "host-registry.bin", "genesis.bin", "height.json",
            *(f"key.{index}" for index in range(1, 13)),
            *(f"wallet.{index}" for index in range(count)))}
        if not required <= present:
            raise H.RejectedBlock("native candidate preparation is missing required input pins")
        configuration = H.sha(H.canonical(self.store.verifier.configuration))
        view, _ = self.store.snapshot()
        if recover_proof is not None and view.token != manifest.get('parent_head_token'):
            self.recovered_application, view = self.store.recover_application(
                H.Candidate(manifest['height'], (self.fixture / 'complete-body.bin').read_bytes(),
                            Path(recover_proof).read_bytes()),
                expected_parent=manifest['parent_head_token'],
                expected_generation=recover_binding.get('generation'))
        record_type = "native_arrival_prefix_preparation" if prefix else "native_delivery_preparation"
        if (manifest.get("record_type") != record_type
                or manifest.get("status") != "succeeded"
                or manifest.get("host_configuration_sha256") != configuration
                or manifest.get("parent_head_token") != view.token
                or manifest.get("parent_tip") != view.tip
                or H.canonical(manifest.get("parent_state")) != H.canonical(view.state)
                or manifest.get("height") != view.state["height"] + 1):
            raise H.StaleHead("native preparation does not match the verified current head")
        complete_body = (self.fixture / "complete-body.bin").read_bytes()
        if H.body_count(complete_body) != count:
            raise H.RejectedBlock("native candidate count differs from its complete body")
        derived = native_expected(self.store.verifier, complete_body)
        if (derived[:8] != b"LBV2EX01" or derived[8:72] != self.store.verifier._context
                or int.from_bytes(derived[104:112], "little") != count
                or (self.fixture / "native-expected.bin").read_bytes() != derived
                or (self.fixture / "rust-expected.bin").read_bytes() != derived
                or (self.fixture / "host-registry.bin").read_bytes() != self.store.verifier._registry
                or (self.fixture / "genesis.bin").read_bytes() != self.store.verifier._genesis):
            raise H.RejectedBlock("native and prepared verifier inputs differ")
        grant_policy = self.store.verifier._policy.for_prefix if prefix else self.store.verifier._policy.for_block
        expected = {
            "schema_version": 1, "profile": list(derived[8:40]), "chain": list(derived[40:72]),
            "root": list(struct.unpack_from("<QQQQ", derived, 72)), "count": count,
            "block_height": manifest["height"],
            "authorized_issuance": {str(index): value for index, value in enumerate(
                grant_policy(manifest["height"], count)) if value},
        }
        if H.canonical(read(self.fixture / "expected.json")) != H.canonical(expected):
            raise H.RejectedBlock("native height, issuance policy or root expectation differs")
        self.binding = {
            "schema_version": 1, "head_token": list(bytes.fromhex(view.token)),
            "generation": view.generation, "configuration_sha256": list(bytes.fromhex(configuration)),
            "complete_body_sha256": list(bytes.fromhex(H.sha(complete_body))),
            "preparation_sha256": list(bytes.fromhex(self.manifest_pin["sha256"])), "expected": expected,
        }
        if prefix:
            self.binding["scope"] = "prefix"
        self.head = view
        self.count = count
        if recover_binding is not None and H.canonical(self.binding) != H.canonical(recover_binding):
            raise H.RejectedBlock('recovered application binding differs from the original candidate')
        if self.recovered_application is not None:
            self.recovered_receipt = self._application_receipt(self.recovered_application, recover_proof)

    @property
    def current_head(self):
        return self.recovered_application or self.head

    def check(self, expected_binding):
        if H.canonical(self.binding) != H.canonical(expected_binding):
            raise H.RejectedBlock("native candidate binding was substituted")
        if D.pin(self.config_path) != self.config_pin or D.pin(self.manifest_path) != self.manifest_pin:
            raise H.RejectedBlock("native candidate configuration or preparation changed")
        check_pins(self.pins)
        if self.store.read().token != self.current_head.token:
            raise H.StaleHead("native head changed while proving")

    def apply(self, proof, expected_binding):
        if self.prefix:
            raise H.RejectedBlock("an unsealed prefix cannot be applied as a native candidate")
        self.check(expected_binding)
        if self.recovered_application is None:
            view = D.apply_prepared(self.store, self.fixture, proof)
        else:
            view, _ = self.store.recover_application(
                H.Candidate(self.binding['expected']['block_height'],
                            (self.fixture / 'complete-body.bin').read_bytes(), Path(proof).read_bytes()),
                expected_parent=self.head.token, expected_generation=self.head.generation)
        return self._application_receipt(view, proof)

    def _application_receipt(self, view, proof):
        return {
            "schema_version": 1, "record_type": "native_shared_candidate_application",
            "parent_head_token": self.head.token, "head_token": view.token, "tip": view.tip,
            "generation": view.generation, "state": view.state,
            "durability_confirmed": view.durability_confirmed, "count": self.count,
            "complete_body_sha256": H.sha((self.fixture / "complete-body.bin").read_bytes()),
            "root_sha256": H.sha(Path(proof).read_bytes()),
            "host_configuration_sha256": H.sha(H.canonical(self.store.verifier.configuration)),
            "native_verifier": self.store.verifier.identity,
        }

    def verify_application(self, receipt, proof, expected_binding):
        if self.prefix:
            raise H.RejectedBlock("an unsealed prefix has no native application receipt")
        """Reopen and CPU-replay the published state independently of the owner."""
        if H.canonical(self.binding) != H.canonical(expected_binding) or D.pin(self.config_path) != self.config_pin:
            raise H.RejectedBlock("native application configuration or binding differs")
        if D.pin(self.manifest_path) != self.manifest_pin:
            raise H.RejectedBlock("native preparation changed after application")
        check_pins(self.pins)
        store = open_host(self.config_path, self.journal)
        view, history = store.snapshot()
        if (receipt.get("record_type") != "native_shared_candidate_application"
                or receipt.get("schema_version") != 1
                or receipt.get("parent_head_token") != self.head.token
                or receipt.get("head_token") != view.token or receipt.get("tip") != view.tip
                or type(receipt.get("generation")) is not int
                or receipt.get("generation") != self.head.generation + 1
                or receipt.get("generation") != view.generation
                or H.canonical(receipt.get("state")) != H.canonical(view.state)
                or receipt.get("durability_confirmed") is not True
                or type(receipt.get("count")) is not int or receipt["count"] != self.count
                or receipt.get("host_configuration_sha256") != H.sha(H.canonical(store.verifier.configuration))
                or receipt.get("native_verifier") != store.verifier.identity
                or receipt.get("complete_body_sha256") != bytes(self.binding["complete_body_sha256"]).hex()
                or receipt.get("root_sha256") != H.sha(Path(proof).read_bytes())
                or not history or history[-1].height != self.binding["expected"]["block_height"]
                or H.sha(history[-1].body) != receipt["complete_body_sha256"]
                or H.sha(history[-1].proof) != receipt["root_sha256"]):
            raise H.RejectedBlock("native application receipt differs from verified published state")
        return view
