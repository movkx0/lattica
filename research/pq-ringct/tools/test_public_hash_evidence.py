"""Synthetic acceptance-policy fixtures; these tests make no GPU-work claim."""
import copy
import unittest

from public_hash_evidence import (
    require_requested,
    validate_record,
    workflow_records,
)


def evidence(kernel="baseline", *, tuning=True, nvidia=True):
    return {
        "kernel": kernel,
        "gpu_tuning_compiled": tuning,
        "nvidia_supported": nvidia,
    }


def reports(value):
    return tuple({"public_hash": copy.deepcopy(value)} for _ in range(3))


class PublicHashEvidenceTests(unittest.TestCase):
    def test_baseline_preserves_both_build_and_device_choices(self):
        for tuning in (False, True):
            for nvidia in (False, True):
                value = evidence(tuning=tuning, nvidia=nvidia)
                with self.subTest(tuning=tuning, nvidia=nvidia):
                    self.assertEqual(
                        validate_record(value, expected_kernel="baseline"), value
                    )

    def test_candidate_requires_compiled_feature_and_supported_device(self):
        value = evidence("sbox-pair-v1")
        self.assertEqual(validate_record(value), value)
        for tuning, nvidia in ((False, True), (True, False), (False, False)):
            with self.subTest(tuning=tuning, nvidia=nvidia), self.assertRaises(ValueError):
                validate_record(evidence("sbox-pair-v1", tuning=tuning, nvidia=nvidia))

    def test_missing_unknown_or_non_object_evidence_cannot_imply_a_baseline(self):
        for value in (None, False, 0, "baseline", [], {}, {"kernel": "baseline"}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_record(value, expected_kernel="baseline")
        for field in evidence():
            value = evidence()
            del value[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                validate_record(value)
        value = dict(evidence(), fallback="cpu")
        with self.assertRaises(ValueError):
            validate_record(value)

    def test_effective_and_requested_kernels_are_exact_strings(self):
        invalid = (None, True, 0, "", "Baseline", "sbox_pair_v1", "sbox-pair-v1 ", "cpu", ["baseline"])
        for kernel in invalid:
            with self.subTest(effective=kernel), self.assertRaises(ValueError):
                validate_record(evidence(kernel))
        for kernel in invalid[1:]:
            with self.subTest(requested=kernel), self.assertRaises(ValueError):
                validate_record(evidence(), expected_kernel=kernel)
        for actual, expected in (("baseline", "sbox-pair-v1"), ("sbox-pair-v1", "baseline")):
            with self.subTest(actual=actual, expected=expected), self.assertRaises(ValueError):
                validate_record(evidence(actual), expected_kernel=expected)

    def test_flags_reject_truthy_values_and_integer_boolean_aliases(self):
        for field in ("gpu_tuning_compiled", "nvidia_supported"):
            for value in (None, 0, 1, 0.0, 1.0, "true", "false", [], {}):
                changed = evidence("sbox-pair-v1")
                changed[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    validate_record(changed)

    def test_acceptance_copy_cannot_mutate_original_evidence(self):
        value = evidence("sbox-pair-v1")
        accepted = validate_record(value)
        self.assertIsNot(accepted, value)
        accepted["kernel"] = "baseline"
        self.assertEqual(value["kernel"], "sbox-pair-v1")

    def test_request_environment_and_effective_execution_must_all_agree(self):
        for kernel in ("baseline", "sbox-pair-v1"):
            value = evidence(kernel)
            self.assertEqual(require_requested(value, kernel, kernel), value)
        for actual, requested, environment in (
            ("baseline", "sbox-pair-v1", "sbox-pair-v1"),
            ("sbox-pair-v1", "baseline", "baseline"),
            ("baseline", "baseline", "sbox-pair-v1"),
            ("sbox-pair-v1", "sbox-pair-v1", "baseline"),
        ):
            with self.subTest(actual=actual, requested=requested, environment=environment):
                with self.assertRaises(ValueError):
                    require_requested(evidence(actual), requested, environment)
        for invalid in (None, True, 0, "", "sbox_pair_v1", "sbox-pair-v1 ", "cpu"):
            for requested, environment in ((invalid, "baseline"), ("baseline", invalid)):
                with self.subTest(requested=requested, environment=environment):
                    with self.assertRaises(ValueError):
                        require_requested(evidence(), requested, environment)

    def test_complete_workflow_requires_both_preprocessing_sessions_to_agree(self):
        for kernel in ("baseline", "sbox-pair-v1"):
            value = evidence(kernel)
            self.assertEqual(
                workflow_records(*reports(value), expected_kernel=kernel), value
            )
        for index in range(3):
            values = reports(evidence("sbox-pair-v1"))
            values[index]["public_hash"] = evidence("baseline")
            with self.subTest(changed=index), self.assertRaises(ValueError):
                workflow_records(*values)
            values = list(reports(evidence()))
            values[index] = {}
            with self.subTest(missing=index), self.assertRaises(ValueError):
                workflow_records(*values)

    def test_workflow_checks_support_flags_and_requested_selector_too(self):
        for field in ("gpu_tuning_compiled", "nvidia_supported"):
            values = reports(evidence())
            values[2]["public_hash"][field] = False
            with self.subTest(field=field), self.assertRaises(ValueError):
                workflow_records(*values)
        with self.assertRaises(ValueError):
            workflow_records(*reports(evidence()), expected_kernel="sbox-pair-v1")
        with self.assertRaises(ValueError):
            workflow_records(None, {}, {})

    def test_component_comparison_can_validate_each_actual_selection(self):
        # Deliberate component alternation uses each row's actual selection.
        # The enclosing guard separately checks complete pairs/counts and keeps
        # these timings separate from complete-workflow qualification.
        for kernel in ("baseline", "sbox-pair-v1", "sbox-pair-v1", "baseline"):
            row = {"selection": kernel, "public_hash": evidence(kernel)}
            self.assertEqual(
                validate_record(row["public_hash"], expected_kernel=row["selection"]),
                row["public_hash"],
            )
        with self.assertRaises(ValueError):
            validate_record(evidence("baseline"), expected_kernel="sbox-pair-v1")


if __name__ == "__main__":
    unittest.main()
