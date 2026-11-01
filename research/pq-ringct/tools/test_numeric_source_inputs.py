import unittest
from numeric_source_inputs import selected, select_receipt, MANIFEST

class NumericSourceInputsTests(unittest.TestCase):
    def test_protocol_compiler_and_new_helper_files_are_bound(self):
        for path in [MANIFEST, 'lattica-prover-p3/src/block_v2/machine/verifier/pcs.rs',
                     'lattica-prover-p3/src/block_v2/machine/new_helper.rs',
                     'lattica-prover-p3/src/block_v2/profile.rs',
                     'lattica-prover-p3/vendor/p3-field/src/field.rs', 'research/pq-ringct/Cargo.lock']:
            self.assertTrue(selected(path),path)
        for path in ['research/pq-ringct/src/ntt_air.rs',
                     'research/pq-ringct/src/ntt_air/new_helper.rs',
                     'research/pq-ringct/src/rust_verify/constants.rs',
                     'research/pq-ringct/src/component_tree/native_shape/key.rs']:
            self.assertTrue(selected(path,True),path)
            self.assertFalse(selected(path),path)

    def test_unrelated_execution_and_generated_rows_do_not_invalidate(self):
        for path in ['research/pq-ringct/src/spend_pipeline/full_workflow/driver/native_layers/compile.rs',
                     'research/pq-ringct/native/spend.c',
                     'lattica-prover-p3/src/block_v2/gpu_hash/engine/device/operations_arithmetic.cl',
                     'lattica-prover-p3/src/block_v2/machine/program/counting/tests.rs',
                     'research/pq-ringct/src/component_tree/native_shape/precomputed/data.rs',
                     'lattica-prover-p3/src/block_v2/machine/verifier/batch/shape/precomputed/data.rs']:
            self.assertFalse(selected(path,True),path)

    def test_reproduction_pins_tooling_as_well_as_numeric_inputs(self):
        tooling = 'research/pq-ringct/tools/generate_native_metadata_tables.py'
        source = 'research/pq-ringct/src/ntt_air.rs'
        driver = 'research/pq-ringct/src/spend_pipeline/full_workflow/driver/native_layers/compile.rs'
        original = {tooling:'a',source:'a',driver:'a'}
        self.assertEqual(select_receipt(original,True), select_receipt(dict(original, **{driver:'b'}),True))
        for path in [tooling,source]:
            self.assertNotEqual(select_receipt(original,True), select_receipt(dict(original, **{path:'b'}),True))
