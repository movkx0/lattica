"""Generator provenance and reproduction checks using synthetic evidence only."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import generate_metadata_tables as generator
from test_metadata_cpu_qualification import MetadataQualificationTests

class GeneratedTablesTests(unittest.TestCase):
    def fixture(self, root):
        counts, rows = MetadataQualificationTests().fixture()
        log = root / 'qual.log'
        log.write_text(MetadataQualificationTests.content(counts, rows))
        sources = {'lattica-prover-p3/src/block_v2/machine/a.rs': 'a', 'lattica-prover-p3/Cargo.lock': 'b',
                   generator.DESTINATION: 'old'}
        build = root / 'build.json'
        build.write_text(json.dumps(dict(status='passed', input_sha256=sources)))
        data = dict(status='passed', profile='research-compile-large', source_inputs_unchanged=True,
                    executable_unchanged=True, all_subprocesses_terminal_and_reaped=True,
                    service_stop_completed=True, expect_tests=True, input_sha256=sources,
                    command=['/tmp/binary', generator.TEST, '--exact', '--ignored', '--test-threads=1', '--nocapture'],
                    raw_log=str(log), raw_log_sha256=generator.sha(log),
                    executable_provenance=dict(build_record=str(build), build_record_sha256=generator.sha(build)))
        record = root / 'qual.json'
        record.write_text(json.dumps(data))
        return sources, data, record, log

    def test_generator_requires_terminal_source_matched_qualification(self):
        with tempfile.TemporaryDirectory() as directory:
            sources, data, record, log = self.fixture(Path(directory))
            with patch.object(generator, 'source_manifest', return_value=sources):
                tables = generator.verified(record)
                rendered = generator.render(tables)
                self.assertEqual(rendered.count('Row {'), 72)
                self.assertEqual(rendered, generator.render(tables))
                for key, value in [('status', 'starting'), ('source_inputs_unchanged', False),
                                   ('all_subprocesses_terminal_and_reaped', False), ('raw_log_sha256', 'bad')]:
                    bad = copy.deepcopy(data); bad[key] = value
                    record.write_text(json.dumps(bad))
                    with self.assertRaises(ValueError): generator.verified(record)
                record.write_text(json.dumps(data))
                log.write_text(log.read_text() + '\ntampered')
                with self.assertRaises(ValueError): generator.verified(record)

    def test_source_additions_deletions_and_changes_refuse_but_generated_file_can_change(self):
        with tempfile.TemporaryDirectory() as directory:
            sources, data, record, log = self.fixture(Path(directory))
            for current in [dict(sources, **{'lattica-prover-p3/src/block_v2/machine/a.rs': 'changed'}),
                            dict(sources, **{'lattica-prover-p3/src/block_v2/machine/new.rs': 'new'}),
                            {k: v for k, v in sources.items() if k != 'lattica-prover-p3/src/block_v2/machine/a.rs'}]:
                with patch.object(generator, 'source_manifest', return_value=current):
                    with self.assertRaises(ValueError): generator.verified(record)
            current = dict(sources); current[generator.DESTINATION] = 'generated'
            with patch.object(generator, 'source_manifest', return_value=current):
                self.assertEqual(len(generator.verified(record)['rows']), 72)
