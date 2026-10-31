"""Negative evidence checks; these unit fixtures do not prove or verify a relation."""
import copy
import unittest
import identity_screen_report as audit

HASH='bounded_gpu_program_identity fields=4096 batches=1 device_ns=7 uploaded_bytes=32768 downloaded_bytes=32'
MISS='bounded_gpu_program_identity_reuse hit=false hint_present=false fields=4096 receipt_bytes=112 full_stream_checked=true'
HIT='bounded_gpu_program_identity_reuse hit=true fields=4096 receipt_bytes=112 full_stream_checked=true'


class IdentityEvidenceTests(unittest.TestCase):
    def test_exact_counts_and_order_distinguish_modes(self):
        cold=audit.identity_markers('\n'.join([HASH,MISS,HASH,MISS]),'baseline')
        warm=audit.identity_markers('\n'.join([HASH,MISS,HIT]),'receipt-v1')
        self.assertEqual((cold['full_gpu_identity_hashes'],cold['identity_receipt_hits']), (2,0))
        self.assertEqual((warm['full_gpu_identity_hashes'],warm['identity_receipt_hits']), (1,1))
        self.assertEqual(cold['raw_hash_device_ns'],14)
        self.assertEqual(warm['raw_hash_device_ns'],7)

    def test_missing_reordered_duplicate_and_retry_markers_refuse(self):
        for lines in ([HASH,MISS], [HASH,HIT,MISS], [HASH,MISS,HIT,HIT],
                      [HASH,MISS,HASH,MISS], [HASH,MISS,HIT,HASH],
                      [HASH,MISS.replace('hint_present=false','hint_present=true'),HIT]):
            with self.subTest(lines=lines),self.assertRaises(ValueError):
                audit.identity_markers('\n'.join(lines),'receipt-v1')

    def test_incomplete_stream_or_changed_receipt_refuses(self):
        for hit in (HIT.replace('4096','4095'),HIT.replace('112','113'),
                    HIT.replace('full_stream_checked=true','full_stream_checked=false'),
                    HIT+' fields=4096',HIT+' unexpected=1'):
            with self.subTest(hit=hit),self.assertRaises(ValueError):
                audit.identity_markers('\n'.join([HASH,MISS,hit]),'receipt-v1')
        for changed in (HASH.replace('device_ns=7','device_ns=0'),HASH+' unknown=1',HASH.replace('fields=4096','fields=true')):
            with self.assertRaises(ValueError):audit.identity_markers('\n'.join([changed,MISS,HIT]),'receipt-v1')

    def test_identity_and_orchestration_fit_each_actual_caller_reservation(self):
        screen={'source_identity_host_bytes':4096}
        fits={'caller_requested_bytes':4096+(32<<10)}
        audit.caller_identity_charge(screen,fits,fits)
        for bad in (1,4096,4096+(32<<10)-1,(1<<20)+1,True):
            with self.assertRaises(ValueError):
                audit.caller_identity_charge(screen,dict(caller_requested_bytes=bad),fits)
            with self.assertRaises(ValueError):
                audit.caller_identity_charge(screen,fits,dict(caller_requested_bytes=bad))

    def test_bare_or_unknown_identity_markers_cannot_be_ignored(self):
        for extra in ('bounded_gpu_program_identity','bounded_gpu_program_identity_reuse','bounded_gpu_program_identity_extra fields=4096'):
            with self.assertRaises(ValueError):
                audit.identity_markers('\n'.join([HASH,MISS,HIT,extra]),'receipt-v1')

    def fixture(self):
        public={'kernel':'baseline','gpu_tuning_compiled':False,'nvidia_supported':True}
        case={'identity_reuse_profile':audit.PROFILE,'public_hash':public,'descriptor':{'registered_program_id':[1,2,3,4]}}
        proving={'public_hash':public}
        reuse={key:True for key in 'identity_hint_hit full_identity_stream_checked public_preprocessing_reused fresh_preprocessing_cap prover_session_retired_before_verifier_start expected_statement_reconstructed'.split()}
        reuse.update({key:False for key in ('prepared_program_reused','proof_reused','fresh_identity_gpu_hash')})
        reuse.update(profile=audit.PROFILE,reused_part='protocol-program-identity-only',lookup_digest='sha3-512-over-complete-canonical-identity-stream-v1',receipt_payload_bytes=112,source_admitted_host_bytes=4096,receipt_sublimit_bytes=1<<20,combined_metadata_limit_bytes=64<<20,idle_device_bytes=0,receipt_retained_after_setup_bytes=0,reuse_distance_registrations=0,receipt_lifetime_ns=1,registered_program_id=[1,2,3,4],source_public_hash=public,verifier_fresh_public_hash=None)
        return case,proving,dict(public_hash=None,identity_reuse=reuse)

    def test_receipt_rejects_present_fresh_hash_even_equal_to_source(self):
        case,proving,verification=self.fixture()
        # Both fields agree, so a consistency-only check would accept the
        # original bug. A new session must have no fresh hash observation.
        verification['public_hash']=copy.deepcopy(proving['public_hash'])
        verification['identity_reuse']['verifier_fresh_public_hash']=copy.deepcopy(proving['public_hash'])
        with self.assertRaises(ValueError):
            audit.audit_identity_provenance(case,proving,verification,'receipt-v1')

    def test_actual_hit_preserves_cached_and_fresh_provenance_separately(self):
        case,proving,verification=self.fixture()
        audit.audit_identity_provenance(case,proving,verification,'receipt-v1')
        for key,value in [('identity_hint_hit',False),('full_identity_stream_checked',False),
                          ('fresh_identity_gpu_hash',True),('prepared_program_reused',True),
                          ('prover_session_retired_before_verifier_start',False),
                          ('idle_device_bytes',1),('receipt_retained_after_setup_bytes',112),
                          ('source_admitted_host_bytes',1<<20),('registered_program_id',[4,3,2,1]),
                          ('verifier_fresh_public_hash',proving['public_hash'])]:
            changed=copy.deepcopy(verification);changed['identity_reuse'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                audit.audit_identity_provenance(case,proving,changed,'receipt-v1')
        with self.assertRaises(ValueError):audit.audit_identity_provenance(case,proving,verification,'baseline')
        del verification['public_hash']
        with self.assertRaises(ValueError):audit.audit_identity_provenance(case,proving,verification,'receipt-v1')


if __name__=='__main__':unittest.main()
