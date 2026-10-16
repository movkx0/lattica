"""Independent, read-only native replay of a bounded journal.

The versioned audit ABI reconstructs native state from the trusted genesis and
verifies one complete body/root at a time. No session cache or journal state
summary supplies proof authority. This does not publish, repair, resume, or
confirm durability of a journal, and it starts no proving work.
"""

import base64
import ctypes
import dataclasses
import fcntl
import os
import stat
import struct

import block_v2_host_store as H

MAX_AUDIT_BLOCKS = 4096
READER = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, ctypes.c_uint32,
                         ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t))
RECORD_KEYS = {'schema', 'configuration_sha256', 'parent', 'height', 'body',
               'body_sha256', 'proof', 'proof_sha256', 'state', 'verified_by'}
HEAD_KEYS = {'schema', 'configuration_sha256', 'tip', 'state', 'generation', 'verified_by'}


class NativeReplayAuditor:
    def __init__(self, verifier, *, history_limit=None):
        declared = getattr(verifier, 'history_limit', H.MAX_BLOCKS)
        limit = declared if history_limit is None else history_limit
        if type(limit) is not int or not 1 <= limit <= min(declared, MAX_AUDIT_BLOCKS):
            raise ValueError('audit history limit must fit the trusted host limit and 1..4096')
        self.verifier, self.history_limit = verifier, limit
        try:
            self._audit = verifier._lib.lattica_v2_research_host_audit_v2
        except AttributeError as error:
            raise H.HostStoreError('native bridge lacks the streaming audit ABI') from error
        self._audit.argtypes = ([ctypes.c_void_p, ctypes.c_size_t] * 3 +
                               [ctypes.c_uint32, READER, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t])
        self._audit.restype = ctypes.c_int32

    def replay(self, count, provider):
        """Read each indexed candidate once; retain only native state summaries."""
        if type(count) is not int or not 0 <= count <= self.history_limit:
            raise H.RejectedBlock('declared audit history limit exceeded')
        verifier = self.verifier
        initial_height = struct.unpack_from('<Q', verifier._genesis, 8)[0]
        failure, visited = [], []

        def read_record(_context, index, output, capacity, written):
            try:
                if failure or index != len(visited) or index >= count or not output or not written:
                    raise H.RejectedBlock('native auditor requested an invalid record index or buffer')
                written[0] = 0
                candidate = provider(index)
                if not isinstance(candidate, H.Candidate):
                    raise H.RejectedBlock('audit provider returned an invalid candidate')
                candidate.validate()
                if candidate.height != initial_height + index + 1:
                    raise H.RejectedBlock('audit history heights are not contiguous')
                transactions = H.body_count(candidate.body)
                grants = verifier._policy.for_block(candidate.height, transactions)
                packet = (b'LBV2RP01' + struct.pack('<IQIQI', 1, candidate.height,
                          len(candidate.body), len(candidate.proof), transactions) +
                          struct.pack('<' + 'Q' * transactions, *grants) + candidate.body + candidate.proof)
                if len(packet) > capacity:
                    raise H.RejectedBlock('audit record exceeds the native buffer bound')
                ctypes.memmove(output, packet, len(packet))
                written[0] = len(packet)
                visited.append(index)
                return 0
            except BaseException as error:
                # Python exceptions must not escape across a C callback boundary.
                failure.append(error)
                return -1

        callback = READER(read_record)
        buffers = [ctypes.create_string_buffer(data) for data in
                   (verifier._registry, verifier._context, verifier._genesis)]
        args = [item for buffer in buffers for item in (buffer, len(buffer) - 1)]
        output = ctypes.create_string_buffer((count + 1) * H.STATE_BYTES)
        code = self._audit(*args, count, callback, None, output, len(output))
        if failure:
            raise H.RejectedBlock('audit record provider rejected the history') from failure[0]
        if code != 0 or len(visited) != count:
            raise H.RejectedBlock(f'native streaming audit rejected the history (status {code})')
        states, encoded = [], output.raw
        for index in range(count + 1):
            row = encoded[index * H.STATE_BYTES:(index + 1) * H.STATE_BYTES]
            if row[:8] != b'LBV2ST01':
                raise H.RejectedBlock('native audit state encoding')
            counters = struct.unpack_from('<QQQQQ', row, 168)
            supply = [int.from_bytes(row[start:start + 16], 'little') for start in range(104, 168, 16)]
            if counters[3:] != (index, initial_height + index) or supply[0] - supply[1] != supply[2] + supply[3]:
                raise H.RejectedBlock('native audit state invariant')
            states.append({'state_root': row[8:40].hex(), 'event_root': row[40:72].hex(), 'anchor': row[72:104].hex(),
                           'supply': dict(zip(('issued', 'burned', 'shielded_pool', 'fees_paid'), map(str, supply))),
                           'nullifiers': counters[0], 'outputs': counters[1], 'events': counters[2],
                           'blocks': counters[3], 'height': counters[4]})
        return states

    def audit_journal(self, directory):
        """Verify a locked published branch without retaining its proof bodies.

        The first pass retains only record hashes, heights and state digests.
        Each record is read and authenticated again when native replay needs it.
        The shared lock excludes cooperative publishers; a final HEAD/config
        comparison also rejects a publisher that ignores the lock.
        """
        store = H.Store(directory, self.verifier)
        descriptor = os.open(store.directory / '.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise H.CorruptStore('invalid audit lock file')
            fcntl.flock(descriptor, fcntl.LOCK_SH)
            return self._locked_journal(store)
        finally:
            os.close(descriptor)

    def _locked_journal(self, store):
        configuration = store._read_file(store.directory / 'configuration.json', 16384)
        if configuration != store._configuration:
            raise H.CorruptStore('audit configuration differs from trusted host inputs')
        raw = store._read_file(store.directory / 'HEAD.json', 16384)
        head = H._json(raw)
        if (not isinstance(head, dict) or set(head) != HEAD_KEYS or head['schema'] != H.SCHEMA or
                head['configuration_sha256'] != store._configuration_sha or not isinstance(head['state'], dict) or
                type(head['generation']) is not int or not 0 <= head['generation'] < 2**64):
            raise H.CorruptStore('invalid audit journal head')

        def record(tip):
            H._digest(tip)
            data = store._read_file(store.directory / 'records' / (tip + '.json'), H.MAX_RECORD_BYTES)
            if H.sha(data) != tip:
                raise H.CorruptStore('audit record hash mismatch')
            row = H._json(data)
            if (not isinstance(row, dict) or set(row) != RECORD_KEYS or row['schema'] != H.SCHEMA or
                    row['configuration_sha256'] != store._configuration_sha or not isinstance(row['state'], dict) or
                    type(row['height']) is not int or not 0 < row['height'] < 2**52):
                raise H.CorruptStore('invalid audit journal record')
            if row['parent'] is not None:
                H._digest(row['parent'])
            return row

        tip, seen, records = head['tip'], set(), []
        while tip is not None:
            H._digest(tip)
            if tip in seen or len(records) == self.history_limit:
                raise H.CorruptStore('cyclic or oversized audit history')
            seen.add(tip)
            row = record(tip)
            records.append((tip, row['height'], H.sha(H.canonical(row['state']))))
            tip = row['parent']
            del row
        records.reverse()

        def provider(index):
            digest, height, state_digest = records[index]
            row = record(digest)
            try:
                body = base64.b64decode(row['body'], validate=True)
                proof = base64.b64decode(row['proof'], validate=True)
            except (ValueError, TypeError) as error:
                raise H.CorruptStore('invalid audit body/proof encoding') from error
            candidate = H.Candidate(row['height'], body, proof)
            candidate.validate()
            if (candidate.height != height or H.sha(body) != row['body_sha256'] or H.sha(proof) != row['proof_sha256'] or
                    H.sha(H.canonical(row['state'])) != state_digest):
                raise H.CorruptStore('audit body/proof/state identity changed')
            return candidate

        states = self.replay(len(records), provider)
        for index, (_, height, state_digest) in enumerate(records, 1):
            if states[index]['height'] != height or H.sha(H.canonical(states[index])) != state_digest:
                raise H.CorruptStore('recorded state differs from independently audited application')
        if states[-1] != head['state']:
            raise H.CorruptStore('head state differs from independently audited application')
        if (store._read_file(store.directory / 'HEAD.json', 16384) != raw or
                store._read_file(store.directory / 'configuration.json', 16384) != configuration):
            raise H.StaleHead('published head or configuration changed during the audit')
        return {'schema': 'lattica-native-streaming-audit-v2', 'status': 'passed',
                'head': dataclasses.asdict(H.View(H.sha(raw), head['tip'], states[-1], head['generation'], False)),
                'states': states, 'record_digests': [item[0] for item in records],
                'native_verifier': self.verifier.identity, 'verified_history_blocks': len(records),
                'read_only': True, 'durability_confirmed': False,
                'prover_jobs_started': 0, 'native_blocks_applied': 0, 'journal_resumed': False}
