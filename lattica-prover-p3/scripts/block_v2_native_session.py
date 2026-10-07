"""Opt-in incremental native state; published history remains authoritative.

Restart, reorg, changed artifacts, or a failed native call discards the cache.
The legacy complete replay ABI remains the differential verification oracle.
"""
import copy
import ctypes
import struct
import threading
import block_v2_host_store as H


class NativeSessionVerifier(H.NativeVerifier):
    max_genesis_bytes = 64 * 1024 * 1024

    def __init__(self, *args, history_limit=4096, workload_fixture="delivery-v1"):
        if type(history_limit) is not int or not 1 <= history_limit <= 1_000_000:
            raise ValueError('invalid declared native history limit')
        if workload_fixture not in ('delivery-v1', 'sustained-v2'):
            raise ValueError('unknown native workload fixture')
        super().__init__(*args)
        self.wallet_slot_limit = 16384 if workload_fixture == 'sustained-v2' else 2048
        self.history_limit = history_limit
        self.configuration = {**self.configuration, 'verifier': 'native-session-v2', 'history_limit': history_limit, 'workload_fixture': workload_fixture}
        self.identity = {**self.identity, 'kind': 'native-session-v2'}
        self._session_mutex = threading.RLock()
        self._handle, self._record_ids, self._states = 0, [], []
        signatures = {
            'open': [ctypes.c_void_p, ctypes.c_size_t] * 3 + [ctypes.POINTER(ctypes.c_uint64)],
            'close': [ctypes.c_uint64],
            'state': [ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t],
            'apply': [ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t],
            'preflight': [ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint64,
                          ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t,
                          ctypes.POINTER(ctypes.c_size_t)],
            'wallet': [ctypes.c_uint64, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t,
                       ctypes.POINTER(ctypes.c_size_t)],
        }
        self._session_calls = {}
        for name, types in signatures.items():
            try:
                symbol = 'sustained_wallet' if name == 'wallet' and workload_fixture == 'sustained-v2' else name
                call = getattr(self._lib, f'lattica_v2_research_session_{symbol}_v2')
            except AttributeError as error:
                raise H.HostStoreError('native bridge lacks incremental session ABI') from error
            call.argtypes, call.restype = types, ctypes.c_int32
            self._session_calls[name] = call

    def close(self):
        with self._session_mutex:
            handle, self._handle = self._handle, 0
            self._record_ids, self._states = [], []
            if handle and self._session_calls['close'](handle) != 0:
                raise H.HostStoreError('native session close failed')

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def _open(self):
        buffers = [ctypes.create_string_buffer(data) for data in (self._registry, self._context, self._genesis)]
        args = [value for buffer in buffers for value in (buffer, len(buffer) - 1)]
        handle = ctypes.c_uint64()
        if self._session_calls['open'](*args, ctypes.byref(handle)) != 0 or not handle.value:
            raise H.RejectedBlock('native session initialization rejected')
        self._handle = handle.value
        output = ctypes.create_string_buffer(H.STATE_BYTES)
        if self._session_calls['state'](self._handle, output, len(output)) != 0:
            raise H.RejectedBlock('native initial state unavailable')
        self._states = [self._decode_state(output.raw, 0, struct.unpack_from('<Q', self._genesis, 8)[0])]

    @staticmethod
    def _decode_state(row, blocks, height):
        if len(row) != H.STATE_BYTES or row[:8] != b'LBV2ST01':
            raise H.RejectedBlock('native session state encoding')
        counters = struct.unpack_from('<QQQQQ', row, 168)
        supply = [int.from_bytes(row[start:start + 16], 'little') for start in range(104, 168, 16)]
        if counters[3:] != (blocks, height) or supply[0] - supply[1] != supply[2] + supply[3]:
            raise H.RejectedBlock('native session state invariant')
        return {'state_root': row[8:40].hex(), 'event_root': row[40:72].hex(), 'anchor': row[72:104].hex(),
                'supply': dict(zip(('issued', 'burned', 'shielded_pool', 'fees_paid'), map(str, supply))),
                'nullifiers': counters[0], 'outputs': counters[1], 'events': counters[2],
                'blocks': counters[3], 'height': counters[4]}

    def replay(self, candidates):
        if len(candidates) > self.history_limit:
            raise H.RejectedBlock('declared native history limit exceeded')
        with self._session_mutex:
            try:
                ids = []
                for candidate in candidates:
                    candidate.validate()
                    ids.append(H.sha(struct.pack('<Q', candidate.height) +
                                     bytes.fromhex(H.sha(candidate.body)) + bytes.fromhex(H.sha(candidate.proof))))
                if len(ids) < len(self._record_ids) or ids[:len(self._record_ids)] != self._record_ids:
                    self.close()
                if not self._handle:
                    self._open()
                for index in range(len(self._record_ids), len(candidates)):
                    candidate = candidates[index]
                    packet = self._history_inputs([candidate])[-1]
                    output = ctypes.create_string_buffer(H.STATE_BYTES)
                    if self._session_calls['apply'](self._handle, packet, len(packet) - 1, output, len(output)) != 0:
                        raise H.RejectedBlock(f'native incremental application rejected at record {index}')
                    self._states.append(self._decode_state(output.raw, index + 1, candidate.height))
                    self._record_ids.append(ids[index])
                return copy.deepcopy(self._states)
            except Exception:
                self.close()
                raise

    def _preflight(self, candidates, complete_body, height, grants):
        count = H.body_count(complete_body)
        if type(height) is not int or not 0 <= height < 1 << 52 or len(candidates) >= self.history_limit:
            raise H.RejectedBlock('invalid native candidate height/history')
        with self._session_mutex:
            self.replay(candidates)
            body = ctypes.create_string_buffer(complete_body)
            grant_bytes = struct.pack('<' + 'Q' * count, *grants)
            encoded_grants = ctypes.create_string_buffer(grant_bytes)
            output = ctypes.create_string_buffer(8 + 112 + 64 * (2 + 31 * 8))
            length = ctypes.c_size_t()
            if (self._session_calls['preflight'](self._handle, body, len(complete_body), height,
                    encoded_grants, len(grant_bytes), output, len(output), ctypes.byref(length)) != 0
                    or not 120 <= length.value <= len(output)):
                raise H.RejectedBlock('native incremental preflight rejected')
            return self._decode_preflight(output.raw[:length.value], count, height, grants)

    def prepare_wallet(self, candidates, index):
        if type(index) is not int or not 0 <= index < self.wallet_slot_limit or len(candidates) >= self.history_limit:
            raise H.RejectedBlock('invalid delivery slot or declared history limit')
        with self._session_mutex:
            self.replay(candidates)
            output = ctypes.create_string_buffer(16 + 186252 + 2 * 1024 * 1024 + 264)
            length = ctypes.c_size_t()
            if (self._session_calls['wallet'](self._handle, index, output, len(output), ctypes.byref(length)) != 0
                    or not 16 <= length.value <= len(output)):
                raise H.RejectedBlock(f'native incremental wallet generation rejected: slot {index}')
            return output.raw[:length.value]
