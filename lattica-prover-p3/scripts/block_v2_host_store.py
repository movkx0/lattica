"""Local research journal backed by complete native transaction replay.

The host supplies registry, context, genesis and issuance policy independently.
Immutable records are synced before an atomic, synced head publication. Recovery
replays only the published branch; reorgs replay the selected prefix and suffix.
This intentionally bounded prototype replays history on each commit. Its cost
belongs in measured host finalization, and it is not production activation.
"""

from contextlib import contextmanager
import base64
import ctypes
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import tempfile
import threading

MAX_BLOCKS = 128
MAX_BODY_BYTES = 256 * 1024
MAX_PROOF_BYTES = 2 * 1024 * 1024
MAX_RECORD_BYTES = 4 * (MAX_BODY_BYTES + MAX_PROOF_BYTES) // 3 + 16 * 1024
STATE_BYTES = 208
HEX = re.compile(r'[0-9a-f]{64}')
SCHEMA = 'lattica-research-host-journal-v1'


class HostStoreError(RuntimeError):
    pass


class CorruptStore(HostStoreError):
    pass


class RejectedBlock(HostStoreError):
    pass


class StaleHead(HostStoreError):
    pass


class CommitIndeterminate(HostStoreError):
    """Head replacement occurred but durable publication was not confirmed.

    Reopen/replay the store before deciding whether to resubmit. Never count
    this exception as delivered throughput or assume the old head remains.
    """


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CorruptStore('duplicate JSON field')
        result[key] = value
    return result


def _json(data):
    try:
        value = json.loads(data, object_pairs_hook=_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError('non-finite JSON')))
        if canonical(value) != data:
            raise CorruptStore('noncanonical journal encoding')
        return value
    except (ValueError, TypeError, UnicodeError) as error:
        raise CorruptStore('invalid journal JSON') from error


def _digest(value):
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise CorruptStore('invalid record digest')
    return value


def body_count(body):
    if type(body) is not bytes or not 12 <= len(body) <= MAX_BODY_BYTES or body[:8] != b'LBV2BD01':
        raise RejectedBlock('complete public body encoding required')
    count = struct.unpack_from('<I', body, 8)[0]
    if not 1 <= count <= 64:
        raise RejectedBlock('invalid complete-body count')
    return count


@dataclass(frozen=True)
class Candidate:
    height: int
    body: bytes
    proof: bytes

    def validate(self):
        if type(self.height) is not int or not 0 < self.height < 2**52:
            raise RejectedBlock('invalid host height')
        body_count(self.body)
        if type(self.proof) is not bytes or not 0 < len(self.proof) <= MAX_PROOF_BYTES:
            raise RejectedBlock('invalid root proof size')


class IssuancePolicy:
    """A pinned host grant table, never read from a proposed block/journal."""

    def __init__(self, grants):
        normalized = {}
        for height, row in grants.items():
            if type(height) is not int or not 0 < height < 2**52 or not isinstance(row, dict):
                raise ValueError('invalid grant height')
            normalized[height] = {}
            for index, amount in row.items():
                if (type(index) is not int or not 0 <= index < 64 or
                        type(amount) is not int or not 0 < amount < 2**52):
                    raise ValueError('invalid issuance grant')
                normalized[height][index] = amount
        self._grants = normalized
        self.sha256 = sha(canonical({str(h): {str(i): n for i, n in row.items()}
                                    for h, row in normalized.items()}))

    def for_block(self, height, count):
        row = self._grants.get(height, {})
        if any(index >= count for index in row):
            raise RejectedBlock('body omits a transaction with a required host grant')
        return self.for_prefix(height, count)

    def for_prefix(self, height, count):
        """Planning only: grants for occupied slots, without waiving later slots."""
        if type(count) is not int or not 1 <= count <= 64:
            raise RejectedBlock('invalid candidate prefix count')
        row = self._grants.get(height, {})
        return tuple(row.get(index, 0) for index in range(count))


class NativeVerifier:
    """Calls the linked Zig node / Rust CPU verifier; has no stub fallback."""

    _lock = threading.Lock()
    _libraries = {}
    max_genesis_bytes = 8 * 1024 * 1024
    wallet_slot_limit = 2048

    def __init__(self, library, registry, profile_id, chain_id, genesis, policy):
        if (type(registry) is not bytes or not registry.startswith(b'LBV2RG01') or len(registry) > 65536
                or type(profile_id) is not bytes or len(profile_id) != 32
                or type(chain_id) is not bytes or len(chain_id) != 32
                or type(genesis) is not bytes or not 68 <= len(genesis) <= self.max_genesis_bytes
                or not genesis.startswith(b'LBV2GN01') or not isinstance(policy, IssuancePolicy)):
            raise ValueError('invalid independently supplied host configuration')
        library = Path(library).resolve(strict=True)
        library_sha = sha(library.read_bytes())
        with self._lock:
            prior = self._libraries.get(str(library))
            if prior is not None and prior[0] != library_sha:
                raise HostStoreError('loaded library path changed; use a new frozen path or restart')
            if prior is None:
                loaded = ctypes.CDLL(str(library))
                if sha(library.read_bytes()) != library_sha:
                    raise HostStoreError('native library changed while loading')
                loaded.lattica_v2_research_host_initialize_v1.argtypes = []
                loaded.lattica_v2_research_host_initialize_v1.restype = None
                loaded.lattica_v2_research_host_initialize_v1()
                self._libraries[str(library)] = (library_sha, loaded)
            self._lib = self._libraries[str(library)][1]
        self._call = self._lib.lattica_v2_research_host_replay_v1
        self._call.argtypes = [ctypes.c_void_p, ctypes.c_size_t] * 5
        self._call.restype = ctypes.c_int32
        self._registry, self._context, self._genesis = registry, profile_id + chain_id, genesis
        self._policy = policy
        self.configuration = {'schema': 'lattica-research-trusted-host-inputs-v1',
                              'verifier': 'native-root-replay-v1', 'registry_sha256': sha(registry),
                              'profile_id': profile_id.hex(), 'chain_id': chain_id.hex(),
                              'genesis_sha256': sha(genesis), 'issuance_policy_sha256': policy.sha256}
        self.identity = {'kind': 'native-root-replay-v1', 'library_path': str(library),
                         'library_sha256': library_sha}

    def _history_inputs(self, candidates):
        if len(candidates) > MAX_BLOCKS:
            raise RejectedBlock('research replay history limit exceeded')
        stream = bytearray(b'LBV2RP01' + struct.pack('<I', len(candidates)))
        for candidate in candidates:
            candidate.validate()
            count = body_count(candidate.body)
            grants = self._policy.for_block(candidate.height, count)
            stream.extend(struct.pack('<QIQI', candidate.height, len(candidate.body), len(candidate.proof), count))
            stream.extend(struct.pack('<' + 'Q' * count, *grants))
            stream.extend(candidate.body)
            stream.extend(candidate.proof)
        return [ctypes.create_string_buffer(data) for data in
                (self._registry, self._context, self._genesis, bytes(stream))]

    def preflight(self, candidates, complete_body, height):
        return self._preflight(candidates, complete_body, height,
                               self._policy.for_block(height, body_count(complete_body)))

    def preflight_prefix(self, candidates, complete_body, height):
        """Screen a prefix for selection; full preflight still requires every grant."""
        return self._preflight(candidates, complete_body, height,
                               self._policy.for_prefix(height, body_count(complete_body)))

    def _preflight(self, candidates, complete_body, height, grants):
        """Validate native state/policy and export body-derived public statements.

        Candidate authentication is still required. The CPU probe verifies each
        wallet proof against these statements before any GPU work is dispatched.
        """
        import struct
        count = body_count(complete_body)
        if type(height) is not int or not 0 <= height < 1 << 64 or len(candidates) >= MAX_BLOCKS:
            raise RejectedBlock('invalid native candidate height')
        buffers = self._history_inputs(candidates)
        args = []
        for buffer in buffers:
            args.extend((buffer, len(buffer) - 1))
        body_buffer = ctypes.create_string_buffer(complete_body)
        grant_bytes = struct.pack('<' + 'Q' * count, *grants)
        grant_buffer = ctypes.create_string_buffer(grant_bytes)
        try:
            call = self._lib.lattica_v2_research_candidate_preflight_v1
        except AttributeError as error:
            raise RejectedBlock('native library lacks candidate preflight support') from error
        call.argtypes = [ctypes.c_void_p, ctypes.c_size_t] * 5 + [
            ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t,
            ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        call.restype = ctypes.c_int32
        output = ctypes.create_string_buffer(8 + 112 + 64 * (2 + 31 * 8))
        length = ctypes.c_size_t()
        args.extend((body_buffer, len(complete_body), height, grant_buffer, len(grant_bytes),
                     output, len(output), ctypes.byref(length)))
        if call(*args) != 0 or not 120 <= length.value <= len(output):
            raise RejectedBlock('native candidate state or issuance policy rejected')
        return self._decode_preflight(output.raw[:length.value], count, height, grants)

    def _decode_preflight(self, packet, count, height, grants):
        import struct
        expected = packet[8:120]
        if (packet[:8] != b'LBV2PF01' or len(expected) != 112 or expected[:8] != b'LBV2EX01'
                or expected[8:72] != self._context or int.from_bytes(expected[104:112], 'little') != count):
            raise RejectedBlock('native preflight context or count differs')
        kinds = ('joinsplit', 'htlc_redeem', 'htlc_refund', 'issuance')
        statements, offset = [], 120
        for _ in range(count):
            if offset + 2 > len(packet):
                raise RejectedBlock('truncated native public statement')
            kind, width = packet[offset:offset + 2]
            offset += 2
            if kind >= len(kinds) or width != (31 if kind in (1, 2) else 26) or offset + width * 8 > len(packet):
                raise RejectedBlock('invalid native public statement shape')
            values = list(struct.unpack_from('<' + 'Q' * width, packet, offset))
            if any(value >= 0xffff_ffff_0000_0001 for value in values):
                raise RejectedBlock('noncanonical native public statement')
            statements.append({'kind': kinds[kind], 'statement': values})
            offset += width * 8
        if offset != len(packet):
            raise RejectedBlock('trailing native preflight data')
        return {'expected': expected, 'height': height, 'grants': list(grants),
                'body': {'schema_version': 1, 'chain': list(self._context[32:]), 'transactions': statements}}

    def prepare_wallet(self, candidates, index):
        """Fresh synthetic leaf from verified history; caller fences the head."""
        if type(index) is not int or not 0 <= index < 2048 or len(candidates) >= MAX_BLOCKS:
            raise RejectedBlock('invalid delivery slot or exhausted history')
        inputs = self._history_inputs(candidates)
        call = self._lib.lattica_v2_research_delivery_wallet_v1
        call.argtypes = [ctypes.c_void_p, ctypes.c_size_t] * 4 + [
            ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        call.restype = ctypes.c_int32
        output = ctypes.create_string_buffer(16 + 186252 + 2 * 1024 * 1024 + 264)
        length = ctypes.c_size_t()
        args = []
        for buffer in inputs:
            args.extend((buffer, len(buffer) - 1))
        status = call(*args, index, output, len(output), ctypes.byref(length))
        if status != 0 or not 16 <= length.value <= len(output):
            raise RejectedBlock(f'native delivery wallet rejected slot/history (status {status})')
        return output.raw[:length.value]

    def replay(self, candidates):
        inputs = self._history_inputs(candidates)
        output = ctypes.create_string_buffer((len(candidates) + 1) * STATE_BYTES)
        args = []
        for buffer in inputs:
            args.extend((buffer, len(buffer) - 1))
        status = self._call(*args, output, len(output))
        if status != 0:
            raise RejectedBlock(f'native complete-body replay rejected the branch (status {status})')
        states = []
        for index in range(len(candidates) + 1):
            row = output.raw[index * STATE_BYTES:(index + 1) * STATE_BYTES]
            if row[:8] != b'LBV2ST01':
                raise RejectedBlock('native state summary version mismatch')
            counters = struct.unpack_from('<QQQQQ', row, 168)
            supply = [int.from_bytes(row[start:start + 16], 'little') for start in range(104, 168, 16)]
            expected_height = candidates[index - 1].height if index else struct.unpack_from('<Q', self._genesis, 8)[0]
            if (counters[3] != index or counters[4] != expected_height
                    or supply[0] - supply[1] != supply[2] + supply[3]):
                raise RejectedBlock('native state summary invariant mismatch')
            states.append({'state_root': row[8:40].hex(), 'event_root': row[40:72].hex(),
                           'anchor': row[72:104].hex(),
                           'supply': dict(zip(('issued', 'burned', 'shielded_pool', 'fees_paid'), map(str, supply))),
                           'nullifiers': counters[0], 'outputs': counters[1], 'events': counters[2],
                           'blocks': counters[3], 'height': counters[4]})
        return states


@dataclass(frozen=True)
class View:
    token: str
    tip: str | None
    state: dict
    generation: int
    durability_confirmed: bool = True


class Store:
    def __init__(self, directory, verifier, *, fault_hook=None):
        self.directory = Path(directory).resolve(strict=True)
        self.verifier = verifier
        self._configuration = canonical(verifier.configuration)
        self._configuration_sha = sha(self._configuration)
        self._fault_hook = fault_hook
        self._layout()

    def _layout(self):
        if not self.directory.is_dir():
            raise CorruptStore('host store is not a directory')
        records = self.directory / 'records'
        if not stat.S_ISDIR(records.lstat().st_mode):
            raise CorruptStore('record directory must be a real directory')

    def _fault(self, stage):
        if self._fault_hook is not None:
            self._fault_hook(stage)

    @staticmethod
    def _sync_dir(path):
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _read_file(path, limit):
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise CorruptStore('journal file is not regular or exceeds its bound')
            data = handle.read(limit + 1)
            if len(data) > limit:
                raise CorruptStore('journal file exceeds its bound')
            return data

    @contextmanager
    def _locked(self):
        self._layout()
        descriptor = os.open(self.directory / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise CorruptStore('invalid lock file')
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)

    def _immutable(self, path, data):
        descriptor, name = tempfile.mkstemp(prefix='.record-', dir=path.parent)
        try:
            with os.fdopen(descriptor, 'wb') as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            self._fault('record_file_synced')
            try:
                os.link(name, path, follow_symlinks=False)
            except FileExistsError:
                if self._read_file(path, max(len(data), MAX_RECORD_BYTES)) != data:
                    raise CorruptStore('immutable record collision')
                # A prior attempt may have linked this complete record before
                # directory sync failed. Confirm both syncs before publishing HEAD.
                existing = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    os.fsync(existing)
                finally:
                    os.close(existing)
            os.unlink(name)
            self._sync_dir(path.parent)
            self._fault('record_directory_synced')
        finally:
            try:
                os.unlink(name)
            except FileNotFoundError:
                pass

    def _publish(self, data):
        descriptor, name = tempfile.mkstemp(prefix='.head-', dir=self.directory)
        replaced = False
        try:
            with os.fdopen(descriptor, 'wb') as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            self._fault('head_file_synced')
            os.replace(name, self.directory / 'HEAD.json')
            replaced = True
            self._fault('head_replaced')
            self._sync_dir(self.directory)
            self._fault('head_directory_synced')
        except Exception as error:
            if replaced:
                raise CommitIndeterminate('head changed; reopen and replay before retrying') from error
            raise
        finally:
            try:
                os.unlink(name)
            except FileNotFoundError:
                pass

    @classmethod
    def create(cls, directory, verifier):
        states = verifier.replay([])
        if len(states) != 1 or states[0].get('blocks') != 0:
            raise RejectedBlock('invalid independently supplied genesis')
        directory = Path(directory)
        directory.mkdir(mode=0o700)
        (directory / 'records').mkdir(mode=0o700)
        store = cls(directory, verifier)
        with store._locked():
            store._immutable(store.directory / 'configuration.json', store._configuration)
            head = store._head(None, states[0], 0)
            data = canonical(head)
            store._publish(data)
            try:
                store._sync_dir(store.directory.parent)
            except Exception as error:
                raise CommitIndeterminate('new store directory durability is unconfirmed') from error
        return store

    def _head(self, tip, state, generation):
        return {'schema': SCHEMA, 'configuration_sha256': self._configuration_sha,
                'tip': tip, 'state': state, 'generation': generation,
                'verified_by': self.verifier.identity}

    def _history(self):
        try:
            if self._read_file(self.directory / 'configuration.json', 16384) != self._configuration:
                raise CorruptStore('store differs from independently selected host configuration')
            data = self._read_file(self.directory / 'HEAD.json', 16384)
            head = _json(data)
            if (set(head) != {'schema', 'configuration_sha256', 'tip', 'state', 'generation', 'verified_by'}
                    or head['schema'] != SCHEMA or head['configuration_sha256'] != self._configuration_sha
                    or type(head['generation']) is not int or not 0 <= head['generation'] < 2**64
                    or not isinstance(head['state'], dict)):
                raise CorruptStore('invalid journal head')
            tip, records, seen = head['tip'], [], set()
            while tip is not None:
                _digest(tip)
                if tip in seen or len(records) == getattr(self.verifier, 'history_limit', MAX_BLOCKS):
                    raise CorruptStore('cyclic or oversized journal history')
                seen.add(tip)
                raw = self._read_file(self.directory / 'records' / (tip + '.json'), MAX_RECORD_BYTES)
                if sha(raw) != tip:
                    raise CorruptStore('record hash mismatch')
                row = _json(raw)
                if (set(row) != {'schema', 'configuration_sha256', 'parent', 'height', 'body',
                                'body_sha256', 'proof', 'proof_sha256', 'state', 'verified_by'}
                        or row['schema'] != SCHEMA or row['configuration_sha256'] != self._configuration_sha):
                    raise CorruptStore('invalid immutable record')
                body = base64.b64decode(row['body'], validate=True)
                proof = base64.b64decode(row['proof'], validate=True)
                candidate = Candidate(row['height'], body, proof)
                candidate.validate()
                if sha(body) != row['body_sha256'] or sha(proof) != row['proof_sha256']:
                    raise CorruptStore('body/proof hash mismatch')
                records.append((tip, row, candidate))
                tip = row['parent']
            records.reverse()
            return data, head, records
        except (FileNotFoundError, ValueError, TypeError, KeyError, RejectedBlock) as error:
            raise CorruptStore('unreadable or malformed published history') from error

    @staticmethod
    def _check_states(records, states, head=None):
        if len(states) != len(records) + 1 or states[0].get('blocks') != 0:
            raise CorruptStore('native replay returned incomplete states')
        for index, (_, row, candidate) in enumerate(records, 1):
            if (row['state'] != states[index] or states[index].get('blocks') != index
                    or states[index].get('height') != candidate.height):
                raise CorruptStore('recorded state differs from verified native application')
        if head is not None and head['state'] != states[-1]:
            raise CorruptStore('head state differs from verified native application')

    def published_head_token(self):
        """Observe atomic head publication without replaying the chain.

        This is only a change detector. Snapshot and commit still verify native
        history and fence writes; this digest grants no validity authority.
        """
        return sha(self._read_file(self.directory / 'HEAD.json', 16384))

    def read(self):
        return self.snapshot()[0]

    def snapshot(self):
        # Immutable verified history can be proved outside the lock; the token
        # still fences eventual submission against concurrent writes/reorgs.
        """Recovery validates all published bodies/proofs, then confirms the head sync."""
        with self._locked():
            raw, head, records = self._history()
            states = self.verifier.replay([record[2] for record in records])
            self._check_states(records, states, head)
            descriptor = os.open(self.directory / 'HEAD.json', os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            self._sync_dir(self.directory)
            self._sync_dir(self.directory.parent)
            return (View(sha(raw), head['tip'], states[-1], head['generation']),
                    tuple(record[2] for record in records))

    def commit(self, candidate, *, expected_head):
        return self._replace([candidate], expected_head=expected_head, ancestor='current')

    def recover_application(self, candidate, *, expected_parent, expected_generation):
        """Confirm one exact published child without committing it again."""
        _digest(expected_parent)
        if type(expected_generation) is not int or not 0 <= expected_generation < 2**64 - 1:
            raise RejectedBlock('invalid recovery parent generation')
        candidate.validate()
        published, history = self.snapshot()
        if (not history or history[-1] != candidate
                or published.generation != expected_generation + 1):
            raise StaleHead('published head is not the exact application being recovered')
        parent_state = self.verifier.replay(history[:-1])[-1]
        with self._locked():
            raw, _, records = self._history()
            if sha(raw) != published.token:
                raise StaleHead('published head changed during application recovery')
            parent = self._head(records[-1][1]['parent'], parent_state, expected_generation)
            if sha(canonical(parent)) != expected_parent:
                raise StaleHead('published application has a different verified parent')
        return published, View(expected_parent, parent['tip'], parent_state, expected_generation)

    def reorganize(self, ancestor, candidates, *, expected_head):
        """Explicitly replace the canonical suffix; old immutable records remain retained."""
        if ancestor is not None:
            _digest(ancestor)
        return self._replace(list(candidates), expected_head=expected_head, ancestor=ancestor)

    def _replace(self, candidates, *, expected_head, ancestor):
        _digest(expected_head)
        with self._locked():
            raw, head, records = self._history()
            if sha(raw) != expected_head:
                raise StaleHead('published head changed; reload before submitting')
            if head['generation'] == 2**64 - 1:
                raise HostStoreError('journal generation exhausted')
            if ancestor != 'current':
                prior_states = self.verifier.replay([row[2] for row in records])
                self._check_states(records, prior_states, head)
            if ancestor == 'current':
                prefix = records
            elif ancestor is None:
                prefix = []
            else:
                index = next((i for i, row in enumerate(records) if row[0] == ancestor), None)
                if index is None:
                    raise StaleHead('reorg ancestor is not in the published branch')
                prefix = records[:index + 1]
            if len(prefix) + len(candidates) > getattr(self.verifier, 'history_limit', MAX_BLOCKS):
                raise RejectedBlock('research journal history limit exceeded')
            for candidate in candidates:
                candidate.validate()
            states = self.verifier.replay([row[2] for row in prefix] + candidates)
            self._check_states(prefix, states[:len(prefix) + 1])
            if len(states) != len(prefix) + len(candidates) + 1:
                raise RejectedBlock('native replay returned incomplete replacement states')
            if ancestor == 'current' and states[len(prefix)] != head['state']:
                raise CorruptStore('published parent differs from native replay')
            parent = prefix[-1][0] if prefix else None
            for index, candidate in enumerate(candidates, len(prefix) + 1):
                if states[index].get('blocks') != index or states[index].get('height') != candidate.height:
                    raise RejectedBlock('native replacement state metadata mismatch')
                row = {'schema': SCHEMA, 'configuration_sha256': self._configuration_sha,
                       'parent': parent, 'height': candidate.height,
                       'body': base64.b64encode(candidate.body).decode(), 'body_sha256': sha(candidate.body),
                       'proof': base64.b64encode(candidate.proof).decode(), 'proof_sha256': sha(candidate.proof),
                       'state': states[index], 'verified_by': self.verifier.identity}
                encoded = canonical(row)
                if len(encoded) > MAX_RECORD_BYTES:
                    raise RejectedBlock('encoded record exceeds storage bound')
                parent = sha(encoded)
                self._immutable(self.directory / 'records' / (parent + '.json'), encoded)
            new_head = self._head(parent, states[-1], head['generation'] + 1)
            encoded = canonical(new_head)
            self._publish(encoded)
            return View(sha(encoded), parent, states[-1], new_head['generation'])
