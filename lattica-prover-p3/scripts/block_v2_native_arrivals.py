"""Bounded, durable intake for the native research host.

An intake receipt records unverified transaction bytes. Only a CPU-checked native
preparation may seal an ordered selection, and only independently replayed native
application may mark it applied. Late arrivals stay outside sealed selections.
This module does not dispatch GPU work or claim sustained transaction throughput.
"""

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import os
from pathlib import Path
import re
import sqlite3
import stat
import time

import block_v2_host_store as H

SCHEMA = 'lattica-native-arrivals-v1'
REQUEST_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}')


class IntakeError(RuntimeError):
    pass


class DuplicateTransaction(IntakeError):
    pass


class IntakeCommitIndeterminate(IntakeError):
    """Publication may have happened; reopen and inspect before retrying."""


@dataclass(frozen=True)
class Limits:
    arrivals: int
    payload_bytes: int
    database_bytes: int
    events: int

    def validate(self):
        if (any(type(v) is not int or v <= 0 for v in asdict(self).values())
                or self.arrivals > 4096 or self.events > 32768
                or self.database_bytes < 128 * 1024
                or self.database_bytes > 4 * 1024**3
                or self.payload_bytes >= self.database_bytes):
            raise ValueError('invalid bounded intake limits')


class Store:
    def __init__(self, directory, host, *, fault_hook=None):
        self.directory = Path(directory).absolute()
        self.host = host
        self.configuration = H.sha(H.canonical(host.verifier.configuration))
        self.fault_hook = fault_hook

    def _fault(self, stage):
        if self.fault_hook is not None:
            self.fault_hook(stage)

    @classmethod
    def create(cls, directory, host, limits):
        limits.validate()
        store = cls(directory, host)
        store.directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        # Reserve headroom for a rollback journal as large as the database.
        disk = os.statvfs(store.directory)
        if disk.f_bavail * disk.f_frsize < 2 * limits.database_bytes + 1024**2:
            raise IntakeError('insufficient space for intake database and rollback journal')
        path = store.directory / 'arrivals.sqlite3'
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(descriptor)
        with store._connect(initializing=True) as connection:
            connection.execute('PRAGMA page_size=4096')
            connection.execute(f'PRAGMA max_page_count={limits.database_bytes // 4096}')
            connection.executescript('''
                BEGIN IMMEDIATE;
                CREATE TABLE configuration (id INTEGER PRIMARY KEY CHECK (id=1), value BLOB NOT NULL);
                CREATE TABLE arrivals (
                    request_id TEXT PRIMARY KEY, transaction_sha256 TEXT NOT NULL UNIQUE,
                    wallet_sha256 TEXT NOT NULL, head_token TEXT NOT NULL,
                    body BLOB NOT NULL, wallet BLOB NOT NULL, metadata BLOB NOT NULL,
                    received_unix_ns TEXT NOT NULL, payload_bytes INTEGER NOT NULL);
                CREATE TABLE selections (
                    selection_id TEXT PRIMARY KEY, document BLOB NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('sealed','applied','cancelled')),
                    application BLOB);
                CREATE TABLE claims (
                    request_id TEXT PRIMARY KEY REFERENCES arrivals(request_id),
                    selection_id TEXT NOT NULL REFERENCES selections(selection_id));
                CREATE TABLE events (
                    sequence INTEGER PRIMARY KEY, kind TEXT NOT NULL,
                    subject TEXT NOT NULL, recorded_unix_ns TEXT NOT NULL, document BLOB NOT NULL);
            ''')
            config = {'schema': SCHEMA, 'host_configuration_sha256': store.configuration,
                      'limits': asdict(limits)}
            connection.execute('INSERT INTO configuration VALUES (1,?)', (H.canonical(config),))
            connection.execute('COMMIT')
        H.Store._sync_dir(store.directory)
        H.Store._sync_dir(store.directory.parent)
        return store

    @contextmanager
    def _connect(self, *, initializing=False):
        if not stat.S_ISDIR(self.directory.lstat().st_mode):
            raise IntakeError('intake directory must be a real directory')
        path = self.directory / 'arrivals.sqlite3'
        if not stat.S_ISREG(path.lstat().st_mode):
            raise IntakeError('intake database must be a regular file')
        connection = sqlite3.connect(path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute('PRAGMA journal_mode=DELETE')
            connection.execute('PRAGMA synchronous=EXTRA')
            connection.execute('PRAGMA foreign_keys=ON')
            connection.execute('PRAGMA trusted_schema=OFF')
            connection.execute('PRAGMA cache_size=-4096')
            connection.execute('PRAGMA temp_store=MEMORY')
            if not initializing:
                config = H._json(connection.execute('SELECT value FROM configuration WHERE id=1').fetchone()[0])
                if config.get('schema') != SCHEMA or config.get('host_configuration_sha256') != self.configuration:
                    raise IntakeError('intake belongs to a different native host configuration')
                limits = Limits(**config['limits'])
                limits.validate()
                connection.execute(f'PRAGMA max_page_count={limits.database_bytes // 4096}')
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _transaction(self):
        with self._connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            try:
                yield connection
                self._fault('before_commit')
            except BaseException:
                if connection.in_transaction:
                    connection.execute('ROLLBACK')
                raise
            try:
                connection.execute('COMMIT')
                self._fault('after_commit')
            except BaseException as error:
                raise IntakeCommitIndeterminate('intake commit outcome requires reopening the store') from error

    @staticmethod
    def _limits(connection):
        return Limits(**H._json(connection.execute('SELECT value FROM configuration WHERE id=1').fetchone()[0])['limits'])

    def _event(self, connection, kind, subject, document):
        if connection.execute('SELECT count(*) FROM events').fetchone()[0] >= self._limits(connection).events:
            raise IntakeError('intake event limit exhausted')
        connection.execute('INSERT INTO events(kind,subject,recorded_unix_ns,document) VALUES (?,?,?,?)',
                           (kind, subject, str(time.time_ns()), H.canonical(document)))

    @staticmethod
    def _arrival(row):
        if row is None:
            raise IntakeError('unknown arrival request')
        if (H.sha(row['body']) != row['transaction_sha256'] or H.sha(row['wallet']) != row['wallet_sha256']
                or row['payload_bytes'] != len(row['body']) + len(row['wallet']) + len(row['metadata'])):
            raise IntakeError('retained arrival bytes are corrupt')
        return {'request_id': row['request_id'], 'transaction_sha256': row['transaction_sha256'],
                'wallet_sha256': row['wallet_sha256'], 'head_token': row['head_token'],
                'received_unix_ns': row['received_unix_ns'], 'metadata': H._json(row['metadata']),
                'validation': 'pending_native_candidate_and_proof', 'durability_confirmed': True}

    def submit(self, request_id, *, expected_head, body, wallet, metadata=None):
        if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
            raise ValueError('invalid arrival request id')
        H._digest(expected_head)
        if H.body_count(body) != 1 or type(wallet) is not bytes or not 0 < len(wallet) <= H.MAX_PROOF_BYTES:
            raise ValueError('arrival requires one complete transaction and one bounded wallet proof')
        if metadata is None:
            metadata = {}
        if not isinstance(metadata, dict):
            raise ValueError('arrival metadata must be an object')
        encoded = H.canonical(metadata)
        H._json(encoded)
        if len(encoded) > 4096:
            raise ValueError('arrival metadata exceeds its bound')
        transaction, proof = H.sha(body), H.sha(wallet)
        size = len(body) + len(wallet) + len(encoded)
        with self._transaction() as connection:
            row = connection.execute('SELECT * FROM arrivals WHERE request_id=?', (request_id,)).fetchone()
            if row is not None:
                result = self._arrival(row)
                if (row['head_token'], row['body'], row['wallet'], row['metadata']) != (expected_head, body, wallet, encoded):
                    raise IntakeError('arrival request id was reused with different inputs')
                return result
            duplicate = connection.execute('SELECT request_id FROM arrivals WHERE transaction_sha256=?', (transaction,)).fetchone()
            if duplicate is not None:
                raise DuplicateTransaction('transaction body already retained as ' + duplicate[0])
            if self.host.read().token != expected_head:
                raise H.StaleHead('arrival was prepared for a different native head')
            limits = self._limits(connection)
            count, used = connection.execute('SELECT count(*),coalesce(sum(payload_bytes),0) FROM arrivals').fetchone()
            if count >= limits.arrivals or used + size > limits.payload_bytes:
                raise IntakeError('intake payload or arrival limit exhausted')
            connection.execute('INSERT INTO arrivals VALUES (?,?,?,?,?,?,?,?,?)',
                               (request_id, transaction, proof, expected_head, body, wallet, encoded, str(time.time_ns()), size))
            row = connection.execute('SELECT * FROM arrivals WHERE request_id=?', (request_id,)).fetchone()
            result = self._arrival(row)
            self._event(connection, 'received', request_id, result)
            return result

    @staticmethod
    def _selection(connection, selection_id):
        H._digest(selection_id)
        row = connection.execute('SELECT * FROM selections WHERE selection_id=?', (selection_id,)).fetchone()
        if row is None:
            raise IntakeError('unknown sealed selection')
        if H.sha(row['document']) != selection_id:
            raise IntakeError('sealed selection is corrupt')
        return {'selection_id': selection_id, **H._json(row['document']), 'status': row['status'],
                'application': H._json(row['application']) if row['application'] is not None else None}

    def pending_inputs(self, *, expected_head, request_ids=None, limit=64):
        return self._input_snapshot(expected_head=expected_head, request_ids=request_ids,
                                    limit=limit, include_stale=False)

    def candidate_inputs(self, *, expected_head, request_ids=None, limit=256):
        """Unclaimed arrivals, including old heads; none is approved by this read."""
        return self._input_snapshot(expected_head=expected_head, request_ids=request_ids,
                                    limit=limit, include_stale=True)

    def _input_snapshot(self, *, expected_head, request_ids, limit, include_stale):
        """Copy an ordered unclaimed snapshot; sealing rechecks all bytes/head."""
        H._digest(expected_head)
        maximum = 4096 if include_stale else 64
        if type(limit) is not int or not 1 <= limit <= maximum:
            raise ValueError('candidate limit must be in 1..64')
        if request_ids is not None and (type(request_ids) is not list or not 1 <= len(request_ids) <= limit
                or any(not isinstance(r, str) or not REQUEST_ID.fullmatch(r) for r in request_ids)
                or len(set(request_ids)) != len(request_ids)):
            raise ValueError('candidate requires distinct ordered request ids')
        if self.host.read().token != expected_head:
            raise H.StaleHead('native head changed before pending selection')
        with self._connect() as connection:
            connection.execute('BEGIN')
            if request_ids is None:
                query = ('SELECT a.request_id FROM arrivals a LEFT JOIN claims c USING(request_id) '
                         'WHERE c.request_id IS NULL ')
                if include_stale:
                    request_ids = [row[0] for row in connection.execute(query + 'ORDER BY a.rowid LIMIT ?', (limit,))]
                else:
                    request_ids = [row[0] for row in connection.execute(
                        query + 'AND a.head_token=? ORDER BY a.rowid LIMIT ?', (expected_head, limit))]
            if not request_ids:
                raise IntakeError('no pending arrivals for the current native head')
            selected = []
            for request in request_ids:
                row = connection.execute('SELECT * FROM arrivals WHERE request_id=?', (request,)).fetchone()
                receipt = self._arrival(row)
                if not include_stale and row['head_token'] != expected_head:
                    raise H.StaleHead('pending arrival requires revalidation against the current head')
                if connection.execute('SELECT 1 FROM claims WHERE request_id=?', (request,)).fetchone():
                    raise IntakeError('pending arrival is already sealed or applied')
                selected.append({'receipt': receipt, 'body': row['body'], 'wallet': row['wallet']})
            return selected

    def _revalidation_receipts(self, candidate):
        """A pinned, CPU-checked preparation binds old receipts to its new head."""
        path = getattr(candidate, 'manifest_path', None)
        if path is None:
            return {}
        manifest_bytes = H.Store._read_file(path, 16 * 1024**2)
        manifest = H._json(manifest_bytes)
        if manifest.get('arrival_head_revalidation') is not True:
            return {}
        pending_path = candidate.fixture / 'pending-arrivals.json'
        pending_bytes = H.Store._read_file(pending_path, 1024**2)
        pending = H._json(pending_bytes)
        source_pins = {p['path']: p for p in manifest.get('sources', [])}
        pending_pin = source_pins.get(str(pending_path))
        arrivals = pending.get('arrivals', [])
        requests = pending.get('request_ids')
        if (H.sha(manifest_bytes) != candidate.manifest_pin['sha256']
                or manifest.get('preparation_backend') != 'durable-pending-arrivals'
                or manifest.get('status') != 'succeeded'
                or manifest.get('native_state_preflight_passed') is not True
                or manifest.get('independently_cpu_verified_wallets') != candidate.count
                or manifest.get('parent_head_token') != candidate.head.token
                or pending.get('native_head') != candidate.head.token
                or pending.get('host_configuration_sha256') != self.configuration
                or not pending_pin or pending_pin['sha256'] != H.sha(pending_bytes)
                or pending_pin['bytes'] != len(pending_bytes)
                or not isinstance(arrivals, list) or len(arrivals) != candidate.count
                or requests != manifest.get('request_ids')
                or requests != [r.get('request_id') for r in arrivals]
                or len(set(requests)) != candidate.count):
            raise IntakeError('arrival revalidation is not bound to the prepared native candidate')
        revalidated = [r['request_id'] for r in arrivals if r['head_token'] != candidate.head.token]
        if manifest.get('revalidated_request_ids') != revalidated:
            raise IntakeError('prepared arrival revalidation list differs from original receipts')
        return {r['request_id']: r for r in arrivals}

    def _head_matches(self, row, head, revalidated):
        return (row['head_token'] == head or
                H.canonical(revalidated.get(row['request_id'])) == H.canonical(self._arrival(row)))

    def seal(self, candidate, request_ids):
        if getattr(candidate, 'prefix', False):
            raise IntakeError('an unsealed prefix cannot claim or seal arrival inputs')
        if (type(request_ids) is not list or len(request_ids) != candidate.count
                or any(not isinstance(r, str) or not REQUEST_ID.fullmatch(r) for r in request_ids)
                or len(set(request_ids)) != len(request_ids)):
            raise ValueError('selection must name each prepared transaction exactly once, in order')
        if H.sha(H.canonical(candidate.store.verifier.configuration)) != self.configuration:
            raise IntakeError('candidate belongs to a different native host')
        document = {'schema': SCHEMA, 'host_configuration_sha256': self.configuration,
                    'native_host_binding': candidate.binding, 'request_ids': request_ids,
                    'fixture': str(candidate.fixture), 'manifest_sha256': candidate.manifest_pin['sha256']}
        revalidated = self._revalidation_receipts(candidate)
        encoded = H.canonical(document)
        selection_id = H.sha(encoded)
        with self._transaction() as connection:
            prior = connection.execute('SELECT 1 FROM selections WHERE selection_id=?', (selection_id,)).fetchone()
            if prior:
                return self._selection(connection, selection_id)
            candidate.check(candidate.binding)
            if self.host.read().token != candidate.head.token:
                raise H.StaleHead('intake host and candidate head differ')
            for position, request_id in enumerate(request_ids):
                row = connection.execute('SELECT * FROM arrivals WHERE request_id=?', (request_id,)).fetchone()
                self._arrival(row)
                if not self._head_matches(row, candidate.head.token, revalidated):
                    raise H.StaleHead('selection contains an arrival for a different head')
                if (row['body'] != (candidate.fixture / f'complete-body.{position}').read_bytes()
                        or row['wallet'] != (candidate.fixture / f'wallet.{position}').read_bytes()):
                    raise IntakeError('ordered arrival bytes differ from the native preparation')
                if connection.execute('SELECT 1 FROM claims WHERE request_id=?', (request_id,)).fetchone():
                    raise IntakeError('arrival is already claimed by a sealed or applied selection')
            connection.execute('INSERT INTO selections VALUES (?,?,?,NULL)', (selection_id, encoded, 'sealed'))
            connection.executemany('INSERT INTO claims VALUES (?,?)', [(r, selection_id) for r in request_ids])
            event = {'request_ids': request_ids, 'native_head': candidate.head.token}
            if revalidated:
                event['revalidated_arrivals'] = [
                    {'request_id': request, 'original_head_token': revalidated[request]['head_token'],
                     'validated_head_token': candidate.head.token}
                    for request in request_ids if revalidated[request]['head_token'] != candidate.head.token]
            self._event(connection, 'sealed', selection_id, event)
            return self._selection(connection, selection_id)

    def check_selection(self, selection_id, candidate):
        revalidated = self._revalidation_receipts(candidate)
        candidate.check(candidate.binding)
        if self.host.read().token != getattr(candidate, 'current_head', candidate.head).token:
            raise H.StaleHead('intake host changed after selection')
        with self._connect() as connection:
            result = self._selection(connection, selection_id)
            recovered = getattr(candidate, 'recovered_receipt', None)
            if ((result['status'] != 'sealed' and not (
                    recovered is not None and result['status'] == 'applied'
                    and result['application'] == recovered))
                    or result['native_host_binding'] != candidate.binding
                    or result['host_configuration_sha256'] != self.configuration
                    or result['fixture'] != str(candidate.fixture)
                    or result['manifest_sha256'] != candidate.manifest_pin['sha256']):
                raise IntakeError('sealed selection does not match the native candidate')
            for position, request_id in enumerate(result['request_ids']):
                row = connection.execute('SELECT * FROM arrivals WHERE request_id=?', (request_id,)).fetchone()
                self._arrival(row)
                claim = connection.execute('SELECT selection_id FROM claims WHERE request_id=?', (request_id,)).fetchone()
                if (claim is None or claim[0] != selection_id or not self._head_matches(row, candidate.head.token, revalidated)
                        or row['body'] != (candidate.fixture / f'complete-body.{position}').read_bytes()
                        or row['wallet'] != (candidate.fixture / f'wallet.{position}').read_bytes()):
                    raise IntakeError('sealed arrival data or claim differs from the candidate')
            return result

    def check_prefix(self, candidate):
        if getattr(candidate, 'prefix', False) is not True:
            raise IntakeError('prefix dispatch requires a native prefix preparation')
        candidate.check(candidate.binding)
        receipts = self._revalidation_receipts(candidate)
        if len(receipts) != candidate.count:
            raise IntakeError('prefix preparation lacks pinned arrival receipts')
        with self._connect() as connection:
            connection.execute('BEGIN')
            for position, (request, receipt) in enumerate(receipts.items()):
                row = connection.execute('SELECT * FROM arrivals WHERE request_id=?', (request,)).fetchone()
                if (self._arrival(row) != receipt
                        or row['body'] != (candidate.fixture / f'complete-body.{position}').read_bytes()
                        or row['wallet'] != (candidate.fixture / f'wallet.{position}').read_bytes()
                        or connection.execute('SELECT 1 FROM claims WHERE request_id=?', (request,)).fetchone()):
                    raise IntakeError('prefix arrivals changed or were already claimed')
        if self.host.read().token != candidate.head.token:
            raise H.StaleHead('native head changed during prefix validation')

    def record_application(self, selection_id, candidate, receipt, proof):
        # Replays the published native state. An owner success flag is insufficient.
        candidate.verify_application(receipt, proof, candidate.binding)
        published = self.host.read()
        if published.token != receipt.get('head_token') or published.generation != receipt.get('generation'):
            raise H.StaleHead('application is not the published state of this intake host')
        with self._transaction() as connection:
            result = self._selection(connection, selection_id)
            if result['native_host_binding'] != candidate.binding:
                raise IntakeError('application belongs to a different sealed selection')
            if result['status'] == 'applied' and result['application'] == receipt:
                return result
            if result['status'] != 'sealed':
                raise IntakeError('selection cannot accept this application')
            connection.execute('UPDATE selections SET status=?,application=? WHERE selection_id=?',
                               ('applied', H.canonical(receipt), selection_id))
            self._event(connection, 'applied', selection_id, receipt)
            return self._selection(connection, selection_id)

    def cancel(self, selection_id, reason):
        if reason not in ('stale_head', 'proving_failed', 'operator_cancelled'):
            raise ValueError('invalid selection cancellation reason')
        with self._transaction() as connection:
            result = self._selection(connection, selection_id)
            if result['status'] == 'cancelled':
                return result
            if result['status'] != 'sealed':
                raise IntakeError('an applied selection cannot be cancelled')
            connection.execute('UPDATE selections SET status=? WHERE selection_id=?', ('cancelled', selection_id))
            connection.execute('DELETE FROM claims WHERE selection_id=?', (selection_id,))
            self._event(connection, 'cancelled', selection_id, {'reason': reason})
            return self._selection(connection, selection_id)

    def verify_recorded_application(self, selection_id, candidate, receipt, proof):
        candidate.verify_application(receipt, proof, candidate.binding)
        published = self.host.read()
        with self._connect() as connection:
            result = self._selection(connection, selection_id)
            if (result['status'] != 'applied' or result['application'] != receipt
                    or result['native_host_binding'] != candidate.binding
                    or published.token != receipt.get('head_token')
                    or published.generation != receipt.get('generation')):
                raise IntakeError('intake application has not been independently confirmed')
            return result

    def snapshot(self):
        head = self.host.read()
        with self._connect() as connection:
            connection.execute('BEGIN')
            arrivals = []
            for row in connection.execute('SELECT a.*,s.status,s.selection_id FROM arrivals a LEFT JOIN claims c USING(request_id) LEFT JOIN selections s USING(selection_id) ORDER BY a.rowid'):
                value = self._arrival(row)
                value['status'] = row['status'] or ('pending' if row['head_token'] == head.token else 'stale')
                value['selection_id'] = row['selection_id']
                arrivals.append(value)
            selections = [self._selection(connection, row[0]) for row in connection.execute('SELECT selection_id FROM selections ORDER BY rowid')]
            events = [{**dict(row), 'document': H._json(row['document'])} for row in connection.execute('SELECT * FROM events ORDER BY sequence')]
            return {'schema': SCHEMA, 'host_configuration_sha256': self.configuration, 'native_head': head.token,
                    'native_generation': head.generation, 'limits': asdict(self._limits(connection)),
                    'arrivals': arrivals, 'selections': selections, 'events': events,
                    'arrival_backend_integrated': False, 'active_recovery_qualified': False}
