"""Portable transaction lifecycle accounting. This code does not verify proofs.

Producers emit block_applied only after host validation and a durable state
commit. Import validates the event contract, not the producer's truthfulness.
"""
import copy
import re
import statistics

from .model import ID_PATTERN, exact, reject_payloads

MINUTE_NS = 60_000_000_000
KINDS = {"joinsplit", "htlc_redeem", "htlc_refund", "issuance"}
SCOPES = {"durable_test_chain", "canonical_chain"}
HEX = re.compile(r"^[a-f0-9]{64}$")


def integer(value, name):
    if isinstance(value, bool) or not isinstance(value, (str, int)) or not re.fullmatch(r"\d+", str(value)):
        raise ValueError("invalid integer: " + name)
    return int(value)


def digest_field(value, name):
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise ValueError("invalid digest: " + name)
    return value


def distribution(values):
    values = sorted(values)
    if not values:
        return {"count": 0, "median_seconds": None, "p95_seconds": None, "max_seconds": None}
    # Nearest rank. A pilot distribution is not a production tail claim.
    return {"count": len(values), "median_seconds": statistics.median(values),
            "p95_seconds": values[(95*len(values)+99)//100-1], "max_seconds": values[-1]}


def analyze(campaign):
    if not isinstance(campaign, dict):
        raise ValueError("campaign must be an object")
    reject_payloads(campaign)
    exact(campaign)
    if campaign.get("schema_version") != 1 or campaign.get("record_type") != "transaction_campaign":
        raise ValueError("unsupported transaction campaign")
    if not isinstance(campaign.get("campaign_id"), str) or not ID_PATTERN.fullmatch(campaign["campaign_id"]):
        raise ValueError("invalid campaign_id")
    for key in ("label", "track", "resource_profile_id"):
        if not isinstance(campaign.get(key), str) or not campaign[key]:
            raise ValueError("missing campaign " + key)
    if campaign.get("measurement_scope") not in SCOPES:
        raise ValueError("campaign must describe durable test-chain or canonical-chain application")
    digest_field(campaign.get("initial_tip"), "initial chain tip")
    if not isinstance(campaign.get("sources"), list) or not campaign["sources"]:
        raise ValueError("campaign requires public source provenance")
    for source in campaign["sources"]:
        if not isinstance(source, dict) or not isinstance(source.get("path"), str) or not source["path"]:
            raise ValueError("invalid campaign source")
        digest_field(source.get("sha256"), "source.sha256")
    window = campaign["window"]
    if not isinstance(window, dict):
        raise ValueError("window must be an object")
    if not isinstance(window.get("clock"), str) or not window["clock"]:
        raise ValueError("declare one coordinator clock for lifecycle events")
    start = integer(window["started_ns"], "window start")
    end = integer(window["finished_ns"], "window finish") if window.get("finished_ns") is not None else None
    if end is not None and end <= start:
        raise ValueError("empty or reversed window")
    if not isinstance(campaign.get("events"), list):
        raise ValueError("events must be a list")
    events, event_ids = [], {}
    for event in campaign["events"]:
        if (not isinstance(event, dict) or not isinstance(event.get("event_id"), str)
                or not ID_PATTERN.fullmatch(event["event_id"])):
            raise ValueError("invalid event_id")
        eid = event["event_id"]
        if eid in event_ids:
            if event != event_ids[eid]:
                raise ValueError("conflicting replay of event_id " + eid)
            continue
        event_ids[eid] = event
        timestamp = integer(event["at_ns"], "event time")
        if events and timestamp < events[-1][0]:
            raise ValueError("events must be in coordinator capture order")
        events.append((timestamp, event))
    state = {"transactions": {}, "blocks": {}, "chain": [],
             "accepted_user": set(), "accepted_issuance": set(), "ever_applied": set(),
             "reapplications": 0, "reversed_user": set(), "reversal_events": 0,
             "invalid": set(), "duplicate_submissions": 0, "failures": 0,
             "submitted_user": set(), "deferred": 0, "duplicate_rejections": 0,
             "accepted_latency": [], "wallet_latency": [], "queue_latency": [],
             "seal_to_root": [], "root_to_applied": [], "last_user_application": None,
             "application_gaps": [], "backlog_samples": [], "closed": False}
    initial_backlog, snapshot = None, None

    def backlog():
        return sum(t["kind"] != "issuance" and not t["applied"] and not t["rejected"]
                   for t in state["transactions"].values())

    for at, event in events:
        if initial_backlog is None and at >= start:
            initial_backlog = backlog()
        if snapshot is None and end is not None and at >= end:
            snapshot = copy.deepcopy(state)
        in_window = at >= start and (end is None or at < end)
        kind = event.get("type")
        if kind == "submitted":
            tid = digest_field(event.get("transaction_id"), "transaction_id")
            tx_kind = event.get("transaction_kind")
            if tx_kind not in KINDS:
                raise ValueError("unknown transaction kind")
            if tid in state["transactions"]:
                if state["transactions"][tid]["kind"] != tx_kind:
                    raise ValueError("transaction ID changes kind")
                if in_window:
                    state["duplicate_submissions"] += 1
            else:
                state["transactions"][tid] = {"kind": tx_kind, "submitted": at, "applied": False,
                                              "rejected": False, "stages": {}}
                if in_window and tx_kind != "issuance":
                    state["submitted_user"].add(tid)
        elif kind in ("wallet_proof_ready", "admitted", "rejected"):
            tid = digest_field(event.get("transaction_id"), "transaction_id")
            if tid not in state["transactions"]:
                raise ValueError("event for unsubmitted transaction")
            tx = state["transactions"][tid]
            if kind == "rejected":
                reason = event.get("reason")
                if reason not in ("invalid", "duplicate", "deferred"):
                    raise ValueError("rejection reason must be invalid, duplicate or deferred")
                if reason == "invalid":
                    if tx["applied"]:
                        raise ValueError("applied transaction cannot subsequently be invalid")
                    tx["rejected"] = True
                    if in_window:
                        state["invalid"].add(tid)
                elif in_window:
                    state["deferred" if reason == "deferred" else "duplicate_rejections"] += 1
            elif tx["rejected"]:
                raise ValueError("invalid transaction cannot advance")
            else:
                if kind in tx["stages"]:
                    raise ValueError("duplicate lifecycle stage; replay the original event_id")
                if kind == "admitted" and "wallet_proof_ready" not in tx["stages"]:
                    raise ValueError("admission must follow wallet proof readiness")
                tx["stages"][kind] = at
        elif kind == "sealed":
            bid = digest_field(event.get("block_id"), "block_id")
            if bid in state["blocks"]:
                raise ValueError("block sealed twice")
            ids = event.get("transaction_ids")
            if not isinstance(ids, list) or not 1 <= len(ids) <= 64:
                raise ValueError("invalid block transaction selection")
            for tid in ids:
                digest_field(tid, "sealed transaction_id")
            if len(set(ids)) != len(ids):
                raise ValueError("duplicate transaction in block")
            if any(tid not in state["transactions"] or state["transactions"][tid]["rejected"] for tid in ids):
                raise ValueError("block includes an unknown or invalid transaction")
            for tid in ids:
                stages = state["transactions"][tid]["stages"]
                if "wallet_proof_ready" not in stages or "admitted" not in stages:
                    raise ValueError("sealed transaction lacks proof-ready/admission evidence")
            state["blocks"][bid] = {"ids": ids, "sealed": at, "verified": None}
        elif kind == "root_verified":
            block = state["blocks"].get(digest_field(event.get("block_id"), "block_id"))
            if block is None or block["verified"] is not None:
                raise ValueError("root verification must follow one sealed selection")
            if event.get("cpu_audited") is not True or event.get("expected_statement_verified") is not True:
                raise ValueError("root lacks independent CPU/expected-statement verification")
            if type(event.get("level")) is not int or event["level"] != 6 or not 0 < integer(event["proof_bytes"], "proof bytes") <= 2*1024**2:
                raise ValueError("root geometry or size gate failed")
            digest_field(event.get("proof_sha256"), "root proof")
            digest_field(event.get("profile_sha256"), "profile")
            block["verified"] = at
            if in_window:
                state["seal_to_root"].append((at-block["sealed"])/1e9)
        elif kind == "block_applied":
            bid = digest_field(event.get("block_id"), "block_id")
            block = state["blocks"].get(bid)
            if (block is None or block["verified"] is None or event.get("durable") is not True
                    or event.get("host_validated") is not True):
                raise ValueError("application requires verified root and durable host commit")
            expected_parent = state["chain"][-1] if state["chain"] else campaign.get("initial_tip")
            if event.get("parent_block_id") != expected_parent:
                raise ValueError("application does not extend the recorded canonical tip")
            if "parent" in block and block["parent"] != expected_parent:
                raise ValueError("a block ID cannot change its parent after a reorg")
            block["parent"] = expected_parent
            digest_field(event.get("state_commit_sha256"), "durable state commit")
            if any(state["transactions"][tid]["applied"] for tid in block["ids"]):
                raise ValueError("transaction already applied on this chain")
            if any(state["transactions"][tid]["rejected"] for tid in block["ids"]):
                raise ValueError("block includes a subsequently rejected transaction")
            state["chain"].append(bid)
            accepted_users = 0
            for tid in block["ids"]:
                tx = state["transactions"][tid]
                tx["applied"] = True
                if tid in state["ever_applied"]:
                    if in_window:
                        state["reapplications"] += 1
                    continue
                state["ever_applied"].add(tid)
                if not in_window:
                    continue
                state["accepted_issuance" if tx["kind"] == "issuance" else "accepted_user"].add(tid)
                if tx["kind"] != "issuance":
                    accepted_users += 1
                    state["accepted_latency"].append((at-tx["submitted"])/1e9)
                    stages = tx["stages"]
                    state["wallet_latency"].append((stages["wallet_proof_ready"]-tx["submitted"])/1e9)
                    state["queue_latency"].append((block["sealed"]-stages["admitted"])/1e9)
            if in_window:
                state["root_to_applied"].append((at-block["verified"])/1e9)
                if accepted_users:
                    prior = state["last_user_application"]
                    state["application_gaps"].append((at-(prior if prior is not None else start))/1e9)
                    state["last_user_application"] = at
        elif kind == "block_reverted":
            bid = digest_field(event.get("block_id"), "block_id")
            if not state["chain"] or state["chain"][-1] != bid or event.get("durable") is not True:
                raise ValueError("reversal must durably remove the current tip")
            digest_field(event.get("state_commit_sha256"), "reversal state commit")
            state["chain"].pop()
            for tid in state["blocks"][bid]["ids"]:
                state["transactions"][tid]["applied"] = False
                if in_window and state["transactions"][tid]["kind"] != "issuance":
                    state["reversed_user"].add(tid)
                    state["reversal_events"] += 1
        elif kind in ("failed", "recovered"):
            if not isinstance(event.get("reason"), str) or not event["reason"]:
                raise ValueError("failure/recovery requires a reason")
            if in_window and kind == "failed":
                state["failures"] += 1
        elif kind == "window_closed":
            if end is None or at != end or state["closed"]:
                raise ValueError("window closure must match the declared finish exactly once")
            state["closed"] = True
            if snapshot is not None:
                snapshot["closed"] = True
        else:
            raise ValueError("unknown lifecycle event type")
        if in_window:
            state["backlog_samples"].append({"at_ns": str(at), "pending_user_transactions": backlog()})
    measured = snapshot if snapshot is not None else state
    closed = end is not None and measured["closed"]
    duration = (end-start)/1e9 if closed else None
    n = len(measured["accepted_user"])
    retained = sum(measured["transactions"][t]["applied"] for t in measured["accepted_user"])
    retained_issuance = sum(measured["transactions"][t]["applied"] for t in measured["accepted_issuance"])
    final_pending = sum(t["kind"] != "issuance" and not t["applied"] and not t["rejected"]
                        for t in measured["transactions"].values())
    gaps = measured["application_gaps"][:]
    if closed:
        last = measured["last_user_application"]
        gaps.append((end-(last if last is not None else start))/1e9)
    initial_pending = initial_backlog if initial_backlog is not None else backlog()
    return exact({
        "status": "complete" if closed else "incomplete", "measurement_scope": campaign["measurement_scope"],
        "unique_user_transactions": n, "issuance_transactions": len(measured["accepted_issuance"]),
        "measured_seconds": duration, "user_transactions_per_minute": retained*60/duration if duration else None,
        "unique_application_transactions_per_minute": n*60/duration if duration else None,
        "target_met_in_pilot": retained*60/duration >= 4 if duration else None,
        "submitted_unique_user_transactions": len(measured["submitted_user"]),
        "initial_pending_user_transactions": initial_pending,
        "final_pending_user_transactions": final_pending,
        "pending_user_transaction_change": final_pending-initial_pending,
        "reversed_unique_user_transactions": len(measured["reversed_user"]),
        "user_reversal_events": measured["reversal_events"], "reapplications": measured["reapplications"],
        "unique_user_transactions_retained_at_end": retained,
        "issuance_transactions_retained_at_end": retained_issuance,
        "retained_user_transactions_by_kind": {
            k: sum(measured["transactions"][t]["kind"] == k and measured["transactions"][t]["applied"]
                   for t in measured["accepted_user"]) for k in sorted(KINDS-{"issuance"})},
        "invalid_transactions": len(measured["invalid"]), "duplicate_submissions": measured["duplicate_submissions"],
        "deferral_events": measured["deferred"], "duplicate_rejections": measured["duplicate_rejections"],
        "failures": measured["failures"], "longest_user_application_gap_seconds": max(gaps, default=None),
        "latencies": {name: distribution(measured[name]) for name in
                      ("accepted_latency", "wallet_latency", "queue_latency", "seal_to_root", "root_to_applied")},
        "backlog_samples": measured["backlog_samples"],
        "events_after_window": sum(end is not None and at > end for at, _ in events),
        "events_at_window_end": sum(end is not None and at == end and e["type"] != "window_closed" for at, e in events),
        "tip_at_window_end": measured["chain"][-1] if measured["chain"] else campaign["initial_tip"],
        "evidence_level": "producer_attested_lifecycle; reporter does not verify proofs or host state",
        "sustained_service_qualified": False,
    })
