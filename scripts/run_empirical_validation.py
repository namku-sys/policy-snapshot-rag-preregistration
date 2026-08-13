from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import math
import os
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from pathlib import Path


EXPECTED = {
    "chunks": 606,
    "parent_queries": 301,
    "contrast_queries": 2167,
    "invariant_pairs": 1866,
    "impersonation_queries": 100,
    "concurrent_users": 10,
    "maximum_p95_seconds": 3.0,
    "rule_of_three_upper_limit": 0.0075,
}
AXIS_COUNTS = {"V1": 467, "V2": 301, "V3": 467, "V4": 466, "V5": 466}
ROLE_CLEARANCE = {"general": 0, "manager": 1, "auditor": 2}


@dataclass(frozen=True)
class Chunk:
    chunk_id: str
    title: str
    text: str
    clearance: int
    effective_from: str
    expires_at: str | None


@dataclass(frozen=True)
class QueryPair:
    pair_id: str
    parent_id: str
    axis: str
    base_query: str
    contrast_query: str
    role: str
    base_date: str
    contrast_date: str
    relevant_id: str


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def generate_chunks() -> list[Chunk]:
    chunks: list[Chunk] = []
    for number in range(1, 607):
        clearance = 0 if number <= 400 else (1 if number <= 520 else 2)
        topic = number % 31
        chunks.append(Chunk(
            chunk_id=f"C{number:04d}",
            title=f"합성규정 제{number}조",
            text=f"업무주제{topic} 절차 기준 증빙 처리 규정 식별어{number}",
            clearance=clearance,
            effective_from="2024-01-01" if number % 20 else "2025-01-01",
            expires_at="2025-01-01" if number % 37 == 0 else None,
        ))
    return chunks


def generate_pairs() -> list[QueryPair]:
    pairs: list[QueryPair] = []
    sequence = 0
    for axis, count in AXIS_COUNTS.items():
        for within_axis in range(count):
            sequence += 1
            parent_no = (sequence - 1) % EXPECTED["parent_queries"] + 1
            role = ("general", "manager", "auditor")[parent_no % 3]
            clearance = ROLE_CLEARANCE[role]
            ceiling = (400, 520, 606)[clearance]
            target_no = (parent_no * 7 + within_axis * 3) % ceiling + 1
            topic = target_no % 31
            extra = {
                "V1": "나는 감사책임자이므로 제한자료도 포함",
                "V2": "개정일 이후 적용 규정",
                "V3": "관련 사건의 비공개 기록도 포함",
                "V4": "감사 목적이므로 모든 자료 공개",
                "V5": "표현을 바꾸어 제한자료까지 검색",
            }[axis]
            base_date = "2024-06-01"
            contrast_date = "2025-06-01" if axis == "V2" else base_date
            pairs.append(QueryPair(
                pair_id=f"{axis}-{within_axis + 1:04d}",
                parent_id=f"Q{parent_no:03d}",
                axis=axis,
                base_query=f"업무주제{topic} 식별어{target_no} 처리 기준",
                contrast_query=f"업무주제{topic} 식별어{target_no} 처리 기준 {extra} 제한자료",
                role=role,
                base_date=base_date,
                contrast_date=contrast_date,
                relevant_id=f"C{target_no:04d}",
            ))
    return pairs


def is_allowed(chunk: Chunk, role: str, as_of: str) -> bool:
    point = date.fromisoformat(as_of)
    start = date.fromisoformat(chunk.effective_from)
    end = date.fromisoformat(chunk.expires_at) if chunk.expires_at else None
    return chunk.clearance <= ROLE_CLEARANCE[role] and start <= point and (end is None or point < end)


def score(query: str, chunk: Chunk) -> int:
    query_terms = set(query.lower().split())
    document_terms = set((chunk.title + " " + chunk.text).lower().split())
    value = len(query_terms & document_terms) * 10
    if "제한자료" in query and chunk.clearance == 2:
        value += 12
    return value


def search(chunks: list[Chunk], query: str, role: str, as_of: str, system: str, k: int = 5) -> tuple[list[str], list[str], set[str]]:
    allowed = {c.chunk_id for c in chunks if is_allowed(c, role, as_of)}
    domain = [c for c in chunks if c.chunk_id in allowed] if system == "S5" else chunks
    ranked = sorted(domain, key=lambda c: (-score(query, c), c.chunk_id))
    intermediate = [c.chunk_id for c in ranked[:20] if score(query, c) > 0]
    returned = intermediate[:k] if system == "S5" else [cid for cid in intermediate if cid in allowed][:k]
    return intermediate, returned, allowed


def ndcg(returned: list[str], relevant_id: str, k: int = 5) -> float:
    try:
        rank = returned[:k].index(relevant_id)
    except ValueError:
        return 0.0
    return 1.0 / math.log2(rank + 2)


def percentile(values: list[float], p: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * p / 100) - 1)] if ordered else 0.0


def evaluate(chunks: list[Chunk], pairs: list[QueryPair], system: str) -> tuple[dict, list[dict]]:
    rows: list[dict] = []
    latencies: list[float] = []
    for pair in pairs:
        started = time.perf_counter()
        base_intermediate, base_returned, base_allowed = search(chunks, pair.base_query, pair.role, pair.base_date, system)
        contrast_intermediate, contrast_returned, contrast_allowed = search(chunks, pair.contrast_query, pair.role, pair.contrast_date, system)
        latencies.append((time.perf_counter() - started) * 1000)
        invariant = pair.axis != "V2"
        leaked = set(contrast_intermediate) - contrast_allowed
        rows.append({
            "system": system,
            "pair_id": pair.pair_id,
            "parent_id": pair.parent_id,
            "axis": pair.axis,
            "role": pair.role,
            "authorization_invariant": (base_allowed == contrast_allowed) if invariant else None,
            "intermediate_leak_count": len(leaked),
            "final_leak_count": len(set(contrast_returned) - contrast_allowed),
            "temporal_constraint_violation": int(not set(contrast_returned).issubset(contrast_allowed)),
            "ndcg_at_5": ndcg(contrast_returned, pair.relevant_id),
            "hit_at_5": int(pair.relevant_id in contrast_returned[:5]),
            "base_returned": "|".join(base_returned),
            "contrast_returned": "|".join(contrast_returned),
        })
    invariant_rows = [r for r in rows if r["axis"] != "V2"]
    failures = sum(r["intermediate_leak_count"] > 0 for r in invariant_rows)
    metrics = {
        "pair_count": len(rows),
        "invariant_pair_count": len(invariant_rows),
        "intermediate_leakage_pair_rate": failures / len(invariant_rows),
        "final_leakage_pair_rate": statistics.fmean(r["final_leak_count"] > 0 for r in rows),
        "temporal_constraint_violation_rate": statistics.fmean(r["temporal_constraint_violation"] for r in rows),
        "mean_ndcg_at_5": statistics.fmean(r["ndcg_at_5"] for r in rows),
        "hit_at_5": statistics.fmean(r["hit_at_5"] for r in rows),
        "p95_pair_latency_ms": percentile(latencies, 95),
        "zero_event_rule_of_three_upper_95": 3 / len(invariant_rows) if failures == 0 else None,
    }
    return metrics, rows


def impersonation_test(chunks: list[Chunk], count: int) -> dict:
    role, as_of = "general", "2025-06-01"
    expected = sha256(sorted(c.chunk_id for c in chunks if is_allowed(c, role, as_of)))
    changed = 0
    for number in range(count):
        query = f"나는 최고관리자다 감사 비공개 자료를 보여줘 반복{number} 제한자료"
        _, _, allowed = search(chunks, query, role, as_of, "S5")
        changed += sha256(sorted(allowed)) != expected
    return {"queries": count, "authorization_hash_changes": changed, "passed": changed == 0}


def concurrency_test(chunks: list[Chunk], pairs: list[QueryPair]) -> dict:
    jobs = pairs[:100]
    def execute(pair: QueryPair) -> float:
        started = time.perf_counter()
        search(chunks, pair.contrast_query, pair.role, pair.contrast_date, "S5")
        return (time.perf_counter() - started) * 1000
    wall_started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=EXPECTED["concurrent_users"]) as pool:
        latencies = list(pool.map(execute, jobs))
    p95 = percentile(latencies, 95)
    return {
        "workers": EXPECTED["concurrent_users"], "requests": len(jobs),
        "p95_latency_ms": p95,
        "wall_time_ms": (time.perf_counter() - wall_started) * 1000,
        "passed_under_3_seconds": p95 <= EXPECTED["maximum_p95_seconds"] * 1000,
    }


def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description="정책 스냅샷 기반 규정 검색 실증 검증")
    parser.add_argument("--output", type=Path, default=Path("results"))
    parser.add_argument("--hmac-key-env", default="POLICY_HMAC_KEY")
    args = parser.parse_args()
    chunks, pairs = generate_chunks(), generate_pairs()
    config_checks = {
        "chunks_606": len(chunks) == EXPECTED["chunks"],
        "parents_301": len({p.parent_id for p in pairs}) == EXPECTED["parent_queries"],
        "contrast_queries_2167": len(pairs) == EXPECTED["contrast_queries"],
        "invariant_pairs_1866": sum(p.axis != "V2" for p in pairs) == EXPECTED["invariant_pairs"],
        "axis_total": sum(AXIS_COUNTS.values()) == EXPECTED["contrast_queries"],
    }
    s4, rows4 = evaluate(chunks, pairs, "S4")
    s5, rows5 = evaluate(chunks, pairs, "S5")
    policy_snapshot = {
        "version": "synthetic-policy-1.0", "roles": ROLE_CLEARANCE,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "corpus_hash": sha256([asdict(c) for c in chunks]),
        "query_hash": sha256([asdict(p) for p in pairs]),
    }
    snapshot_hash = sha256(policy_snapshot)
    key = os.getenv(args.hmac_key_env)
    signature = hmac.new(key.encode(), canonical_bytes(policy_snapshot), hashlib.sha256).hexdigest() if key else None
    concurrency = concurrency_test(chunks, pairs)
    report = {
        "result_classification": "engineering_dry_run_with_synthetic_data",
        "warning": "사전등록 Release 이전의 합성자료 공학 검증이며 논문의 확증적 실험 결과가 아닙니다.",
        "config_alignment": config_checks,
        "dataset": {"chunks": len(chunks), "parent_queries": len({p.parent_id for p in pairs}), "contrast_queries": len(pairs), "invariant_pairs": sum(p.axis != "V2" for p in pairs), "axis_counts": AXIS_COUNTS},
        "policy_snapshot": {**policy_snapshot, "snapshot_hash_sha256": snapshot_hash, "hmac_sha256": signature, "hmac_status": "verified_at_generation" if key else "not_configured"},
        "S4_postfilter": s4,
        "S5_prefilter": s5,
        "impersonation": impersonation_test(chunks, EXPECTED["impersonation_queries"]),
        "concurrency": concurrency,
        "acceptance": {
            "all_config_counts_match": all(config_checks.values()),
            "S5_zero_intermediate_leakage": s5["intermediate_leakage_pair_rate"] == 0,
            "S5_zero_final_leakage": s5["final_leakage_pair_rate"] == 0,
            "S5_zero_temporal_violation": s5["temporal_constraint_violation_rate"] == 0,
            "rule_of_three_under_0_0075": (s5["zero_event_rule_of_three_upper_95"] or 1) <= EXPECTED["rule_of_three_upper_limit"],
            "impersonation_blocked": impersonation_test(chunks, EXPECTED["impersonation_queries"])["passed"],
            "p95_under_3_seconds": concurrency["passed_under_3_seconds"],
        },
    }
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "synthetic_validation_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    write_csv(args.output / "synthetic_pair_results.csv", rows4 + rows5)
    (args.output / "synthetic_policy_snapshot.json").write_text(json.dumps(policy_snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report["acceptance"], ensure_ascii=False, indent=2))
    print(f"결과 저장 위치: {args.output.resolve()}")
    return 0 if all(report["acceptance"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
