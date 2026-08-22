from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple


PROTOCOLS_DEFAULT = ("icmp6", "tcp80")
PREFIX_LENGTHS_DEFAULT = tuple(range(64, 125, 4))


# Final MAPD
@dataclass(frozen=True)
class CandidatePrefix:
    prefix: str
    prefix_len: int
    target_count: int


@dataclass(frozen=True)
class ProbeRecord:
    prefix: str
    prefix_len: int
    target_count: int
    branch: int
    probe: str


@dataclass(frozen=True)
class MAPDDecision:
    prefix: str
    prefix_len: int
    target_count: int
    responsive_count: int
    responsive_branches: str
    total_branches: int
    status: str


def canonical_ipv6(addr: str) -> str:
    return str(ipaddress.IPv6Address(addr.strip()))


def read_ipv6_file(path: str | Path) -> List[str]:
    addrs: List[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            token = line.split(",", 1)[0].split()[0]
            try:
                addrs.append(canonical_ipv6(token))
            except ValueError:
                continue
    return addrs


def prefix_of(addr: str, prefix_len: int) -> str:
    return str(
        ipaddress.IPv6Network(f"{canonical_ipv6(addr)}/{prefix_len}", strict=False)
    )


def build_candidate_prefixes(
    target_addresses: Iterable[str],
    prefix_lengths: Sequence[int] = PREFIX_LENGTHS_DEFAULT,
    min_targets: int = 100,
    exempt_prefix_len: int = 64,
) -> List[CandidatePrefix]:
    unique_addrs: Set[str] = set()
    for addr in target_addresses:
        try:
            unique_addrs.add(canonical_ipv6(addr))
        except ValueError:
            continue

    counts: Counter[Tuple[str, int]] = Counter()
    for addr in unique_addrs:
        for plen in prefix_lengths:
            if plen < 0 or plen > 128 or plen % 4 != 0:
                raise ValueError(
                    "MAPD prefix lengths must be nybble-aligned in [0,128]."
                )
            counts[(prefix_of(addr, plen), plen)] += 1

    candidates: List[CandidatePrefix] = []
    for (prefix, plen), count in counts.items():
        if plen == exempt_prefix_len or count > min_targets:
            candidates.append(
                CandidatePrefix(prefix=prefix, prefix_len=plen, target_count=count)
            )

    candidates.sort(
        key=lambda x: (x.prefix_len, ipaddress.IPv6Network(x.prefix).network_address)
    )
    return candidates


def _deterministic_suffix(
    seed: int, prefix: str, branch: int, remaining_bits: int
) -> int:
    if remaining_bits <= 0:
        return 0
    material = f"{seed}|{prefix}|{branch}".encode("utf-8")
    digest = hashlib.sha256(material).digest()
    value = int.from_bytes(digest, "big")
    mask = (1 << remaining_bits) - 1
    return value & mask


def generate_fanout_probes_for_prefix(
    candidate: CandidatePrefix, seed: int = 20260722
) -> List[ProbeRecord]:
    plen = candidate.prefix_len
    if plen % 4 != 0:
        raise ValueError(f"MAPD requires nybble-aligned prefix length, got /{plen}.")
    if plen > 124:
        raise ValueError(
            "MAPD fan-out requires prefix_len <= 124 because it probes child nybbles."
        )

    net = ipaddress.IPv6Network(candidate.prefix, strict=False)
    base = int(net.network_address)
    child_len = plen + 4
    remaining_bits = 128 - child_len

    records: List[ProbeRecord] = []
    for branch in range(16):
        suffix = _deterministic_suffix(seed, str(net), branch, remaining_bits)
        probe_int = base | (branch << remaining_bits) | suffix
        probe = str(ipaddress.IPv6Address(probe_int))
        records.append(
            ProbeRecord(
                prefix=str(net),
                prefix_len=plen,
                target_count=candidate.target_count,
                branch=branch,
                probe=probe,
            )
        )
    return records


def generate_mapd_probes(
    candidates: Iterable[CandidatePrefix], seed: int = 20260722
) -> List[ProbeRecord]:
    probes: List[ProbeRecord] = []
    for cand in candidates:
        probes.extend(generate_fanout_probes_for_prefix(cand, seed=seed))
    return probes


def write_candidates_csv(
    candidates: Sequence[CandidatePrefix], path: str | Path
) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["prefix", "prefix_len", "target_count"])
        writer.writeheader()
        for c in candidates:
            writer.writerow(
                {
                    "prefix": c.prefix,
                    "prefix_len": c.prefix_len,
                    "target_count": c.target_count,
                }
            )


def write_probes_csv(probes: Sequence[ProbeRecord], path: str | Path) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["prefix", "prefix_len", "target_count", "branch", "probe"],
        )
        writer.writeheader()
        for p in probes:
            writer.writerow(
                {
                    "prefix": p.prefix,
                    "prefix_len": p.prefix_len,
                    "target_count": p.target_count,
                    "branch": f"{p.branch:x}",
                    "probe": p.probe,
                }
            )


def read_probes_csv(path: str | Path) -> List[ProbeRecord]:
    probes: List[ProbeRecord] = []
    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        required = {"prefix", "prefix_len", "target_count", "branch", "probe"}
        if not required.issubset(set(reader.fieldnames or [])):
            raise ValueError(f"Probe CSV must contain columns: {sorted(required)}")
        for row in reader:
            branch_raw = str(row["branch"]).strip().lower()
            branch = (
                int(branch_raw, 16)
                if branch_raw in "0123456789abcdef"
                else int(branch_raw)
            )
            probes.append(
                ProbeRecord(
                    prefix=str(ipaddress.IPv6Network(row["prefix"], strict=False)),
                    prefix_len=int(row["prefix_len"]),
                    target_count=int(row["target_count"]),
                    branch=branch,
                    probe=canonical_ipv6(row["probe"]),
                )
            )
    return probes


def read_response_files(paths: Sequence[str | Path]) -> Set[str]:
    merged: Set[str] = set()
    for path in paths:
        if not path:
            continue
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(str(p))
        merged.update(read_ipv6_file(p))
    return merged


def classify_prefixes_from_responses(
    probes: Sequence[ProbeRecord],
    responsive_probe_addresses: Set[str],
) -> List[MAPDDecision]:
    responsive = {canonical_ipv6(addr) for addr in responsive_probe_addresses}
    grouped: Dict[Tuple[str, int], List[ProbeRecord]] = defaultdict(list)
    target_counts: Dict[Tuple[str, int], int] = {}

    for p in probes:
        key = (p.prefix, p.prefix_len)
        grouped[key].append(p)
        target_counts[key] = p.target_count

    decisions: List[MAPDDecision] = []
    for (prefix, plen), records in grouped.items():
        responded = [r for r in records if canonical_ipv6(r.probe) in responsive]
        branches = sorted({r.branch for r in responded})
        status = "aliased" if len(branches) == 16 else "non_aliased"
        decisions.append(
            MAPDDecision(
                prefix=prefix,
                prefix_len=plen,
                target_count=target_counts[(prefix, plen)],
                responsive_count=len(branches),
                responsive_branches="".join(f"{b:x}" for b in branches),
                total_branches=16,
                status=status,
            )
        )

    decisions.sort(
        key=lambda x: (x.prefix_len, ipaddress.IPv6Network(x.prefix).network_address)
    )
    return decisions


def write_decision_outputs(
    decisions: Sequence[MAPDDecision],
    aliased_out: str | Path,
    nonaliased_out: Optional[str | Path] = None,
    summary_out: Optional[str | Path] = None,
) -> None:
    with open(aliased_out, "w", encoding="utf-8", newline="\n") as f:
        for d in decisions:
            if d.status == "aliased":
                f.write(d.prefix + "\n")

    if nonaliased_out:
        with open(nonaliased_out, "w", encoding="utf-8", newline="\n") as f:
            for d in decisions:
                if d.status == "non_aliased":
                    f.write(d.prefix + "\n")

    if summary_out:
        with open(summary_out, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "prefix",
                    "prefix_len",
                    "target_count",
                    "responsive_count",
                    "responsive_branches",
                    "total_branches",
                    "status",
                ],
            )
            writer.writeheader()
            for d in decisions:
                writer.writerow(d.__dict__)


def detect_mapd_alias_prefixes(
    target_addresses: Iterable[str],
    scan_func: Callable[[str, Sequence[str]], Iterable[str]],
    protocols: Sequence[str] = PROTOCOLS_DEFAULT,
    prefix_lengths: Sequence[int] = PREFIX_LENGTHS_DEFAULT,
    min_targets: int = 100,
    seed: int = 20260722,
    previous_responsive_probe_sets: Optional[Sequence[Set[str]]] = None,
) -> Tuple[List[str], List[MAPDDecision], List[ProbeRecord]]:
    candidates = build_candidate_prefixes(
        target_addresses=target_addresses,
        prefix_lengths=prefix_lengths,
        min_targets=min_targets,
        exempt_prefix_len=64,
    )
    probes = generate_mapd_probes(candidates, seed=seed)
    unique_probe_addrs = sorted({p.probe for p in probes})

    merged_responsive: Set[str] = set()
    for protocol in protocols:
        protocol_responsive = scan_func(protocol, unique_probe_addrs)
        for addr in protocol_responsive:
            try:
                merged_responsive.add(canonical_ipv6(addr))
            except ValueError:
                continue

    if previous_responsive_probe_sets:
        for old_set in previous_responsive_probe_sets:
            for addr in old_set:
                try:
                    merged_responsive.add(canonical_ipv6(addr))
                except ValueError:
                    continue

    decisions = classify_prefixes_from_responses(probes, merged_responsive)
    aliased = [d.prefix for d in decisions if d.status == "aliased"]
    return aliased, decisions, probes


def cmd_generate(args: argparse.Namespace) -> None:
    targets = read_ipv6_file(args.input)
    candidates = build_candidate_prefixes(
        target_addresses=targets,
        prefix_lengths=tuple(range(args.min_prefix_len, args.max_prefix_len + 1, 4)),
        min_targets=args.min_targets,
        exempt_prefix_len=64,
    )
    probes = generate_mapd_probes(candidates, seed=args.seed)
    write_candidates_csv(candidates, args.candidates_out)
    write_probes_csv(probes, args.probes_out)
    print(
        f"[MAPD][generate] targets={len(set(targets))}, "
        f"candidate_prefixes={len(candidates)}, probes={len(probes)}, "
        f"logical_protocol_probes={len(probes) * 2}"
    )


def cmd_classify(args: argparse.Namespace) -> None:
    probes = read_probes_csv(args.probes)
    response_files: List[str] = []
    if args.icmp_responses:
        response_files.append(args.icmp_responses)
    if args.tcp80_responses:
        response_files.append(args.tcp80_responses)
    if args.window_responses:
        response_files.extend(args.window_responses)
    if not response_files:
        raise ValueError("At least one response file is required.")

    responsive = read_response_files(response_files)
    decisions = classify_prefixes_from_responses(probes, responsive)
    write_decision_outputs(
        decisions=decisions,
        aliased_out=args.aliased_out,
        nonaliased_out=args.nonaliased_out,
        summary_out=args.summary_out,
    )
    aliased_count = sum(1 for d in decisions if d.status == "aliased")
    print(
        f"[MAPD][classify] probed_prefixes={len(decisions)}, "
        f"aliased={aliased_count}, non_aliased={len(decisions) - aliased_count}, "
        f"merged_responsive_probes={len(responsive)}"
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Gasser-style MAPD/APD without LPM filtering."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    g = sub.add_parser(
        "generate", help="Generate MAPD candidate prefixes and 16-way fan-out probes."
    )
    g.add_argument(
        "--input", required=True, help="Input responsive/hitlist IPv6 addresses."
    )
    g.add_argument(
        "--candidates-out", required=True, help="Output candidate prefixes CSV."
    )
    g.add_argument("--probes-out", required=True, help="Output MAPD probes CSV.")
    g.add_argument(
        "--seed",
        type=int,
        default=20260722,
        help="Deterministic probe-generation seed.",
    )
    g.add_argument(
        "--min-targets",
        type=int,
        default=100,
        help="Probe > min_targets for longer-than-/64 prefixes.",
    )
    g.add_argument("--min-prefix-len", type=int, default=64, help="Default 64.")
    g.add_argument("--max-prefix-len", type=int, default=124, help="Default 124.")
    g.set_defaults(func=cmd_generate)

    c = sub.add_parser(
        "classify", help="Classify prefixes from ICMPv6/TCP80 response files; no LPM."
    )
    c.add_argument(
        "--probes", required=True, help="MAPD probes CSV produced by generate."
    )
    c.add_argument(
        "--icmp-responses",
        default=None,
        help="Responsive probe addresses from ICMPv6 scan.",
    )
    c.add_argument(
        "--tcp80-responses",
        default=None,
        help="Responsive probe addresses from TCP/80 scan.",
    )
    c.add_argument(
        "--window-responses",
        nargs="*",
        default=None,
        help="Optional previous-day merged response files for sliding-window loss resilience.",
    )
    c.add_argument(
        "--aliased-out", required=True, help="Output aliased prefixes text file."
    )
    c.add_argument(
        "--nonaliased-out",
        default=None,
        help="Optional output non-aliased prefixes text file.",
    )
    c.add_argument(
        "--summary-out", default=None, help="Optional full prefix decision CSV."
    )
    c.set_defaults(func=cmd_classify)
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
