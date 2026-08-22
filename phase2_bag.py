#!/usr/bin/env python3.10
# encoding:utf-8

"""
6Hierarchical - Phase 2: BAG (Budget-based Address Generation)
"""

import ipaddress
import itertools
import math
import os
import pickle
import random
import sys
from collections import Counter, defaultdict

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")


BAG_CONFIG = {
    "INPUT_PKL": "mghp_root.pkl",
    "OUTPUT_TXT": "candidates.txt",
    "TOTAL_BUDGET": 1_000_000,
    "HPV_BUDGET_PERCENT": 10,
    "R_THRESHOLD": 0.8,
    "ENTROPY_THRESHOLD": 0.1,
    "SMOOTHING_ALPHA": 0.01,
    "HMLEA_ENUMERATION_LIMIT": 200_000,
    "LOWBYTE_ZERO_PREFIX_LEN": 14,
    "DEBUG_PRINT_LIMIT": 20,
}


class KBCNode:
    def __init__(self, key_type, key_value, depth):
        self.key_type = key_type
        self.key_value = key_value
        self.depth = depth
        self.children = {}
        self.ip_list = []
        self.iid_profile = {}
        self.meta_pattern = ""
        self.n_total = 0
        self.n_unique_64 = 0
        self.r_val = 0.0
        self.node_type = "Unknown"
        self.weight = 0.0
        self.budget = 0
        self.hpv_budget = 0
        self.lpv_budget = 0
        self._tmp_prefix_counts = None
        self._parent = None

    def get_children(self):
        return self.children.values()

    @property
    def is_leaf_64(self):
        return self.key_type == "subnet_leaf_64"

    def __repr__(self):
        return f"<{self.key_type}:{self.key_value} (IPs:{len(self.ip_list)})>"


class HPVHMLEAGenerator:
    STATIC_SUFFIXES = [
        "::1",
        "::80",
        "::443",
        "::2",
        "::53",
        "::22",
        "::3",
        "::8080",
        "::8443",
        "::21",
        "::25",
        "::3389",
        "::4",
        "::5",
    ]

    def __init__(self, entropy_threshold=0.1, alpha=0.01, enumeration_limit=200_000):
        self.threshold = entropy_threshold
        self.alpha = alpha
        self.enumeration_limit = enumeration_limit
        self.suffix_iids = [int(ipaddress.IPv6Address(s)) for s in self.STATIC_SUFFIXES]

    def generate(self, prefix_counts, total_seeds, budget):
        if budget <= 0 or not prefix_counts or total_seeds <= 0:
            return []

        fixed_vals, prob_tables, high_entropy_positions = self._build_entropy_model(
            prefix_counts,
            total_seeds,
        )
        theoretical_prefixes = 16 ** len(high_entropy_positions)
        theoretical_addresses = theoretical_prefixes * len(self.suffix_iids)

        if theoretical_addresses <= min(
            self.enumeration_limit, max(budget * 10, budget)
        ):
            return self._generate_by_enumeration(
                fixed_vals, high_entropy_positions, budget
            )
        return self._generate_by_sampling(fixed_vals, prob_tables, budget)

    def _build_entropy_model(self, prefix_counts, total):
        fixed_vals = {}
        prob_tables = {}
        high_entropy_positions = []

        for idx in range(16):
            counts = prefix_counts[idx]
            entropy = 0.0
            for cnt in counts.values():
                p = cnt / total
                entropy -= p * math.log2(p)

            if entropy < self.threshold:
                fixed_vals[idx] = counts.most_common(1)[0][0] if counts else "0"
            else:
                population = [hex(v)[2:] for v in range(16)]
                denom = total + 16 * self.alpha
                weights = [
                    (counts.get(ch, 0) + self.alpha) / denom for ch in population
                ]
                prob_tables[idx] = (population, weights)
                high_entropy_positions.append(idx)

        return fixed_vals, prob_tables, high_entropy_positions

    def _make_ip(self, prefix_hex, suffix_iid):
        prefix_int = int(prefix_hex + "0" * 16, 16)
        return str(ipaddress.IPv6Address(prefix_int | suffix_iid))

    def _suffixes_for_occurrence(self, occurrence):
        start = (occurrence * 3) % len(self.suffix_iids)
        return [
            self.suffix_iids[(start + offset) % len(self.suffix_iids)]
            for offset in range(3)
        ]

    def _generate_by_sampling(self, fixed_vals, prob_tables, budget):
        results = []
        prefix_occurrences = defaultdict(int)

        while len(results) < budget:
            chars = []
            for idx in range(16):
                if idx in fixed_vals:
                    chars.append(fixed_vals[idx])
                else:
                    population, weights = prob_tables[idx]
                    chars.append(random.choices(population, weights=weights, k=1)[0])
            prefix_hex = "".join(chars)

            occurrence = prefix_occurrences[prefix_hex]
            prefix_occurrences[prefix_hex] += 1
            for suffix_iid in self._suffixes_for_occurrence(occurrence):
                if len(results) >= budget:
                    break
                results.append(self._make_ip(prefix_hex, suffix_iid))

        return results

    def _generate_by_enumeration(self, fixed_vals, high_entropy_positions, budget):
        prefixes = []
        if high_entropy_positions:
            for combo in itertools.product(
                "0123456789abcdef", repeat=len(high_entropy_positions)
            ):
                chars = [fixed_vals.get(idx, "0") for idx in range(16)]
                for pos, ch in zip(high_entropy_positions, combo):
                    chars[pos] = ch
                prefixes.append("".join(chars))
        else:
            prefixes.append("".join(fixed_vals.get(idx, "0") for idx in range(16)))

        addresses = []
        for prefix_hex in prefixes:
            occurrence = 0
            while len(addresses) < budget and occurrence * 3 < len(self.suffix_iids):
                for suffix_iid in self._suffixes_for_occurrence(occurrence):
                    if len(addresses) >= budget:
                        break
                    addresses.append(self._make_ip(prefix_hex, suffix_iid))
                occurrence += 1
            if len(addresses) >= budget:
                break

        random.shuffle(addresses)
        if not addresses:
            return []
        while len(addresses) < budget:
            addresses.append(random.choice(addresses))
        return addresses[:budget]


class LPVIIDGenerator:
    CATEGORIES = [
        "EmbeddedPort",
        "LowByte",
        "EmbeddedIPv4",
        "EUI64",
        "BytePattern",
        "RandomLike",
    ]

    PORT_PLACEHOLDERS = [
        "21",
        "22",
        "23",
        "25",
        "49",
        "53",
        "80",
        "110",
        "123",
        "179",
        "220",
        "389",
        "443",
        "547",
        "993",
        "995",
        "1194",
        "3306",
        "5060",
        "5061",
        "5432",
        "6446",
        "8080",
    ]

    def __init__(self, lowbyte_zero_prefix_len=14, entropy_threshold=0.1, alpha=0.01):
        self.lowbyte_zero_prefix_len = lowbyte_zero_prefix_len
        self.entropy_threshold = entropy_threshold
        self.alpha = alpha
        self.port_iids = [port.zfill(16).lower() for port in self.PORT_PLACEHOLDERS]

    def generate(self, prefix_str, seeds, budget):
        if budget <= 0:
            return []
        try:
            prefix_net = ipaddress.IPv6Network(prefix_str, strict=False)
            prefix_base = int(prefix_net.network_address) & (0xFFFFFFFFFFFFFFFF << 64)
        except Exception:
            print(f"[DEBUG-LPV] Prefix parsing failed: {prefix_str}")
            return []

        categorized = {cat: [] for cat in self.CATEGORIES}
        for seed in seeds:
            try:
                iid_hex = self._iid_hex(seed)
            except Exception:
                continue
            cat = self.classify_iid_hex(iid_hex)
            categorized[cat].append(iid_hex)

        budgets = self._category_budgets(categorized, budget)
        iids = []
        carry = 0
        for cat in self.CATEGORIES:
            cat_budget = budgets[cat] + carry
            generated, unused = self._generate_category(
                cat, categorized[cat], cat_budget
            )
            iids.extend(generated)
            carry = unused

        return [
            str(ipaddress.IPv6Address(prefix_base | int(iid_hex, 16)))
            for iid_hex in iids[:budget]
        ]

    def _iid_hex(self, ip_str):
        ip_int = int(ipaddress.IPv6Address(ip_str))
        return f"{ip_int & 0xFFFFFFFFFFFFFFFF:016x}"

    def classify_iid_hex(self, iid):
        if iid in self.port_iids:
            return "EmbeddedPort"
        if iid[: self.lowbyte_zero_prefix_len] == "0" * self.lowbyte_zero_prefix_len:
            return "LowByte"
        if self._is_embedded_ipv4(iid):
            return "EmbeddedIPv4"
        if iid[6:10].lower() == "fffe":
            return "EUI64"
        if self._is_byte_pattern(iid):
            return "BytePattern"
        return "RandomLike"

    def _is_embedded_ipv4(self, iid):
        if iid[:8].lower() in {"00005efe", "02005efe", "00000000"}:
            return True
        if iid[:8].lower() == "00000000":
            return True
        if (
            iid[0:2] == "00"
            and iid[4:6] == "00"
            and iid[8:10] == "00"
            and iid[12:14] == "00"
        ):
            try:
                return all(int(iid[pos : pos + 2], 16) < 255 for pos in (2, 6, 10, 14))
            except Exception:
                return False
        return False

    def _is_byte_pattern(self, iid):
        zero_pairs = 0
        run = 0
        for ch in iid:
            if ch == "0":
                run += 1
            else:
                zero_pairs += run // 2
                run = 0
        zero_pairs += run // 2
        return zero_pairs >= 3

    def _category_budgets(self, categorized, budget):
        total = sum(len(categorized[cat]) for cat in self.CATEGORIES)
        budgets = {cat: 0 for cat in self.CATEGORIES}
        if total == 0:
            budgets["RandomLike"] = budget
            return budgets

        running = budget
        for cat in self.CATEGORIES[:-1]:
            value = int(budget * (len(categorized[cat]) / total))
            budgets[cat] = value
            running -= value
        budgets[self.CATEGORIES[-1]] = max(0, running)
        return budgets

    def _generate_category(self, cat, seeds, budget):
        if budget <= 0:
            return [], 0
        if cat == "EmbeddedPort":
            return self._generate_embedded_port(seeds, budget)
        if cat == "LowByte":
            return self._generate_lowbyte(seeds, budget)
        if cat == "EmbeddedIPv4":
            return self._generate_embedded_ipv4(seeds, budget)
        if cat == "EUI64":
            return self._replay_only(seeds, budget)
        if cat == "BytePattern":
            return self._generate_byte_pattern(seeds, budget)
        return self._replay_only(seeds, budget)

    def _replay_seed_iids(self, seeds, budget):
        replay = seeds[:budget]
        return replay, budget - len(replay)

    def _replay_only(self, seeds, budget):
        return self._replay_seed_iids(seeds, budget)

    def _generate_embedded_port(self, seeds, budget):
        generated, remaining = self._replay_seed_iids(seeds, budget)
        if remaining <= 0:
            return generated, 0

        used = set(seeds)
        for port_iid in self.port_iids:
            if remaining <= 0:
                break
            if port_iid in used:
                continue
            generated.append(port_iid)
            used.add(port_iid)
            remaining -= 1
        return generated, remaining

    def _generate_lowbyte(self, seeds, budget):
        generated, remaining = self._replay_seed_iids(seeds, budget)
        if remaining <= 0 or not seeds:
            return generated, remaining

        used = set(generated)
        seed_vals = [int(seed, 16) for seed in seeds]
        step = 1
        while remaining > 0:
            produced = False
            for value in seed_vals:
                candidate = value + step
                if candidate > 0xFFFFFFFFFFFFFFFF:
                    continue
                iid_hex = f"{candidate:016x}"
                if iid_hex in used:
                    continue
                used.add(iid_hex)
                generated.append(iid_hex)
                remaining -= 1
                produced = True
                if remaining <= 0:
                    break
            if not produced and step > remaining + len(seed_vals) + 65536:
                break
            step += 1
        return generated, remaining

    def _embedded_ipv4_groups(self, seeds):
        groups = {"isatap": [], "ipv4_32": [], "ipv4_64": []}
        for iid in seeds:
            prefix = iid[:8].lower()
            if prefix in {"00005efe", "02005efe", "00000000"}:
                groups["isatap"].append(iid)
            elif prefix == "00000000":
                groups["ipv4_32"].append(iid)
            elif (
                iid[0:2] == "00"
                and iid[4:6] == "00"
                and iid[8:10] == "00"
                and iid[12:14] == "00"
            ):
                groups["ipv4_64"].append(iid)
        return groups

    def _extract_ipv4_int(self, iid, subtype):
        if subtype in {"isatap", "ipv4_32"}:
            return int(iid[8:16], 16)
        return int(iid[2:4] + iid[6:8] + iid[10:12] + iid[14:16], 16)

    def _format_ipv4_iid(self, base_iid, subtype, ipv4_int):
        ipv4_hex = f"{ipv4_int:08x}"
        if subtype in {"isatap", "ipv4_32"}:
            return base_iid[:8] + ipv4_hex
        return (
            "00"
            + ipv4_hex[0:2]
            + "00"
            + ipv4_hex[2:4]
            + "00"
            + ipv4_hex[4:6]
            + "00"
            + ipv4_hex[6:8]
        )

    def _generate_embedded_ipv4(self, seeds, budget):
        generated, remaining = self._replay_seed_iids(seeds, budget)
        if remaining <= 0 or not seeds:
            return generated, remaining

        groups = self._embedded_ipv4_groups(seeds)
        used = set(generated)
        active = [(subtype, iid) for subtype, iids in groups.items() for iid in iids]
        offset = 1
        while remaining > 0 and active:
            produced = False
            for subtype, iid in active:
                base = self._extract_ipv4_int(iid, subtype)
                for candidate_ipv4 in (base + offset, base - offset):
                    if remaining <= 0:
                        break
                    if not (0 <= candidate_ipv4 <= 0xFFFFFFFF):
                        continue
                    candidate = self._format_ipv4_iid(iid, subtype, candidate_ipv4)
                    if candidate in used:
                        continue
                    used.add(candidate)
                    generated.append(candidate)
                    remaining -= 1
                    produced = True
            if not produced and offset > remaining + len(active) + 65536:
                break
            offset += 1
        return generated, remaining

    def _generate_byte_pattern(self, seeds, budget):
        generated, remaining = self._replay_seed_iids(seeds, budget)
        if remaining <= 0:
            return generated, 0
        if not seeds:
            return generated, remaining

        fixed_vals = {}
        prob_tables = {}
        for idx in range(16):
            counts = Counter(seed[idx] for seed in seeds)
            entropy = 0.0
            total = len(seeds)
            for cnt in counts.values():
                p = cnt / total
                entropy -= p * math.log2(p)
            if entropy < self.entropy_threshold:
                fixed_vals[idx] = counts.most_common(1)[0][0]
            else:
                population = [hex(v)[2:] for v in range(16)]
                denom = total + 16 * self.alpha
                weights = [
                    (counts.get(ch, 0) + self.alpha) / denom for ch in population
                ]
                prob_tables[idx] = (population, weights)

        while remaining > 0:
            chars = []
            for idx in range(16):
                if idx in fixed_vals:
                    chars.append(fixed_vals[idx])
                else:
                    population, weights = prob_tables[idx]
                    chars.append(random.choices(population, weights=weights, k=1)[0])
            generated.append("".join(chars))
            remaining -= 1
        return generated, 0


# Stage 2: BAG
class BudgetController:
    def __init__(
        self,
        kbc_root,
        total_budget,
        hpv_k=None,
        suppressed_alias_prefixes=None,
        max_attempt_factor=3,
        return_stats=False,
        hpv_budget_percent=None,
        r_threshold=None,
    ):
        self.root = kbc_root
        print("[*] Initializing tree node attributes (completing budget/weight)...")
        self._init_tree_attributes(self.root)

        self.total_budget = int(total_budget)
        self.hpv_budget_percent = (
            BAG_CONFIG["HPV_BUDGET_PERCENT"]
            if hpv_budget_percent is None
            else hpv_budget_percent
        )
        self.r_threshold = (
            BAG_CONFIG["R_THRESHOLD"] if r_threshold is None else r_threshold
        )
        self.max_attempt_factor = max_attempt_factor
        self.return_stats = return_stats
        self.suppressed_alias_prefixes = self._parse_alias_prefixes(
            suppressed_alias_prefixes or []
        )
        self.hmlea = HPVHMLEAGenerator(
            entropy_threshold=BAG_CONFIG["ENTROPY_THRESHOLD"],
            alpha=BAG_CONFIG["SMOOTHING_ALPHA"],
            enumeration_limit=BAG_CONFIG["HMLEA_ENUMERATION_LIMIT"],
        )
        self.lpv_iid = LPVIIDGenerator(
            lowbyte_zero_prefix_len=BAG_CONFIG["LOWBYTE_ZERO_PREFIX_LEN"],
            entropy_threshold=BAG_CONFIG["ENTROPY_THRESHOLD"],
            alpha=BAG_CONFIG["SMOOTHING_ALPHA"],
        )

        self.hpv_nodes = []
        self.lpv_leaves = []
        self.stats = {
            "HPV_Nodes": 0,
            "LPV_Nodes": 0,
            "LPV_Leaves": 0,
            "Leaves_With_Seeds": 0,
            "Leaves_Zero_Seeds": 0,
            "Budget_Truncated": 0,
            "generated_candidates_raw": 0,
            "alias_candidate_hits": 0,
            "duplicate_hits": 0,
            "failed_generation": 0,
            "abandoned_budget": 0,
            "max_attempts": 0,
            "max_attempts_reached": 0,
            "suppressed_alias_prefix_count": len(self.suppressed_alias_prefixes),
            "hpv_budget": 0,
            "lpv_budget": 0,
        }

    def _init_tree_attributes(self, node):
        for attr, value in (
            ("budget", 0),
            ("hpv_budget", 0),
            ("lpv_budget", 0),
            ("weight", 0.0),
            ("node_type", "Unknown"),
            ("n_total", 0),
            ("n_unique_64", 0),
            ("r_val", 0.0),
            ("_tmp_prefix_counts", None),
        ):
            if not hasattr(node, attr):
                setattr(node, attr, value)
            else:
                setattr(node, attr, value)
        for child in node.get_children():
            self._init_tree_attributes(child)

    def _parse_alias_prefixes(self, prefixes):
        parsed = []
        for prefix in prefixes:
            try:
                parsed.append(ipaddress.IPv6Network(str(prefix).strip(), strict=False))
            except Exception:
                continue
        return parsed

    def _is_suppressed_alias_candidate(self, ip_str):
        if not self.suppressed_alias_prefixes:
            return False
        try:
            ip_obj = ipaddress.IPv6Address(ip_str)
        except Exception:
            return False
        return any(ip_obj in prefix for prefix in self.suppressed_alias_prefixes)

    def process(self):
        print("\n=== [DEBUG] Step 1: Collecting statistics (bottom-up) ===")
        self._calc_metrics_recursive(self.root)
        print(
            f"-> Root statistics: N_total={self.root.n_total}, Unique /64={self.root.n_unique_64}"
        )
        if self.root.n_total == 0:
            print(
                "[!!!CRITICAL ERROR!!!] Root nodes IP count is zero. Check whether Stage 1 saved ip_list correctly."
            )
            return ([], self.stats) if self.return_stats else []

        print("\n=== [DEBUG] Step 2: Classifying nodes (top-down) ===")
        self._classify_nodes(self.root)
        print(
            f"-> Classification: HPV nodes={self.stats['HPV_Nodes']}, LPV nodes={self.stats['LPV_Nodes']}"
        )
        print(
            f"-> LPVleaf nodes={self.stats['LPV_Leaves']}, leaves with seeds={self.stats['Leaves_With_Seeds']}, leaves without seeds={self.stats['Leaves_Zero_Seeds']}"
        )

        print("\n=== [DEBUG] Step 3: Splitting the HPV/LPV budget pools ===")
        self._allocate_budgets()
        print(
            f"-> HPV budget={self.stats['hpv_budget']}, LPV budget={self.stats['lpv_budget']}"
        )

        print("\n=== [DEBUG] Step 4: Generating addresses ===")
        candidates = self._generate_with_alias_filter()
        return (candidates, self.stats) if self.return_stats else candidates

    def _calc_metrics_recursive(self, node):
        if node.is_leaf_64:
            node.n_total = len(node.ip_list)
            node.n_unique_64 = 1 if node.n_total > 0 else 0
            node.r_val = (node.n_unique_64 / node.n_total) if node.n_total > 0 else 0.0
            if node.n_total > 0:
                self.stats["Leaves_With_Seeds"] += 1
            else:
                self.stats["Leaves_Zero_Seeds"] += 1
            return node.n_total, node.n_unique_64

        t_ips = 0
        t_leaves = 0
        for child in node.get_children():
            c_ips, c_leaves = self._calc_metrics_recursive(child)
            t_ips += c_ips
            t_leaves += c_leaves

        node.n_total = t_ips
        node.n_unique_64 = t_leaves
        node.r_val = (t_leaves / t_ips) if t_ips > 0 else 0.0
        return t_ips, t_leaves

    def _classify_nodes(self, node):
        if node.is_leaf_64:
            node.node_type = "LPV"
            self.stats["LPV_Nodes"] += 1
            self.stats["LPV_Leaves"] += 1
            self.lpv_leaves.append(node)
            return

        if node.n_total == 1 and abs(node.r_val - 1.0) < 1e-12:
            node.node_type = "LPV"
            self.stats["LPV_Nodes"] += 1
        elif self.r_threshold <= node.r_val <= 1.0:
            node.node_type = "HPV"
            self.stats["HPV_Nodes"] += 1
            self.hpv_nodes.append(node)
        else:
            node.node_type = "LPV"
            self.stats["LPV_Nodes"] += 1

        for child in node.get_children():
            self._classify_nodes(child)

    def _allocate_budgets(self):
        hpv_budget = int(self.total_budget * (self.hpv_budget_percent / 100.0))
        hpv_budget = max(0, min(self.total_budget, hpv_budget))
        lpv_budget = self.total_budget - hpv_budget
        self.stats["hpv_budget"] = hpv_budget
        self.stats["lpv_budget"] = lpv_budget

        self._allocate_hpv_budget(hpv_budget)
        self._allocate_lpv_budget_recursive(self.root, lpv_budget)

    def _allocate_hpv_budget(self, hpv_budget):
        if hpv_budget <= 0 or not self.hpv_nodes:
            return
        scores = [max(0.0, node.r_val * node.n_total) for node in self.hpv_nodes]
        total_score = sum(scores)
        if total_score <= 0:
            return

        remaining = hpv_budget
        for node, score in zip(self.hpv_nodes[:-1], scores[:-1]):
            value = int(hpv_budget * (score / total_score))
            node.hpv_budget = value
            node.budget += value
            remaining -= value
        self.hpv_nodes[-1].hpv_budget = max(0, remaining)
        self.hpv_nodes[-1].budget += max(0, remaining)

    def _allocate_lpv_budget_recursive(self, node, budget):
        if budget <= 0:
            return
        if node.is_leaf_64:
            node.lpv_budget += budget
            node.budget += budget
            return

        lpv_children = [
            child for child in node.get_children() if child.node_type == "LPV"
        ]
        if not lpv_children:
            return
        total = sum(max(0, child.n_total) for child in lpv_children)
        if total <= 0:
            return

        remaining = budget
        for child in lpv_children[:-1]:
            value = int(budget * (child.n_total / total))
            self._allocate_lpv_budget_recursive(child, value)
            remaining -= value
        self._allocate_lpv_budget_recursive(lpv_children[-1], max(0, remaining))

    def _generate_with_alias_filter(self):
        candidates = []
        max_attempts = max(
            int(self.total_budget * self.max_attempt_factor), self.total_budget
        )
        self.stats["max_attempts"] = max_attempts

        while (
            len(candidates) < self.total_budget
            and self.stats["generated_candidates_raw"] < max_attempts
        ):
            batch = self._generate_batch()
            if not batch:
                self.stats["failed_generation"] += 1
                break

            accepted_this_batch = 0
            alias_hits_before = self.stats["alias_candidate_hits"]
            for ip in batch:
                if self.stats["generated_candidates_raw"] >= max_attempts:
                    break
                self.stats["generated_candidates_raw"] += 1
                if self._is_suppressed_alias_candidate(ip):
                    self.stats["alias_candidate_hits"] += 1
                    continue
                candidates.append(ip)
                accepted_this_batch += 1
                if len(candidates) >= self.total_budget:
                    break

            alias_hits_this_batch = (
                self.stats["alias_candidate_hits"] - alias_hits_before
            )
            if alias_hits_this_batch == 0:
                break
            if (
                accepted_this_batch == 0
                and self.stats["generated_candidates_raw"] >= max_attempts
            ):
                break

        if len(candidates) < self.total_budget:
            self.stats["abandoned_budget"] = self.total_budget - len(candidates)
            if self.stats["generated_candidates_raw"] >= max_attempts:
                self.stats["max_attempts_reached"] = 1
                print("\n[WARNING][A0_pro] Candidate generation reached max_attempts.")
                print(f"  round_budget = {self.total_budget}")
                print(f"  generated_candidates = {len(candidates)}")
                print(f"  abandoned_budget = {self.stats['abandoned_budget']}")
                print(f"  alias_candidate_hits = {self.stats['alias_candidate_hits']}")
                print(f"  failed_generation = {self.stats['failed_generation']}")
                print(f"  max_attempts = {max_attempts}")
                print(
                    "  This round will continue with fewer probes; abandoned budget is not redistributed.\n"
                )
        return candidates

    def _generate_batch(self):
        results = []
        debug_printed = 0

        for node in self.hpv_nodes:
            if node.hpv_budget <= 0:
                continue
            if debug_printed < BAG_CONFIG["DEBUG_PRINT_LIMIT"]:
                print(
                    f"  [Gen-HPV] Node {node.key_type}:{node.key_value} Budget: {node.hpv_budget}, Seeds: {node.n_total}, r={node.r_val:.4f}"
                )
                debug_printed += 1
            prefix_counts, total_seeds = self._build_tmp_prefix_counts_bottom_up(node)
            results.extend(
                self.hmlea.generate(prefix_counts, total_seeds, node.hpv_budget)
            )
            self._clear_tmp_prefix_counts(node)

        for leaf in self.lpv_leaves:
            if leaf.lpv_budget <= 0:
                continue
            if debug_printed < BAG_CONFIG["DEBUG_PRINT_LIMIT"]:
                print(
                    f"  [Gen-LPV] Leaf {leaf.key_value} Budget: {leaf.lpv_budget}, Seeds: {len(leaf.ip_list)}"
                )
                debug_printed += 1
            results.extend(
                self.lpv_iid.generate(leaf.key_value, leaf.ip_list, leaf.lpv_budget)
            )

        return results

    def _build_tmp_prefix_counts_bottom_up(self, node):
        if node.is_leaf_64:
            counts = [Counter() for _ in range(16)]
            total = 0
            for ip in node.ip_list:
                try:
                    h = ipaddress.IPv6Address(ip).exploded.replace(":", "")
                except Exception:
                    continue
                for idx in range(16):
                    counts[idx][h[idx]] += 1
                total += 1
            node._tmp_prefix_counts = counts
            return counts, total

        counts = [Counter() for _ in range(16)]
        total = 0
        for child in node.get_children():
            child_counts, child_total = self._build_tmp_prefix_counts_bottom_up(child)
            total += child_total
            for idx in range(16):
                counts[idx].update(child_counts[idx])
        node._tmp_prefix_counts = counts
        return counts, total

    def _clear_tmp_prefix_counts(self, node):
        node._tmp_prefix_counts = None
        for child in node.get_children():
            self._clear_tmp_prefix_counts(child)


if __name__ == "__main__":
    print("--- Stage 2 (A0_pro_full) started ---")

    pkl_path = BAG_CONFIG["INPUT_PKL"]
    if not os.path.exists(pkl_path):
        print(f"[!] Error: not found {pkl_path}")
        sys.exit(1)

    print(f"[*] Loading {pkl_path} ...")
    with open(pkl_path, "rb") as f:
        kbc_root = pickle.load(f)

    controller = BudgetController(
        kbc_root,
        BAG_CONFIG["TOTAL_BUDGET"],
        hpv_budget_percent=BAG_CONFIG["HPV_BUDGET_PERCENT"],
    )
    candidates = controller.process()

    out_file = BAG_CONFIG["OUTPUT_TXT"]
    print(f"[*] Writing {out_file} (Format: Linux LF) ...")
    with open(out_file, "w", encoding="utf-8", newline="\n") as f:
        for ip in candidates:
            f.write(ip + "\n")

    print("--- Stage 2 completed ---")

