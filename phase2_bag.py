#!/usr/bin/env python3.10
# encoding:utf-8

"""
6Hierarchical - Phase 2: BAG (Budget-based Address Generation)

Loads the MGHP prefix tree (serialized as PKL) from Phase 1,
classifies nodes as HPV/LPV, allocates budget proportionally,
and generates candidate IPv6 addresses.
"""

import pickle
import random
import ipaddress
import sys
import os
import math
from collections import Counter, defaultdict

# =======================================================================
# Configuration
# =======================================================================

BAG_CONFIG = {
    "INPUT_PKL": "kbc_root.pkl",
    "OUTPUT_TXT": "candidates.txt",
    "TOTAL_BUDGET": 1000000,
    "HPV_BONUS_K": 2.0,
    "R_THRESHOLD": 0.8,
    "ENTROPY_THRESHOLD": 0.1,
    "SMOOTHING_ALPHA": 0.01,
    "DEBUG_PRINT_LIMIT": 20
}


# =======================================================================
# MGHP Tree Node Definition
# =======================================================================

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
        self._parent = None

    def get_children(self):
        return self.children.values()

    @property
    def is_leaf_64(self):
        return self.key_type == "subnet_leaf_64"

    def __repr__(self):
        return f"<{self.key_type}:{self.key_value} (IPs:{len(self.ip_list)})>"


# =======================================================================
# HMLEA Generator (Entropy-based address generation for HPV nodes)
# =======================================================================

class HMLEAGenerator:
    def __init__(self, entropy_threshold=0.1, alpha=0.01):
        self.threshold = entropy_threshold
        self.alpha = alpha

    def generate_prefixes(self, leaf_node, count):
        if count <= 0: return []

        if not leaf_node.ip_list:
            print(f"[DEBUG-HMLEA] Warning: leaf node {leaf_node.key_value} has no seed IPs, skipping.")
            return []

        seeds_hex = []
        for ip in leaf_node.ip_list:
            try:
                h = ipaddress.IPv6Address(ip).exploded.replace(':', '')
                seeds_hex.append(h)
            except:
                pass

        if not seeds_hex:
            return []

        generated_prefixes = []
        prob_tables = {}
        fixed_vals = {}

        for k in range(16):
            chars = [s[k] for s in seeds_hex]
            c = Counter(chars)
            total = len(chars)
            entropy = 0
            for char, cnt in c.items():
                p = cnt / total
                entropy -= p * math.log2(p)
            if entropy < self.threshold:
                fixed_vals[k] = c.most_common(1)[0][0]
            else:
                denom = total + 16 * self.alpha
                population = []
                weights = []
                for char_code in range(16):
                    char = hex(char_code)[2:]
                    cnt = c.get(char, 0)
                    prob = (cnt + self.alpha) / denom
                    population.append(char)
                    weights.append(prob)
                prob_tables[k] = (population, weights)

        for _ in range(count):
            new_prefix_list = []
            for k in range(16):
                if k in fixed_vals:
                    new_prefix_list.append(fixed_vals[k])
                else:
                    pop, w = prob_tables[k]
                    char = random.choices(pop, weights=w, k=1)[0]
                    new_prefix_list.append(char)

            hex_str = "".join(new_prefix_list)
            final_ip_int = int(hex_str + "0" * 15 + "1", 16)
            generated_prefixes.append(str(ipaddress.IPv6Address(final_ip_int)))

        return generated_prefixes


# =======================================================================
# ComplexIID Generator (Template-based generation for LPV nodes)
# =======================================================================

class ComplexIIDGenerator:
    def __init__(self):
        self.STATIC_LIST = [
            "::1", "::2", "::3", "::4", "::5",
            "::80", "::443", "::21", "::22", "::25", "::53",
            "::8080", "::3389", "::110", "::143", "::445",
            "::5432", "::5900", "::8443"
        ]
        self.COMMON_PORTS = {80, 443, 53, 22, 21, 23, 25, 110, 143, 8080, 8443, 3306, 3389, 6379, 5353, 8000}

    def classify_iid(self, ipv6_addr):
        try:
            ip_int = int(ipaddress.IPv6Address(ipv6_addr))
            iid = ip_int & 0xFFFFFFFFFFFFFFFF
            if iid in self.COMMON_PORTS: return "C_Port"
            if iid <= 255: return "C_Low"
            iid_high_32 = iid >> 32
            if iid_high_32 in [0x00005EFE, 0x02005EFE]: return "C_IPv4"
            if iid_high_32 == 0 and iid > 0xFFFF: return "C_IPv4"
            segs = [(iid >> (16 * i)) & 0xFFFF for i in range(3, -1, -1)]
            if segs[0] == segs[1] == segs[2] == segs[3]: return "C_Byte"
            zeros = segs.count(0)
            small_vals = sum(1 for s in segs if 0 < s <= 255)
            if zeros >= 1 and (zeros + small_vals == 4): return "C_Byte"
            if (iid >> 24) & 0xFFFF == 0xFFFE: return "C_Ieee"
            if iid > 0x1000000000000: return "C_Rand"
            return "C_Other"
        except:
            return "Error"

    def generate_lpv_iids(self, prefix_str, seeds, budget):
        if not seeds:
            print(f"[DEBUG-LPV] Warning: LPV node {prefix_str} has no seeds, generating static only.")

        generated_iids = set()
        try:
            prefix_net = ipaddress.IPv6Network(prefix_str)
            prefix_base = int(prefix_net.network_address) & (0xFFFFFFFFFFFFFFFF << 64)
        except:
            print(f"[DEBUG-LPV] Error: prefix parse failed: {prefix_str}")
            return []

        for suffix in self.STATIC_LIST:
            val = int(suffix.replace(':', ''), 16)
            generated_iids.add(val)

        remaining_budget = budget - len(generated_iids)
        if remaining_budget <= 0:
            return self._format_ips(prefix_base, generated_iids)

        classified_seeds = defaultdict(list)
        for ip in seeds:
            cat = self.classify_iid(ip)
            classified_seeds[cat].append(ip)

        if classified_seeds["C_Low"]:
            max_val = 0
            for ip in classified_seeds["C_Low"]:
                iid = int(ipaddress.IPv6Address(ip)) & 0xFFFFFFFFFFFFFFFF
                if iid > max_val: max_val = iid
            for i in range(1, int(remaining_budget * 0.4) + 1):
                generated_iids.add(max_val + i)

        return self._format_ips(prefix_base, generated_iids)

    def _format_ips(self, prefix_base, iid_set):
        ips = []
        for iid in iid_set:
            final_int = prefix_base | iid
            ips.append(str(ipaddress.IPv6Address(final_int)))
        return ips


# =======================================================================
# Budget Controller
# =======================================================================

class BudgetController:
    def __init__(self, kbc_root, total_budget, hpv_k):
        self.root = kbc_root

        print("[*] Initializing tree node attributes...")
        self._init_tree_attributes(self.root)

        self.total_budget = total_budget
        self.hpv_k = hpv_k
        self.hmlea = HMLEAGenerator(
            entropy_threshold=BAG_CONFIG["ENTROPY_THRESHOLD"],
            alpha=BAG_CONFIG["SMOOTHING_ALPHA"]
        )
        self.complex_iid = ComplexIIDGenerator()

        self.stats = {
            "HPV_Nodes": 0, "LPV_Nodes": 0,
            "Total_IPs_Found": 0, "Leaves_With_Seeds": 0,
            "Leaves_Zero_Seeds": 0, "Budget_Truncated": 0,
            'is_HPV_LEAF_SIZE_1': 0
        }

    def _init_tree_attributes(self, node):
        if not hasattr(node, 'budget'):
            node.budget = 0
        if not hasattr(node, 'weight'):
            node.weight = 0.0
        if not hasattr(node, 'node_type'):
            node.node_type = "Unknown"
        if not hasattr(node, 'n_total'):
            node.n_total = 0
        if not hasattr(node, 'n_unique_64'):
            node.n_unique_64 = 0
        if not hasattr(node, 'r_val'):
            node.r_val = 0.0

        for child in node.get_children():
            self._init_tree_attributes(child)

    def process(self):
        print("\n=== [DEBUG] Step 1: Compute metrics (Bottom-up) ===")
        self._calc_metrics_recursive(self.root)
        print(f"-> Root stats: N_total={self.root.n_total}, Unique /64={self.root.n_unique_64}")
        if self.root.n_total == 0:
            print("[!!!] Root node IP count is 0! Check if Phase 1 saved ip_list correctly.")
            return []

        print("\n=== [DEBUG] Step 2: Node classification and weight (Top-down) ===")
        self._calc_weight_recursive(self.root)
        print(f"-> Classification: HPV={self.stats['HPV_Nodes']}, LPV={self.stats['LPV_Nodes']}")
        print(f"-> Leaves: with_seeds={self.stats['Leaves_With_Seeds']}, no_seeds={self.stats['Leaves_Zero_Seeds']}")
        print(f"-> Leaves: HPV & single_ip={self.stats['is_HPV_LEAF_SIZE_1']}")

        print("\n=== [DEBUG] Step 3: Budget allocation (Top-down) ===")
        self.root.budget = self.total_budget
        self._distribute_budget_recursive(self.root)

        print("\n=== [DEBUG] Step 4: Address generation ===")
        candidates = self._generate_recursive(self.root)
        return candidates

    def _calc_metrics_recursive(self, node):
        if node.is_leaf_64:
            node.n_total = len(node.ip_list)
            node.n_unique_64 = 1
            node.r_val = 1.0
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
        if node.n_total > 0:
            node.r_val = node.n_unique_64 / node.n_total
        else:
            node.r_val = 0.0
        return t_ips, t_leaves

    def _calc_weight_recursive(self, node):
        if BAG_CONFIG["R_THRESHOLD"] <= node.r_val <= 1.0:
            node.node_type = "HPV"
            node.weight = node.n_total * self.hpv_k
            self.stats["HPV_Nodes"] += 1
        else:
            node.node_type = "LPV"
            node.weight = node.n_total * 1.0
            self.stats["LPV_Nodes"] += 1

        if node.is_leaf_64 and node.n_total == 1 and node.node_type == 'HPV':
            self.stats['is_HPV_LEAF_SIZE_1'] += 1

        for child in node.get_children():
            self._calc_weight_recursive(child)

    def _distribute_budget_recursive(self, node):
        if node.depth < 2 and node.budget > 0:
            print(f"  [Depth {node.depth}] Node {node.key_value} budget: {node.budget}")

        if node.is_leaf_64: return

        children = list(node.get_children())
        if not children: return

        sum_w = sum(c.weight for c in children)

        if sum_w > 0:
            for child in children:
                raw_budget = node.budget * (child.weight / sum_w)

                if 0 < raw_budget < 1.0:
                    child.budget = 1 if random.random() < raw_budget else 0
                    if child.budget == 0: self.stats["Budget_Truncated"] += 1
                else:
                    child.budget = int(raw_budget)

                if child.budget > 0:
                    self._distribute_budget_recursive(child)
        else:
            if node.budget > 0 and node.depth < 2:
                print(f"  [WARNING] Node {node.key_value} has budget {node.budget} but children have no weight (no seeds), budget lost!")

    def _generate_recursive(self, node):
        results = []
        if node.is_leaf_64:
            if node.budget > 0:
                if self.stats["Total_IPs_Found"] < BAG_CONFIG["DEBUG_PRINT_LIMIT"]:
                    print(
                        f"  [Gen] Leaf {node.key_value} (Type {node.node_type}) Budget: {node.budget}, Seeds: {len(node.ip_list)}")

                if node.node_type == "HPV":
                    prefixes = self.hmlea.generate_prefixes(node, node.budget)
                    results.extend(prefixes)
                else:
                    prefix = node.key_value
                    seeds = node.ip_list
                    new_ips = self.complex_iid.generate_lpv_iids(prefix, seeds, node.budget)
                    results.extend(new_ips)

                self.stats["Total_IPs_Found"] += len(results)
            return results

        for child in node.get_children():
            results.extend(self._generate_recursive(child))
        return results


# =======================================================================
# Main Entry
# =======================================================================

if __name__ == "__main__":
    print("--- Phase 2 (BAG) started ---")

    pkl_path = BAG_CONFIG["INPUT_PKL"]
    if not os.path.exists(pkl_path):
        print(f"[!] Error: {pkl_path} not found")
        sys.exit(1)

    print(f"[*] Loading {pkl_path} ...")
    with open(pkl_path, 'rb') as f:
        kbc_root = pickle.load(f)

    print(f"[*] Root loaded. Children: {len(kbc_root.children)}")
    if hasattr(kbc_root, 'ip_list') and len(kbc_root.children) > 0:
        first_child = list(kbc_root.children.values())[0]
        print(f"[*] Sample child: Type={first_child.key_type}, Value={first_child.key_value}")

    controller = BudgetController(kbc_root, BAG_CONFIG["TOTAL_BUDGET"], BAG_CONFIG["HPV_BONUS_K"])
    candidates = controller.process()

    out_file = BAG_CONFIG["OUTPUT_TXT"]
    unique_candidates = list(set(candidates))

    print(f"\n=== [DEBUG] Final Report ===")
    print(f"1. Total budget: {BAG_CONFIG['TOTAL_BUDGET']}")
    print(f"2. Generated: {len(candidates)}")
    print(f"3. After dedup: {len(unique_candidates)}")
    print(f"4. Budget truncated: {controller.stats['Budget_Truncated']} (optimized via probabilistic compensation)")

    if len(unique_candidates) == 0:
        print("\n[!!!] Warning: 0 candidates generated. Check logs above:")
        print("  - 'Leaves_With_Seeds' == 0? -> Phase 1 did not save IP data")
        print("  - Root 'N_total' == 0? -> Same issue")
    else:
        print(f"[*] Writing to {out_file} (Format: Linux LF) ...")
        with open(out_file, 'w', encoding='utf-8', newline='\n') as f:
            for ip in unique_candidates:
                f.write(ip + '\n')

    print("--- Phase 2 complete ---")
