#!/usr/bin/env python3.10
# encoding:utf-8

"""
6Hierarchical - Phase 1: MGHP (Metadata-Guided Hierarchical Partitioning)

MGHP builds a hierarchical prefix tree (referred to as "KBC tree" in code)
from seed IPv6 addresses. The tree structure: Country -> ASN -> Province ->
Network Prefix -> Subnet Prefix -> /64 Leaf.

1. KBCBuilder: builds the hierarchical Trie tree.
2. update_node_counts: post-processing for weight calculation.
"""

import pandas as pd
import ipaddress
import sys
import re
from collections import defaultdict, Counter
import pickle
import os


# =======================================================================
# MGHP Tree Node and Builder
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
        self.ip_count = 0
        self.leaf_count = 0
        self._parent = None

    def get_children(self):
        return self.children.values()

    @property
    def is_leaf_64(self):
        return self.key_type == "subnet_leaf_64"

    @property
    def is_parent(self):
        return not self.is_leaf_64

    def __repr__(self):
        meta = ""
        if self.meta_pattern: meta = f" [Meta: {self.meta_pattern}]"
        if self.is_leaf_64: meta = f" [IIDs: {len(self.ip_list)}]"
        return f"KBCNode({self.key_type}='{self.key_value}', children={len(self.children)}{meta})"


class KBCBuilder:
    def __init__(self):
        self.root = KBCNode(key_type="root", key_value="root", depth=0)
        self.SERVICE_PORTS = [
            '80', '443', '22', '21', '25', '3389', '5432', '3306',
            '8080', '8443', '53', '443', '110', '143', '445', '5900',
            '6379', '27017', '67', '161'
        ]
        self.PORT_PATTERNS = {port: '0' * (16 - len(port)) + port for port in self.SERVICE_PORTS}

    def build_tree(self, csv_file_path):
        print(f"[+] 1. (MGHP) Building Trie tree from {csv_file_path}...")
        try:
            df = pd.read_csv(csv_file_path)
            df.columns = df.columns.str.strip()
            df = df.rename(columns={'IPv6': 'IPv6Address'})
            required_cols = [
                'IPv6Address', 'country', 'province', 'asnum',
                'network_prefix', 'subnet_prefix'
            ]
            if not all(col in df.columns for col in required_cols):
                print(f"Error: CSV missing required columns! Need: {required_cols}", file=sys.stderr)
                return None
            df[required_cols] = df[required_cols].fillna('Unknown')
        except Exception as e:
            print(f"Error: Failed to read CSV: {e}", file=sys.stderr)
            return None

        print(f"[+] 1.2 (MGHP) Inserting {len(df)} IP records...")
        for _, row in df.iterrows():
            self.insert_ip(row)
        print(f"[+] 1.2 (MGHP) Insertion complete.")

        print("[+] 1.3 (MGHP) Traversing Trie tree, extracting IID templates...")
        self.run_iid_extraction(self.root)
        print("[+] 1.4 (MGHP) Recursively tagging all parent nodes with meta-patterns (PV+IV)...")
        self.run_metapattern_tagging(self.root)

        print("[+] Phase 1 (MGHP) build complete!")
        return self.root

    def insert_ip(self, row):
        try:
            country = str(row['country'])
            node = self.root.children.setdefault(country, KBCNode(key_type="country", key_value=country, depth=1))
            asn = str(row['asnum'])
            node = node.children.setdefault(asn, KBCNode(key_type="asn", key_value=asn, depth=2))
            province = str(row['province'])
            node = node.children.setdefault(province, KBCNode(key_type="province", key_value=province, depth=3))
            net_prefix = str(row['network_prefix'])
            node = node.children.setdefault(net_prefix, KBCNode(key_type="network", key_value=net_prefix, depth=4))
            sub_prefix_whois = str(row['subnet_prefix'])
            node = node.children.setdefault(sub_prefix_whois,
                                            KBCNode(key_type="subnet_whois", key_value=sub_prefix_whois, depth=5))
            ip_str = str(row['IPv6Address'])
            if ip_str == 'Unknown' or not ip_str: return
            try:
                ip_obj = ipaddress.IPv6Address(ip_str)
                true_64_prefix_net = ipaddress.IPv6Network(((int(ip_obj) & (2 ** 128 - 2 ** 64)), 64))
                true_64_prefix_str = str(true_64_prefix_net)
            except Exception as e:
                return
            leaf_node = node.children.setdefault(true_64_prefix_str,
                                                 KBCNode(key_type="subnet_leaf_64", key_value=true_64_prefix_str,
                                                         depth=6))
            leaf_node.ip_list.append(ip_str)
        except (KeyError, TypeError, AttributeError) as e:
            pass

    def run_iid_extraction(self, node):
        if node.key_type == "subnet_leaf_64":
            self.extract_iid_templates(node)
            return
        for child in node.children.values():
            self.run_iid_extraction(child)

    def _classify_iid_patterns(self, ip_list):
        if not ip_list: return {"GT-NoData": 1.0}
        counts = Counter()
        hex_iids = []
        for ip_str in ip_list:
            try:
                ip_obj = ipaddress.IPv6Address(ip_str)
                hex_addr = f"{int(ip_obj):032x}"
                hex_iids.append(hex_addr[-16:])
            except ipaddress.AddressValueError:
                continue
        if not hex_iids: return {"GT-NoData": 1.0}
        for last16 in hex_iids:
            if any(last16 == pattern for pattern in self.PORT_PATTERNS.values()):
                counts['EmbeddedPort'] += 1;
                continue
            m = re.match(r'^(0+)', last16)
            if m and len(m.group(1)) >= 12:
                counts['LowByte'] += 1;
                continue
            if last16[6:10].lower() == 'fffe':
                counts['IeeeDerived'] += 1;
                continue
            if (last16[0:2] == '00' and last16[10:16] == '000000') or \
                    (last16[0:8].lower() == '02005efe') or \
                    (last16[0:2] == '00' and last16[4:6] == '00' and last16[8:10] == '00' and last16[12:14] == '00'):
                counts['EmbeddedIPv4'] += 1;
                continue
            if len(set(last16)) >= 8:
                counts['RandomGen'] += 1;
                continue
            if (last16[0:9] == '0' * 9 and last16[9] == '2' and last16[12] == '0' and last16[13] == '0') or \
                    (last16[0:9] == '0' * 9 and last16[9] == '1' and last16[12] == '0'):
                counts['BytePattern'] += 1;
                continue
            counts['Others'] += 1
        total_count = len(hex_iids)
        if total_count == 0: return {"GT-NoData": 1.0}
        profile = {key: round(value / total_count, 4) for key, value in counts.items()}
        for key in ['EmbeddedPort', 'LowByte', 'IeeeDerived', 'EmbeddedIPv4', 'RandomGen', 'BytePattern', 'Others']:
            profile.setdefault(key, 0.0)
        return profile

    def extract_iid_templates(self, leaf_node):
        leaf_node.iid_profile = self._classify_iid_patterns(leaf_node.ip_list)

    def run_metapattern_tagging(self, node):
        if node.key_type == "subnet_leaf_64":
            profile_str = str(node.iid_profile) if node.iid_profile else "GT-NoData"
            return 1, [profile_str]
        if not node.children: return 0, []
        total_leaves = 0
        all_profiles = []
        for child in node.children.values():
            child_leaves, child_profiles = self.run_metapattern_tagging(child)
            total_leaves += child_leaves
            all_profiles.extend(child_profiles)
        if total_leaves > 0:
            pv = "HPV" if total_leaves > 1 else "LPV"
            unique_profiles = set(all_profiles)
            is_uniform = False
            if len(unique_profiles) == 1:
                first_profile_str = list(unique_profiles)[0]
                if "GT-NoData" not in first_profile_str and \
                        ("Others': 1.0" not in first_profile_str or len(first_profile_str) > 20):
                    is_uniform = True
            iv = "LIV" if is_uniform else "HIV"
            node.meta_pattern = f"{pv}+{iv}"
        return total_leaves, all_profiles

    def print_tree(self, node=None, indent="", f=sys.stdout):
        if node is None: node = self.root
        meta = ""
        if node.meta_pattern: meta = f" [Meta: {node.meta_pattern}]"
        if node.iid_profile:
            profile_str = ", ".join(f"{k}: {v * 100:.0f}%" for k, v in node.iid_profile.items() if v > 0)
            meta = f" [IID: {profile_str}] ({len(node.ip_list)} IPs)"
        f.write(f"{indent}* {node.key_type}: {node.key_value}{meta}\n")
        for child in node.children.values():
            self.print_tree(child, indent + "  ", f=f)


# =======================================================================
# SECTION 2: Post-processing (update_node_counts)
# =======================================================================

def update_node_counts(node):
    if node.is_leaf_64:
        node.ip_count = len(node.ip_list)
        node.leaf_count = 1
        return node.ip_count, node.leaf_count

    total_ips = 0
    total_leaves = 0
    for child in node.get_children():
        child._parent = node
        ips, leaves = update_node_counts(child)
        total_ips += ips
        total_leaves += leaves

    node.ip_count = total_ips
    node.leaf_count = total_leaves
    return total_ips, total_leaves


# =======================================================================
# SECTION 3: Main Entry
# =======================================================================

if __name__ == "__main__":

    CSV_INPUT_FILE = "test.csv"
    KBC_TREE_OUTPUT_LOG = "kbc_tree_log.txt"
    KBC_PICKLE_OUTPUT = "kbc_root.pkl"

    print("--- Running Phase 1 (MGHP) ... ---")

    if not os.path.exists(CSV_INPUT_FILE):
        print(f"Error: Input file not found: '{CSV_INPUT_FILE}'.", file=sys.stderr)
        sys.exit(1)

    kbc_builder = KBCBuilder()
    kbc_root = kbc_builder.build_tree(CSV_INPUT_FILE)

    if not kbc_root:
        print("Phase 1 (MGHP) build failed, please check 'test.csv'. Exiting.", file=sys.stderr)
        sys.exit(1)

    try:
        with open(KBC_TREE_OUTPUT_LOG, 'w', encoding='utf-8') as f:
            kbc_builder.print_tree(node=kbc_root, f=f)
        print(f"[+] Phase 1 (MGHP) tree log saved to '{KBC_TREE_OUTPUT_LOG}'")
    except Exception as e:
        print(f"Warning: Failed to save KBC tree log: {e}", file=sys.stderr)

    print("--- Phase 1 (MGHP) complete. ---")

    print("\n--- Running Phase 1.5 (Post-Processing)... ---")
    update_node_counts(kbc_root)
    print(f"MGHP root processed: {kbc_root.ip_count:,} total IPs, {kbc_root.leaf_count:,} total leaves.")
    print("--- Phase 1.5 complete. ---")

    print(f"\n--- Running Phase 1.6 (Serialization)... ---")
    try:
        with open(KBC_PICKLE_OUTPUT, 'wb') as f:
            pickle.dump(kbc_root, f)
        print(f"[+] Success! MGHP tree saved to '{KBC_PICKLE_OUTPUT}'")
        print("You can now run Phase 2 (phase2_bag.py).")
    except Exception as e:
        print(f"\n[!] Error: Failed to serialize MGHP tree: {e}", file=sys.stderr)
