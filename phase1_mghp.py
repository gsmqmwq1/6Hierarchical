import pandas as pd
import ipaddress
import sys
import re
import gc
import socket
from collections import defaultdict, Counter
import pickle
import os

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")


# Stage 1: MGHP
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
        if self.meta_pattern:
            meta = f" [Meta: {self.meta_pattern}]"
        if self.is_leaf_64:
            meta = f" [IIDs: {len(self.ip_list)}]"
        return f"KBCNode({self.key_type}='{self.key_value}', children={len(self.children)}{meta})"


class KBCBuilder:
    def __init__(self):
        self.root = KBCNode(key_type="root", key_value="root", depth=0)
        self.SERVICE_PORTS = [
            "80",
            "443",
            "22",
            "21",
            "25",
            "3389",
            "5432",
            "3306",
            "8080",
            "8443",
            "53",
            "443",
            "110",
            "143",
            "445",
            "5900",
            "6379",
            "27017",
            "67",
            "161",
        ]
        self.PORT_PATTERNS = {
            port: "0" * (16 - len(port)) + port for port in self.SERVICE_PORTS
        }

    def build_tree(self, csv_file_path):
        import csv as csv_module

        print(f"[+] 1. (KBC) building from {csv_file_path} building the trie...")

        required_cols = [
            "IPv6Address",
            "country",
            "province",
            "asnum",
            "network_prefix",
            "subnet_prefix",
        ]

        RENAME_MAP = {
            "IPv6": "IPv6Address",
            "ip": "IPv6Address",
            "prefix": "network_prefix",
            "network": "subnet_prefix",
        }

        try:
            with open(csv_file_path, "r", encoding="utf-8-sig", errors="replace") as fh:
                reader = csv_module.DictReader(fh)
                raw_cols = [c.strip() for c in (reader.fieldnames or [])]
        except Exception as e:
            print(f"Error: Failed to read CSV: {e}", file=sys.stderr)
            return None

        col_map = {}
        for rc in raw_cols:
            if rc in RENAME_MAP:
                col_map[rc] = RENAME_MAP[rc]
            elif rc in required_cols:
                col_map[rc] = rc

        if not all(c in col_map.values() for c in required_cols):
            print(
                f"Error: CSVCSV is missing required columns: {required_cols}",
                file=sys.stderr,
            )
            print(f"Actual columns: {raw_cols}", file=sys.stderr)
            return None

        total_inserted = 0
        total_dropped = 0
        REPORT_INTERVAL = 200000

        with open(csv_file_path, "r", encoding="utf-8-sig", errors="replace") as fh:
            reader = csv_module.DictReader(fh)

            for line_no, raw_row in enumerate(reader, start=1):
                row = {}
                for raw_col, val in raw_row.items():
                    if raw_col is None:
                        continue
                    raw_col = raw_col.strip()
                    std_col = col_map.get(raw_col)
                    if std_col is not None:
                        row[std_col] = str(val).strip() if val else "Unknown"

                for c in required_cols:
                    if c not in row:
                        row[c] = "Unknown"

                if any(not row[c] or row[c] == "Unknown" for c in required_cols):
                    total_dropped += 1
                    continue

                self.insert_ip(row)
                total_inserted += 1

                if total_inserted % REPORT_INTERVAL == 0:
                    try:
                        import psutil

                        mem = psutil.Process().memory_info().rss / (1024**3)
                        print(
                            f"[+] Inserted {total_inserted:,} records, memory {mem:.1f} GB"
                        )
                    except ImportError:
                        print(f"[+] Inserted {total_inserted:,} records")

        if total_dropped > 0:
            print(
                f"[+] 1.1 (KBC) Skipped records with empty fields: {total_dropped} records"
            )
        print(f"[+] 1.2 (KBC) Inserted {total_inserted:,} IP records.")

        print(
            "[+] 1.3 (KBC) Traversing the trie and extracting classical IID templates..."
        )
        self.run_iid_extraction(self.root)
        print(
            "[+] 1.4 (KBC) Recursively labeling meta-patterns (PV+IV) for *all* parent nodes..."
        )
        self.run_metapattern_tagging(self.root)

        print("[+] Stage 1 (KBC) build complete!")
        return self.root

    def insert_ip(self, row):
        try:
            node = self.root

            for key, ktype, depth in [
                (row["country"], "country", 1),
                (row["asnum"], "asn", 2),
                (row["province"], "province", 3),
                (row["network_prefix"], "network", 4),
                (row["subnet_prefix"], "subnet_whois", 5),
            ]:
                child = node.children.get(key)
                if child is None:
                    child = KBCNode(key_type=ktype, key_value=key, depth=depth)
                    node.children[key] = child
                node = child

            ip_str = row["IPv6Address"]
            if not ip_str or ip_str == "Unknown":
                return
            try:
                packed = socket.inet_pton(socket.AF_INET6, ip_str)
                prefix_int = (
                    int.from_bytes(packed, "big") & 0xFFFFFFFFFFFFFFFF0000000000000000
                )
                true_64_prefix_str = str(ipaddress.IPv6Network((prefix_int, 64)))
            except Exception:
                return

            leaf = node.children.get(true_64_prefix_str)
            if leaf is None:
                leaf = KBCNode(
                    key_type="subnet_leaf_64", key_value=true_64_prefix_str, depth=6
                )
                node.children[true_64_prefix_str] = leaf
            leaf.ip_list.append(ip_str)
        except (KeyError, TypeError, AttributeError):
            pass

    def run_iid_extraction(self, node):
        if node.key_type == "subnet_leaf_64":
            self.extract_iid_templates(node)
            return
        for child in node.children.values():
            self.run_iid_extraction(child)

    def _classify_iid_patterns(self, ip_list):
        if not ip_list:
            return {"GT-NoData": 1.0}
        counts = Counter()
        hex_iids = []
        for ip_str in ip_list:
            try:
                ip_obj = ipaddress.IPv6Address(ip_str)
                hex_addr = f"{int(ip_obj):032x}"
                hex_iids.append(hex_addr[-16:])
            except ipaddress.AddressValueError:
                continue
        if not hex_iids:
            return {"GT-NoData": 1.0}
        for last16 in hex_iids:
            if any(last16 == pattern for pattern in self.PORT_PATTERNS.values()):
                counts["EmbeddedPort"] += 1
                continue
            m = re.match(r"^(0+)", last16)
            if m and len(m.group(1)) >= 12:
                counts["LowByte"] += 1
                continue
            if last16[6:10].lower() == "fffe":
                counts["IeeeDerived"] += 1
                continue
            if (
                (last16[0:2] == "00" and last16[10:16] == "000000")
                or (last16[0:8].lower() == "02005efe")
                or (
                    last16[0:2] == "00"
                    and last16[4:6] == "00"
                    and last16[8:10] == "00"
                    and last16[12:14] == "00"
                )
            ):
                counts["EmbeddedIPv4"] += 1
                continue
            if len(set(last16)) >= 8:
                counts["RandomGen"] += 1
                continue
            if (
                last16[0:9] == "0" * 9
                and last16[9] == "2"
                and last16[12] == "0"
                and last16[13] == "0"
            ) or (last16[0:9] == "0" * 9 and last16[9] == "1" and last16[12] == "0"):
                counts["BytePattern"] += 1
                continue
            counts["Others"] += 1
        total_count = len(hex_iids)
        if total_count == 0:
            return {"GT-NoData": 1.0}
        profile = {key: round(value / total_count, 4) for key, value in counts.items()}
        for key in [
            "EmbeddedPort",
            "LowByte",
            "IeeeDerived",
            "EmbeddedIPv4",
            "RandomGen",
            "BytePattern",
            "Others",
        ]:
            profile.setdefault(key, 0.0)
        return profile

    def extract_iid_templates(self, leaf_node):
        leaf_node.iid_profile = self._classify_iid_patterns(leaf_node.ip_list)

    def run_metapattern_tagging(self, node):
        if node.key_type == "subnet_leaf_64":
            profile_str = str(node.iid_profile) if node.iid_profile else "GT-NoData"
            return 1, [profile_str]
        if not node.children:
            return 0, []
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
                if "GT-NoData" not in first_profile_str and (
                    "Others': 1.0" not in first_profile_str
                    or len(first_profile_str) > 20
                ):
                    is_uniform = True
            iv = "LIV" if is_uniform else "HIV"
            node.meta_pattern = f"{pv}+{iv}"
        return total_leaves, all_profiles

    def print_tree(self, node=None, indent="", f=sys.stdout):
        if node is None:
            node = self.root
        meta = ""
        if node.meta_pattern:
            meta = f" [Meta: {node.meta_pattern}]"
        if node.iid_profile:
            profile_str = ", ".join(
                f"{k}: {v * 100:.0f}%" for k, v in node.iid_profile.items() if v > 0
            )
            meta = f" [IID: {profile_str}] ({len(node.ip_list)} IPs)"
        f.write(f"{indent}* {node.key_type}: {node.key_value}{meta}\n")
        for child in node.children.values():
            self.print_tree(child, indent + "  ", f=f)

    def add_new_ips(self, ip_list):
        UNKNOWN = "Unknown"
        added = 0
        for ip_str in ip_list:
            ip_str = ip_str.strip()
            if not ip_str:
                continue
            try:
                node = self.root
                for key, ktype, depth in [
                    (UNKNOWN, "country", 1),
                    (UNKNOWN, "asn", 2),
                    (UNKNOWN, "province", 3),
                    (UNKNOWN, "network", 4),
                    (UNKNOWN, "subnet_whois", 5),
                ]:
                    child = node.children.get(key)
                    if child is None:
                        child = KBCNode(key_type=ktype, key_value=key, depth=depth)
                        node.children[key] = child
                    node = child

                packed = socket.inet_pton(socket.AF_INET6, ip_str)
                prefix_int = (
                    int.from_bytes(packed, "big") & 0xFFFFFFFFFFFFFFFF0000000000000000
                )
                true_64_prefix_str = str(ipaddress.IPv6Network((prefix_int, 64)))

                leaf = node.children.get(true_64_prefix_str)
                if leaf is None:
                    leaf = KBCNode(
                        key_type="subnet_leaf_64", key_value=true_64_prefix_str, depth=6
                    )
                    node.children[true_64_prefix_str] = leaf
                leaf.ip_list.append(ip_str)
                added += 1
            except Exception:
                continue
        return added


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


if __name__ == "__main__":
    # Replace this relative path when running Phase 1 on another authorized dataset.
    CSV_INPUT_FILE = "test.csv"
    KBC_TREE_OUTPUT_LOG = "mghp_tree.txt"
    KBC_PICKLE_OUTPUT = "mghp_root.pkl"

    print("--- Running Stage 1 (KBC) ... ---")

    if not os.path.exists(CSV_INPUT_FILE):
        print(f"Error: Input file not found '{CSV_INPUT_FILE}'.", file=sys.stderr)
        sys.exit(1)

    kbc_builder = KBCBuilder()
    kbc_root = kbc_builder.build_tree(CSV_INPUT_FILE)

    if not kbc_root:
        print(
            "Stage 1 (KBC) build failed; please check 'test.csv'. Exiting.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        with open(KBC_TREE_OUTPUT_LOG, "w", encoding="utf-8") as f:
            kbc_builder.print_tree(node=kbc_root, f=f)
        print(f"[+] Stage 1 (KBC) Tree log saved to '{KBC_TREE_OUTPUT_LOG}'")
    except Exception as e:
        print(f"Warning: Failed to save the KBC tree log: {e}", file=sys.stderr)

    print("--- Stage 1 (KBC) completed. ---")

    print("\n--- Running Stage 1.5 (KBC Post-Processing)... ---")
    update_node_counts(kbc_root)
    print(
        f"KBC root processed: {kbc_root.ip_count:,} total IPs, {kbc_root.leaf_count:,} total leaves."
    )
    print("--- Stage 1.5 completed. ---")

    print(f"\n--- Running Stage 1.6 (serialization)... ---")
    try:
        with open(KBC_PICKLE_OUTPUT, "wb") as f:
            pickle.dump(kbc_root, f)
        print(
            f"[+] Success! The complete KBC object was saved to '{KBC_PICKLE_OUTPUT}'"
        )
        print("Stage 2 (phase2_bag.py) can now be run.")
    except Exception as e:
        print(f"\n[!] Error: failed to serialize the KBC tree: {e}", file=sys.stderr)
