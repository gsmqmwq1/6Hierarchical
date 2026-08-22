#!/usr/bin/env python3.10
# -*- coding: utf-8 -*-

"""
6Hierarchical Full Pipeline (run_pipeline.py)

"""

import os
import sys
import time
import shutil
import pickle
import subprocess
import csv
import ipaddress
from datetime import datetime
from pathlib import Path

import pandas as pd

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

CODE_ROOT = Path(__file__).resolve().parent
if str(CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(CODE_ROOT))

SEED_COLUMNS = [
    "IPv6Address",
    "country",
    "province",
    "city",
    "asnum",
    "asorg",
    "network_prefix",
    "subnet_prefix",
]


import phase1_mghp as phase1_kbc
import phase2_bag
import lapd
import gasser_mapd
from whois.IPv6AddMoreInformationRead import lookup_many as lookup_whois_many


CONFIG = {
    "EXP_PREFIX": "A0_full",
    "VARIANT": "A0_full-test",
    # Replace this relative path to run another authorized seed dataset.
    "INITIAL_SEED_CSV": "test.csv",
    "TOTAL_ROUNDS": 20,
    "BUDGET_PER_ROUND": 200000,
    "INITIAL_K": 15,
    "HITRATE_THRESHOLD_LOW": 0.01,
    "HITRATE_THRESHOLD_HIGH": 0.05,
    "ZMAP_SOURCE_IP": "your_local_ipv6_address",
    "ZMAP_INTERFACE": "",
    "ZMAP_GATEWAY_MAC": "",
    "BASE_OUTPUT_DIR": "./output",
    "LAPD_N_ONLINE": 14,
    "LAPD_TAU_A": 8,
    "LAPD_DELTA_ON": 16,
    "LAPD_L_ON": 112,
    "MAX_GENERATION_ATTEMPT_FACTOR": 3,
    "HPV_BUDGET_PERCENT": 15,
    "R_THRESHOLD": 0.8,
    "MAPD_PROTOCOLS": ("icmp6", "tcp80"),
    "MAPD_MIN_TARGETS": 300,
    "MAPD_MIN_PREFIX_LEN": 64,
    "MAPD_MAX_PREFIX_LEN": 124,
    "MAPD_SHARD_COUNT": 4,
    "WHOIS_ASDB_PATH": "whois/GeoLite2-ASN.mmdb",
    "WHOIS_LOCDB_PATH": "whois/GeoLite2-City.mmdb",
    "WHOIS_COUNTRYDB_PATH": "whois/GeoLite2-Country.mmdb",
}


def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)


def zmap_interface_arg():
    interface = str(CONFIG.get("ZMAP_INTERFACE", "")).strip()
    return f" --interface={interface}" if interface else ""


def zmap_link_args():
    interface = str(CONFIG.get("ZMAP_INTERFACE", "")).strip() or "eth0"
    gateway_mac = str(CONFIG.get("ZMAP_GATEWAY_MAC", "")).strip()
    gateway_arg = f" --gateway-mac={gateway_mac}" if gateway_mac else ""
    return f"-i {interface}{gateway_arg}"


def zmap_base_command():
    interface = str(CONFIG.get("ZMAP_INTERFACE", "")).strip() or "eth0"
    gateway_mac = str(CONFIG.get("ZMAP_GATEWAY_MAC", "")).strip()
    command = ["sudo", "zmap", "-i", interface]
    if gateway_mac:
        command.append(f"--gateway-mac={gateway_mac}")
    command.append(f"--ipv6-source-ip={CONFIG['ZMAP_SOURCE_IP']}")
    return command


def _ip_column(df):
    return "IPv6" if "IPv6" in df.columns else "IPv6Address"


def normalize_seed_csv(csv_path):
    df = pd.read_csv(csv_path, dtype=str, low_memory=False)
    df.columns = df.columns.str.strip()
    if "IPv6Address" not in df.columns and "IPv6" in df.columns:
        df = df.rename(columns={"IPv6": "IPv6Address"})
    missing_columns = [column for column in SEED_COLUMNS if column not in df.columns]
    if missing_columns:
        raise ValueError(
            f"Initial seed CSV is missing required columns: {missing_columns}"
        )
    df = df[SEED_COLUMNS]
    df.to_csv(csv_path, index=False, encoding="utf-8")


def _unique_preserving_order(values):
    return list(
        dict.fromkeys(str(value).strip() for value in values if str(value).strip())
    )


def _prefix64(ip_str):
    try:
        return str(ipaddress.IPv6Network(f"{ip_str}/64", strict=False))
    except Exception:
        return None


def _matches_any_prefix(ip_str, networks):
    try:
        ip_obj = ipaddress.IPv6Address(ip_str)
    except Exception:
        return False
    return any(ip_obj in network for network in networks)


def _write_lines(path, values):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for value in values:
            f.write(str(value) + "\n")


def _write_shards(values, shard_count, path_template):
    shard_count = max(1, int(shard_count))
    shard_paths = [path_template.format(index=i + 1) for i in range(shard_count)]
    handles = [open(path, "w", encoding="utf-8", newline="\n") for path in shard_paths]
    try:
        for idx, value in enumerate(values):
            handles[idx % shard_count].write(str(value) + "\n")
    finally:
        for handle in handles:
            handle.close()
    return shard_paths


def merge_seeds(csv_path, new_ips, output_csv):
    base_df = pd.read_csv(csv_path, dtype=str, low_memory=False)
    col_name = _ip_column(base_df)
    base_df[col_name] = base_df[col_name].astype(str).str.strip()
    base_df = base_df.drop_duplicates(subset=[col_name], keep="first")
    existing_ips = set(base_df[col_name])
    addresses_to_add = [
        ip for ip in _unique_preserving_order(new_ips) if ip not in existing_ips
    ]

    if not addresses_to_add:
        base_df.to_csv(output_csv, index=False, encoding="utf-8")
        return len(base_df), []

    whois_results = lookup_whois_many(
        addresses_to_add,
        asdb_path=CONFIG["WHOIS_ASDB_PATH"],
        locdb_path=CONFIG["WHOIS_LOCDB_PATH"],
        countrydb_path=CONFIG["WHOIS_COUNTRYDB_PATH"],
    )
    whois_by_ip = {record["ip"]: record for record in whois_results}
    field_mapping = {
        "country": "country",
        "province": "province",
        "city": "city",
        "asnum": "asnum",
        "asorg": "asorg",
        "network_prefix": "prefix",
        "subnet_prefix": "network",
    }

    new_rows = []
    for ip in addresses_to_add:
        info = whois_by_ip.get(ip, {})
        row = {column: "Unknown" for column in base_df.columns}
        row[col_name] = ip
        for csv_field, whois_field in field_mapping.items():
            if csv_field in row:
                row[csv_field] = info.get(whois_field, "notexist")
        new_rows.append(row)

    combined_df = pd.concat(
        [base_df, pd.DataFrame(new_rows, columns=base_df.columns)], ignore_index=True
    )
    combined_df.to_csv(output_csv, index=False, encoding="utf-8")
    return len(combined_df), new_rows


class PipelineController:
    def __init__(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.exp_dir = os.path.join(
            CONFIG["BASE_OUTPUT_DIR"], f"{CONFIG['EXP_PREFIX']}_{timestamp}"
        )
        ensure_dir(self.exp_dir)

        print(f"=== Initializing experiment environment ===")
        print(f"[*] Working directory: {self.exp_dir}")

        self.current_seed_csv = os.path.join(self.exp_dir, "current_seeds.csv")
        self.pkl_file = os.path.join(self.exp_dir, "kbc_root.pkl")
        self.candidates_file = os.path.join(self.exp_dir, "candidates_temp.txt")
        self.scan_output_file = os.path.join(self.exp_dir, "scan_results_temp.txt")
        self.all_generated_targets_file = os.path.join(
            self.exp_dir, "all_generated_targets.txt"
        )

        self.all_active_file = os.path.join(self.exp_dir, "all_active_ips.txt")
        open(self.all_active_file, "w", encoding="utf-8").close()
        self.all_lapd_alias_file = os.path.join(
            self.exp_dir, "lapd_alias_prefixes_all.txt"
        )
        self.all_lapd_alias_addresses_file = os.path.join(
            self.exp_dir, "lapd_alias_addresses_all.txt"
        )
        self.all_active_unique_file = os.path.join(
            self.exp_dir, "active_addresses_unique_all.txt"
        )
        self.all_generated_unique_file = os.path.join(
            self.exp_dir, "generated_candidates_unique_all.txt"
        )
        self.mapd_input_active_file = os.path.join(
            self.exp_dir, "mapd_input_active_addresses.txt"
        )
        self.mapd_candidates_file = os.path.join(self.exp_dir, "mapd_candidates.csv")
        self.mapd_probes_file = os.path.join(self.exp_dir, "mapd_probes.csv")
        self.mapd_probe_addresses_file = os.path.join(
            self.exp_dir, "mapd_probe_addresses.txt"
        )
        self.mapd_merged_responses_file = os.path.join(
            self.exp_dir, "mapd_responses_merged.txt"
        )
        self.mapd_aliased_prefixes_file = os.path.join(
            self.exp_dir, "mapd_aliased_prefixes.txt"
        )
        self.mapd_nonaliased_prefixes_file = os.path.join(
            self.exp_dir, "mapd_nonaliased_prefixes.txt"
        )
        self.mapd_prefix_status_file = os.path.join(
            self.exp_dir, "mapd_prefix_status.csv"
        )
        self.mapd_alias_addresses_file = os.path.join(
            self.exp_dir, "mapd_alias_addresses.txt"
        )

        self.stats_csv_file = os.path.join(self.exp_dir, "statistics.csv")
        self.summary_csv_file = os.path.join(self.exp_dir, "summary.csv")
        self.summary_md_file = os.path.join(self.exp_dir, "summary.md")
        self.active_as_distribution_file = os.path.join(
            self.exp_dir, "active_as_distribution.csv"
        )
        self.active_country_distribution_file = os.path.join(
            self.exp_dir, "active_country_distribution.csv"
        )

        print(
            f"[*] Resetting seed pool: copying {CONFIG['INITIAL_SEED_CSV']} -> {self.current_seed_csv}"
        )
        if not os.path.exists(CONFIG["INITIAL_SEED_CSV"]):
            raise FileNotFoundError(
                f"Initial seed file not found: {CONFIG['INITIAL_SEED_CSV']}"
            )
        shutil.copy(CONFIG["INITIAL_SEED_CSV"], self.current_seed_csv)
        normalize_seed_csv(self.current_seed_csv)

        original_df = pd.read_csv(self.current_seed_csv, dtype=str, low_memory=False)
        self.seed_ip_column = _ip_column(original_df)
        original_ips = _unique_preserving_order(
            original_df[self.seed_ip_column].tolist()
        )
        self.original_seed_ips = set(original_ips)
        self.original_prefix64s = {
            prefix for prefix in map(_prefix64, original_ips) if prefix
        }

        self.k = CONFIG["INITIAL_K"]
        self.round_id = 1
        self.last_gen_count = 0
        self.last_gen_unique_count = 0
        self.last_generation_stats = {}
        self.last_lapd_stats = {}
        self.last_seed_filter_stats = {}
        self.last_kbc_stats = {}
        self.previous_lapd_alias_prefixes = set()
        self.all_lapd_alias_prefixes = set()
        self.all_alias_addresses = set()
        self.all_unique_active_addresses = set()
        self.all_active_prefix64s = set()
        self.all_unique_generated_addresses = set()
        self.all_new_seed_addresses = set()
        self.all_new_prefix64s = set()
        self.total_generated_raw = 0
        self.total_active_hits_raw = 0
        self.total_active_prefix64_raw = 0
        self.global_alias_candidate_hits = 0
        self.global_abandoned_budget = 0
        self.lapd_scan_counter = 0
        self.mapd_scan_counter = 0
        self.last_mapd_stats = {
            "candidate_address_count": 0,
            "candidate_prefix_count": 0,
            "probe_count": 0,
            "logical_probe_count": 0,
            "responsive_probe_count": 0,
            "probed_prefix_count": 0,
            "aliased_prefix_count": 0,
            "nonaliased_prefix_count": 0,
            "alias_address_count": 0,
            "total_time_sec": 0.0,
        }

        with open(self.stats_csv_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Round", "Hit_Rate_Raw_On_Raw_Targets"])

    def run(self):
        print(
            f"\n=== MPGG Pipeline started (Total {CONFIG['TOTAL_ROUNDS']} rounds) ==="
        )

        start_time = time.time()

        for r in range(1, CONFIG["TOTAL_ROUNDS"] + 1):
            self.round_id = r
            print(f"\n>>> Round {r} [K={self.k:.2f}] <<<")

            # Stage 1: MGHP
            self.run_phase1()

            # Stage 2: BAG
            self.run_phase2()

            # Stage 3: ZMap
            raw_active_ips_list = self.run_phase3()
            unique_active_ips_list = _unique_preserving_order(raw_active_ips_list)

            # Stage 3: LAPD
            self.run_lapd(unique_active_ips_list)

            self.save_round_data(raw_active_ips_list)

            self.feedback_and_update(raw_active_ips_list, unique_active_ips_list)

        # Final MAPD
        self.run_final_mapd()
        duration = time.time() - start_time
        self.write_final_summary(duration)
        self.cleanup_intermediate_csvs()
        print(f"\n=== Pipeline completed (elapsed: {duration:.1f}s) ===")
        print(f"[*] All results saved to: {self.exp_dir}")

    def run_phase1(self):
        print(f"[Phase 1] Building the hierarchical prefix tree...")
        kbc_seed_csv = self.prepare_kbc_seeds()
        builder = phase1_kbc.KBCBuilder()
        kbc_root = builder.build_tree(kbc_seed_csv)

        if not kbc_root:
            raise Exception("Phase 1 build failed")

        phase1_kbc.update_node_counts(kbc_root)

        with open(self.pkl_file, "wb") as f:
            pickle.dump(kbc_root, f)

        self.last_kbc_stats = self.collect_kbc_stats(kbc_root)

        if os.path.exists(kbc_seed_csv):
            os.remove(kbc_seed_csv)

    def prepare_kbc_seeds(self):
        df = pd.read_csv(self.current_seed_csv, dtype=str, low_memory=False)
        col_name = _ip_column(df)
        df[col_name] = df[col_name].astype(str).str.strip()
        df = df[df[col_name] != ""].drop_duplicates(subset=[col_name], keep="first")
        total_before = len(df)

        networks = []
        for prefix in self.all_lapd_alias_prefixes:
            try:
                networks.append(ipaddress.IPv6Network(prefix, strict=False))
            except Exception:
                continue
        if networks:
            remove_mask = df[col_name].map(lambda ip: _matches_any_prefix(ip, networks))
            filtered_df = df.loc[~remove_mask].copy()
        else:
            filtered_df = df.copy()

        round_seed_csv = os.path.join(
            self.exp_dir, f"round_{self.round_id}_kbc_seeds.csv"
        )
        filtered_df.to_csv(round_seed_csv, index=False, encoding="utf-8")
        self.last_seed_filter_stats = {
            "total_before": total_before,
            "removed": total_before - len(filtered_df),
            "after": len(filtered_df),
        }
        print(
            f"[*] KBC seed filter: total={total_before}, "
            f"LAPD removed={total_before - len(filtered_df)}, kept={len(filtered_df)}"
        )
        return round_seed_csv

    def collect_kbc_stats(self, root):
        stats = {
            "total_nodes": 0,
            "parent_nodes": 0,
            "leaf64_nodes": 0,
            "seed_count": 0,
            "unique_prefix64": 0,
            "country_nodes": 0,
            "asn_nodes": 0,
            "network_nodes": 0,
            "subnet_nodes": 0,
        }

        def visit(node):
            stats["total_nodes"] += 1
            if node.is_leaf_64:
                stats["leaf64_nodes"] += 1
                stats["seed_count"] += len(node.ip_list)
            else:
                stats["parent_nodes"] += 1
            key_to_stat = {
                "country": "country_nodes",
                "asn": "asn_nodes",
                "network": "network_nodes",
                "subnet_whois": "subnet_nodes",
            }
            if node.key_type in key_to_stat:
                stats[key_to_stat[node.key_type]] += 1
            for child in node.get_children():
                visit(child)

        visit(root)
        stats["unique_prefix64"] = stats["leaf64_nodes"]
        return stats

    def run_phase2(self):
        print(f"[Phase 2] Generating candidate addresses...")
        with open(self.pkl_file, "rb") as f:
            kbc_root = pickle.load(f)

        controller = phase2_bag.BudgetController(
            kbc_root,
            total_budget=CONFIG["BUDGET_PER_ROUND"],
            hpv_k=self.k,
            hpv_budget_percent=CONFIG["HPV_BUDGET_PERCENT"],
            r_threshold=CONFIG["R_THRESHOLD"],
            suppressed_alias_prefixes=self.all_lapd_alias_prefixes,
            max_attempt_factor=CONFIG["MAX_GENERATION_ATTEMPT_FACTOR"],
            return_stats=True,
        )

        candidates, generation_stats = controller.process()
        candidate_list = list(candidates)
        self.last_generation_stats = generation_stats
        self.global_alias_candidate_hits += generation_stats.get(
            "alias_candidate_hits", 0
        )
        self.global_abandoned_budget += generation_stats.get("abandoned_budget", 0)

        with open(self.candidates_file, "w", encoding="utf-8", newline="\n") as f:
            for ip in candidate_list:
                f.write(ip + "\n")
        round_candidates_file = os.path.join(
            self.exp_dir, f"round_{self.round_id}_candidates.txt"
        )
        with open(round_candidates_file, "w", encoding="utf-8", newline="\n") as f:
            for ip in candidate_list:
                f.write(ip + "\n")
        with open(
            self.all_generated_targets_file, "a", encoding="utf-8", newline="\n"
        ) as f:
            for ip in candidate_list:
                f.write(ip + "\n")

        print(f"[*] Generated this round: {len(candidate_list)}")
        self.last_gen_count = len(candidate_list)
        self.last_gen_unique_count = len(set(candidate_list))
        self.all_unique_generated_addresses.update(candidate_list)
        self.total_generated_raw += self.last_gen_count

    def run_phase3(self):
        print(f"[Phase 3] ZMap scan...")
        if self.last_gen_count == 0:
            return []

        cmd = zmap_base_command() + [
            f"--ipv6-target-file={self.candidates_file}",
            "-M",
            "icmp6_echoscan",
            "-p",
            "80",
            "-q",
            "--verbosity=0",
            "-o",
            self.scan_output_file,
        ]

        if os.path.exists(self.scan_output_file):
            os.remove(self.scan_output_file)
        try:
            subprocess.run(cmd, check=True)
        except Exception as e:
            print(
                f"[Warning] ZMap execution error (possibly caused by the test environment): {e}"
            )
            raise RuntimeError(f"ZMap phase-3 scan failed: {e}") from e

        if not os.path.exists(self.scan_output_file):
            raise FileNotFoundError(
                f"ZMap output file missing: {self.scan_output_file}"
            )
        with open(self.scan_output_file, "r") as f:
            active_ips = [line.strip() for line in f if line.strip()]

        return active_ips

    def scan_addresses(self, addrs_to_scan, output_prefix):
        addrs_to_scan = [addr for addr in addrs_to_scan if addr]
        if not addrs_to_scan:
            return []

        input_file = f"{output_prefix}_input.txt"
        output_file = f"{output_prefix}_output.txt"
        with open(input_file, "w", encoding="utf-8", newline="\n") as f:
            for addr in addrs_to_scan:
                f.write(addr + "\n")

        cmd = zmap_base_command() + [
            f"--ipv6-target-file={input_file}",
            "-M",
            "icmp6_echoscan",
            "-p",
            "80",
            "-q",
            "--verbosity=0",
            "-o",
            output_file,
        ]

        if os.path.exists(output_file):
            os.remove(output_file)
        try:
            subprocess.run(cmd, check=True)
        except Exception as e:
            print(
                f"[Warning] LAPD ZMap execution error (possibly caused by the test environment): {e}"
            )
            raise RuntimeError(f"LAPD ZMap scan failed: {e}") from e

        if not os.path.exists(output_file):
            raise FileNotFoundError(f"LAPD ZMap output file missing: {output_file}")
        with open(output_file, "r") as f:
            return [line.strip() for line in f if line.strip()]

    def scan_mapd_target_file(self, protocol, input_file, output_file):
        protocol = str(protocol).strip().lower()
        if protocol == "icmp6":
            module = "icmp6_echoscan"
            port_arg = "-p 80"
        elif protocol == "tcp80":
            module = "tcp_synscan"
            port_arg = "-p 80"
        else:
            raise ValueError(f"Unsupported MAPD protocol: {protocol}")

        cmd = zmap_base_command() + [
            f"--ipv6-target-file={input_file}",
            "-M",
            module,
            "-p",
            "80",
            "-q",
            "--verbosity=0",
            "-o",
            output_file,
        ]

        if os.path.exists(output_file):
            os.remove(output_file)
        try:
            subprocess.run(cmd, check=True)
        except Exception as e:
            raise RuntimeError(
                f"MAPD {protocol} ZMap failed for {input_file}: {e}"
            ) from e

        if not os.path.exists(output_file):
            raise FileNotFoundError(
                f"MAPD {protocol} output file missing: {output_file}"
            )
        with open(output_file, "r") as f:
            return [line.strip() for line in f if line.strip()]

    def scan_mapd_addresses(self, protocol, addrs_to_scan, output_prefix):
        addrs_to_scan = [addr for addr in addrs_to_scan if addr]
        if not addrs_to_scan:
            return []

        input_file = f"{output_prefix}_{protocol}_input.txt"
        output_file = f"{output_prefix}_{protocol}_output.txt"
        with open(input_file, "w", encoding="utf-8", newline="\n") as f:
            for addr in addrs_to_scan:
                f.write(addr + "\n")
        return self.scan_mapd_target_file(protocol, input_file, output_file)

    def run_lapd(self, active_ips_list):
        print("[A0 LAPD] online lightweight pre-screening...")
        if not active_ips_list:
            self.previous_lapd_alias_prefixes = set()
            self.last_lapd_stats = {
                "alias_prefixes": 0,
                "new_alias_prefixes": 0,
                "new_alias_addresses": 0,
                "probe_count": 0,
                "responsive_count": 0,
                "total_time_sec": 0.0,
                "zmap_time_sec": 0.0,
                "judge_time_sec": 0.0,
            }
            return

        def _scan_func(probes):
            self.lapd_scan_counter += 1
            output_prefix = os.path.join(
                self.exp_dir,
                f"round_{self.round_id}_lapd_probe_{self.lapd_scan_counter}",
            )
            return self.scan_addresses(probes, output_prefix)

        alias_prefixes_round, lapd_stats = lapd.detect_alias_prefixes(
            active_ips_list,
            scan_func=_scan_func,
            n_online=CONFIG["LAPD_N_ONLINE"],
            tau_a=CONFIG["LAPD_TAU_A"],
            delta_on=CONFIG["LAPD_DELTA_ON"],
            l_on=CONFIG["LAPD_L_ON"],
        )

        detected_round = set(alias_prefixes_round)
        new_alias_prefixes = detected_round - self.all_lapd_alias_prefixes
        self.previous_lapd_alias_prefixes = detected_round
        self.all_lapd_alias_prefixes.update(detected_round)
        all_alias_networks = [
            ipaddress.IPv6Network(prefix, strict=False)
            for prefix in self.all_lapd_alias_prefixes
        ]
        alias_address_universe = self.all_unique_active_addresses | set(active_ips_list)
        alias_addresses_round = {
            ip
            for ip in alias_address_universe
            if _matches_any_prefix(ip, all_alias_networks)
        }
        new_alias_addresses = alias_addresses_round - self.all_alias_addresses
        self.all_alias_addresses.update(alias_addresses_round)
        self.last_lapd_stats = {
            "alias_prefixes": lapd_stats.alias_prefixes,
            "new_alias_prefixes": len(new_alias_prefixes),
            "new_alias_addresses": len(new_alias_addresses),
            "probe_count": lapd_stats.probe_count,
            "responsive_count": lapd_stats.responsive_count,
            "total_time_sec": lapd_stats.total_time_sec,
            "zmap_time_sec": lapd_stats.zmap_time_sec,
            "judge_time_sec": lapd_stats.judge_time_sec,
        }

        round_alias_file = os.path.join(
            self.exp_dir, f"round_{self.round_id}_lapd_alias_prefixes.txt"
        )
        with open(round_alias_file, "w", encoding="utf-8", newline="\n") as f:
            for prefix in alias_prefixes_round:
                f.write(prefix + "\n")
        with open(self.all_lapd_alias_file, "w", encoding="utf-8", newline="\n") as f:
            for prefix in sorted(self.all_lapd_alias_prefixes):
                f.write(prefix + "\n")
        _write_lines(
            self.all_lapd_alias_addresses_file, sorted(self.all_alias_addresses)
        )

        print(
            f"[A0 LAPD] prefixes tested this round={len(detected_round)}, "
            f"new prefixes={len(new_alias_prefixes)}, new alias addresses={len(new_alias_addresses)}, "
            f"cumulative prefixes={len(self.all_lapd_alias_prefixes)}, "
            f"cumulative addresses={len(self.all_alias_addresses)}"
        )

    def run_final_mapd(self):
        print(
            "[Final MAPD] Running gasser_mapd on active addresses not covered by LAPD aliases..."
        )
        t0 = time.time()
        _write_lines(self.all_lapd_alias_file, sorted(self.all_lapd_alias_prefixes))
        _write_lines(
            self.all_lapd_alias_addresses_file, sorted(self.all_alias_addresses)
        )
        active_addresses = sorted(self.all_unique_active_addresses)
        generated_candidates = sorted(self.all_unique_generated_addresses)
        _write_lines(self.all_active_unique_file, active_addresses)
        _write_lines(self.all_generated_unique_file, generated_candidates)

        lapd_alias_networks = [
            ipaddress.IPv6Network(prefix, strict=False)
            for prefix in self.all_lapd_alias_prefixes
        ]
        mapd_targets = [
            ip
            for ip in active_addresses
            if not _matches_any_prefix(ip, lapd_alias_networks)
        ]
        _write_lines(self.mapd_input_active_file, mapd_targets)

        if not mapd_targets:
            gasser_mapd.write_candidates_csv([], self.mapd_candidates_file)
            gasser_mapd.write_probes_csv([], self.mapd_probes_file)
            gasser_mapd.write_decision_outputs(
                decisions=[],
                aliased_out=self.mapd_aliased_prefixes_file,
                nonaliased_out=self.mapd_nonaliased_prefixes_file,
                summary_out=self.mapd_prefix_status_file,
            )
            for path in (self.mapd_alias_addresses_file,):
                _write_lines(path, [])
            self.last_mapd_stats["total_time_sec"] = time.time() - t0
            print("[Final MAPD] No non-LAPD active addresses; skipped.")
            return

        protocols = tuple(CONFIG["MAPD_PROTOCOLS"])
        prefix_lengths = tuple(
            range(CONFIG["MAPD_MIN_PREFIX_LEN"], CONFIG["MAPD_MAX_PREFIX_LEN"] + 1, 4)
        )
        min_targets = CONFIG["MAPD_MIN_TARGETS"]

        candidates = gasser_mapd.build_candidate_prefixes(
            target_addresses=mapd_targets,
            prefix_lengths=prefix_lengths,
            min_targets=min_targets,
            exempt_prefix_len=64,
        )
        gasser_mapd.write_candidates_csv(candidates, self.mapd_candidates_file)

        probes = gasser_mapd.generate_mapd_probes(candidates)
        gasser_mapd.write_probes_csv(probes, self.mapd_probes_file)
        unique_probe_addresses = sorted({probe.probe for probe in probes})
        _write_lines(self.mapd_probe_addresses_file, unique_probe_addresses)

        shard_count = max(1, int(CONFIG.get("MAPD_SHARD_COUNT", 1)))
        shard_template = os.path.join(self.exp_dir, "mapd_probe_shard_{index:02d}.txt")
        shard_paths = _write_shards(unique_probe_addresses, shard_count, shard_template)
        shard_paths = [path for path in shard_paths if os.path.getsize(path) > 0]

        responsive_probe_addresses = set()

        def _scan_shard(protocol, shard_path):
            shard_name = os.path.splitext(os.path.basename(shard_path))[0]
            output_file = os.path.join(
                self.exp_dir, f"{shard_name}_{protocol}_responses.txt"
            )
            responsive = self.scan_mapd_target_file(protocol, shard_path, output_file)
            normalized = []
            for addr in responsive:
                try:
                    normalized.append(gasser_mapd.canonical_ipv6(addr))
                except ValueError:
                    continue
            return normalized

        if unique_probe_addresses:
            from concurrent.futures import ThreadPoolExecutor, as_completed

            for protocol in protocols:
                max_workers = min(shard_count, len(shard_paths))
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    future_to_task = {
                        executor.submit(_scan_shard, protocol, shard_path): (
                            protocol,
                            shard_path,
                        )
                        for shard_path in shard_paths
                    }
                    for future in as_completed(future_to_task):
                        protocol, shard_path = future_to_task[future]
                        try:
                            responsive_probe_addresses.update(future.result())
                        except Exception as e:
                            raise RuntimeError(
                                f"MAPD shard scan failed: "
                                f"protocol={protocol}, shard={os.path.basename(shard_path)}, error={e}"
                            ) from e

        _write_lines(
            self.mapd_merged_responses_file, sorted(responsive_probe_addresses)
        )
        decisions = gasser_mapd.classify_prefixes_from_responses(
            probes,
            responsive_probe_addresses,
        )
        aliased_prefixes = [d.prefix for d in decisions if d.status == "aliased"]
        gasser_mapd.write_decision_outputs(
            decisions=decisions,
            aliased_out=self.mapd_aliased_prefixes_file,
            nonaliased_out=self.mapd_nonaliased_prefixes_file,
            summary_out=self.mapd_prefix_status_file,
        )

        mapd_alias_networks = [
            ipaddress.IPv6Network(prefix, strict=False) for prefix in aliased_prefixes
        ]
        mapd_alias_addresses = {
            ip for ip in mapd_targets if _matches_any_prefix(ip, mapd_alias_networks)
        }
        _write_lines(self.mapd_alias_addresses_file, sorted(mapd_alias_addresses))

        unique_probe_count = len({probe.probe for probe in probes})
        aliased_count = len(aliased_prefixes)
        self.last_mapd_stats = {
            "candidate_address_count": len(mapd_targets),
            "candidate_prefix_count": len(candidates),
            "probe_count": unique_probe_count,
            "logical_probe_count": unique_probe_count * len(protocols),
            "responsive_probe_count": len(responsive_probe_addresses),
            "probed_prefix_count": len(decisions),
            "aliased_prefix_count": aliased_count,
            "nonaliased_prefix_count": len(decisions) - aliased_count,
            "alias_address_count": len(mapd_alias_addresses),
            "total_time_sec": time.time() - t0,
        }
        print(
            f"[Final MAPD] aliased_prefixes={aliased_count}, "
            f"alias_addresses={len(mapd_alias_addresses)}, "
            f"probed_prefixes={len(decisions)}, probes={unique_probe_count}"
        )

    def _is_missing_metadata_value(self, value):
        value = str(value).strip()
        return not value or value.lower() in {"unknown", "notexist", "nan", "none"}

    def _metadata_value(self, info, field):
        value = str(info.get(field, "")).strip()
        return "Unknown" if self._is_missing_metadata_value(value) else value

    def enrich_metadata_for_addresses(self, metadata, addresses):
        enriched = {ip: dict(info) for ip, info in metadata.items()}
        unique_addresses = _unique_preserving_order(addresses)
        missing_addresses = []

        for ip in unique_addresses:
            info = enriched.get(ip, {})
            if (
                self._is_missing_metadata_value(info.get("country", ""))
                or self._is_missing_metadata_value(info.get("asnum", ""))
                or self._is_missing_metadata_value(info.get("asorg", ""))
            ):
                missing_addresses.append(ip)

        if not missing_addresses:
            return enriched

        try:
            whois_results = lookup_whois_many(
                missing_addresses,
                asdb_path=CONFIG["WHOIS_ASDB_PATH"],
                locdb_path=CONFIG["WHOIS_LOCDB_PATH"],
                countrydb_path=CONFIG["WHOIS_COUNTRYDB_PATH"],
            )
        except Exception as e:
            print(f"[Warning] Active metadata WHOIS lookup failed: {e}")
            return enriched

        field_mapping = {
            "country": "country",
            "province": "province",
            "city": "city",
            "asnum": "asnum",
            "asorg": "asorg",
            "network_prefix": "prefix",
            "subnet_prefix": "network",
        }
        for record in whois_results:
            ip = str(record.get("ip", "")).strip()
            if not ip:
                continue
            info = enriched.setdefault(ip, {})
            for csv_field, whois_field in field_mapping.items():
                current = info.get(csv_field, "")
                value = record.get(whois_field, "")
                if self._is_missing_metadata_value(
                    current
                ) and not self._is_missing_metadata_value(value):
                    info[csv_field] = str(value).strip()

        return enriched

    def write_active_distribution_reports(self, metadata):
        if os.path.exists(self.all_active_file):
            with open(self.all_active_file, "r", encoding="utf-8") as f:
                active_raw = [line.strip() for line in f if line.strip()]
        else:
            active_raw = []
        metadata = self.enrich_metadata_for_addresses(metadata, active_raw)

        as_stats = {}
        country_stats = {}
        for ip in active_raw:
            info = metadata.get(ip, {})
            asnum = self._metadata_value(info, "asnum")
            asorg = self._metadata_value(info, "asorg")
            country = self._metadata_value(info, "country")
            prefix64 = _prefix64(ip)

            as_key = (asnum, asorg)
            if as_key not in as_stats:
                as_stats[as_key] = {
                    "IPv6AddressNum": 0,
                    "Prefix64Num_Raw": 0,
                    "prefixes": set(),
                }
            as_stats[as_key]["IPv6AddressNum"] += 1
            if prefix64:
                as_stats[as_key]["Prefix64Num_Raw"] += 1
                as_stats[as_key]["prefixes"].add(prefix64)

            if country not in country_stats:
                country_stats[country] = {
                    "IPv6AddressNum": 0,
                    "Prefix64Num_Raw": 0,
                    "prefixes": set(),
                }
            country_stats[country]["IPv6AddressNum"] += 1
            if prefix64:
                country_stats[country]["Prefix64Num_Raw"] += 1
                country_stats[country]["prefixes"].add(prefix64)

        as_rows = [
            {
                "asnum": asnum,
                "asorg": asorg,
                "IPv6AddressNum": values["IPv6AddressNum"],
                "Prefix64Num_Raw": values["Prefix64Num_Raw"],
                "Prefix64Num_Unique": len(values["prefixes"]),
            }
            for (asnum, asorg), values in as_stats.items()
        ]
        as_rows.sort(key=lambda row: row["IPv6AddressNum"], reverse=True)
        with open(
            self.active_as_distribution_file, "w", encoding="utf-8", newline=""
        ) as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "asnum",
                    "asorg",
                    "IPv6AddressNum",
                    "Prefix64Num_Raw",
                    "Prefix64Num_Unique",
                ],
            )
            writer.writeheader()
            writer.writerows(as_rows)

        country_rows = [
            {
                "country": country,
                "IPv6AddressNum": values["IPv6AddressNum"],
                "Prefix64Num_Raw": values["Prefix64Num_Raw"],
                "Prefix64Num_Unique": len(values["prefixes"]),
            }
            for country, values in country_stats.items()
        ]
        country_rows.sort(key=lambda row: row["IPv6AddressNum"], reverse=True)
        with open(
            self.active_country_distribution_file, "w", encoding="utf-8", newline=""
        ) as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "country",
                    "IPv6AddressNum",
                    "Prefix64Num_Raw",
                    "Prefix64Num_Unique",
                ],
            )
            writer.writeheader()
            writer.writerows(country_rows)

    def write_final_summary(self, duration_sec):
        seed_df = pd.read_csv(self.current_seed_csv, dtype=str, low_memory=False)
        col_name = _ip_column(seed_df)
        seed_df[col_name] = seed_df[col_name].astype(str).str.strip()
        seed_df = seed_df.drop_duplicates(subset=[col_name], keep="first")
        metadata = seed_df.set_index(col_name).to_dict(orient="index")
        metadata = self.enrich_metadata_for_addresses(
            metadata,
            set(self.all_unique_active_addresses) | set(self.all_new_seed_addresses),
        )

        def coverage(addresses, field):
            values = set()
            for address in addresses:
                value = self._metadata_value(metadata.get(address, {}), field)
                if value != "Unknown":
                    values.add(value)
            return len(values)

        summary = {
            "Variant": CONFIG["VARIANT"],
            "Total_Rounds": CONFIG["TOTAL_ROUNDS"],
            "Overall_Hit_Rate_Raw_On_Raw_Targets": (
                self.total_active_hits_raw / self.total_generated_raw
                if self.total_generated_raw
                else 0.0
            ),
            "New_Seeds_Total": len(self.all_new_seed_addresses),
            "New_Prefix64_Total": len(self.all_new_prefix64s),
            "Active_ASNs": coverage(self.all_unique_active_addresses, "asnum"),
            "Active_Countries": coverage(self.all_unique_active_addresses, "country"),
            "LAPD_Alias_Prefixes_Total": len(self.all_lapd_alias_prefixes),
            "LAPD_Alias_Addresses_Total": len(self.all_alias_addresses),
        }
        with open(self.summary_csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(summary))
            writer.writeheader()
            writer.writerow(summary)

        with open(self.summary_md_file, "w", encoding="utf-8", newline="\n") as f:
            f.write("# A0 Pro Full Multi-round experiment summary\n\n")
            f.write("| Metric | Value |\n|---|---:|\n")
            for key, value in summary.items():
                f.write(f"| `{key}` | {value} |\n")
        print(
            f"[*] Final summary saved to: {self.summary_csv_file}, {self.summary_md_file}"
        )

    def cleanup_intermediate_csvs(self):
        keep = {
            os.path.abspath(self.stats_csv_file),
            os.path.abspath(self.summary_csv_file),
        }
        for name in os.listdir(self.exp_dir):
            if not name.lower().endswith(".csv"):
                continue
            path = os.path.abspath(os.path.join(self.exp_dir, name))
            if path not in keep:
                os.remove(path)

    def save_round_data(self, active_ips_list):
        if not active_ips_list:
            round_file = os.path.join(self.exp_dir, f"round_{self.round_id}_active.txt")
            open(round_file, "w", encoding="utf-8", newline="\n").close()
            return

        round_file = os.path.join(self.exp_dir, f"round_{self.round_id}_active.txt")
        with open(round_file, "w", encoding="utf-8", newline="\n") as f:
            for ip in active_ips_list:
                f.write(ip + "\n")
        print(f"[*] Round active addresses archived: {os.path.basename(round_file)}")

        with open(self.all_active_file, "a", encoding="utf-8", newline="\n") as f:
            for ip in active_ips_list:
                f.write(ip + "\n")
        print(f"[*] Appended to cumulative file: all_active_ips.txt")

    def feedback_and_update(self, raw_active_ips, unique_active_ips):
        raw_active_count = len(raw_active_ips)
        unique_active_count = len(unique_active_ips)
        self.total_active_hits_raw += raw_active_count
        self.all_unique_active_addresses.update(unique_active_ips)
        raw_prefix64s = [prefix for prefix in map(_prefix64, raw_active_ips) if prefix]
        self.total_active_prefix64_raw += len(raw_prefix64s)
        self.all_active_prefix64s.update(raw_prefix64s)

        hit_rate_raw = (
            raw_active_count / self.last_gen_count if self.last_gen_count > 0 else 0.0
        )
        hit_rate_unique_targets = (
            raw_active_count / self.last_gen_unique_count
            if self.last_gen_unique_count > 0
            else 0.0
        )
        print(
            f"[Feedback] Raw-target hit rate={hit_rate_raw:.4%}, "
            f"Unique-target hit rate={hit_rate_unique_targets:.4%}"
        )

        lapd_alias_networks = [
            ipaddress.IPv6Network(prefix, strict=False)
            for prefix in self.all_lapd_alias_prefixes
        ]
        non_alias_unique_active_ips = [
            ip
            for ip in unique_active_ips
            if not _matches_any_prefix(ip, lapd_alias_networks)
        ]

        new_seed_hits = set(non_alias_unique_active_ips) - self.original_seed_ips
        new_seeds_first_seen = new_seed_hits - self.all_new_seed_addresses
        self.all_new_seed_addresses.update(new_seed_hits)

        round_new_prefix_hits = {
            prefix
            for prefix in map(_prefix64, new_seed_hits)
            if prefix and prefix not in self.original_prefix64s
        }
        new_prefixes_first_seen = round_new_prefix_hits - self.all_new_prefix64s
        self.all_new_prefix64s.update(round_new_prefix_hits)

        total_seeds_now, _ = merge_seeds(
            self.current_seed_csv, non_alias_unique_active_ips, self.current_seed_csv
        )

        row = [
            self.round_id,
            f"{hit_rate_raw:.6f}",
        ]
        with open(self.stats_csv_file, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(row)

        old_k = self.k
        old_hpv_budget_percent = CONFIG["HPV_BUDGET_PERCENT"]
        if self.round_id == CONFIG["TOTAL_ROUNDS"] - 1:
            new_k = 1.0
        elif self.round_id >= CONFIG["TOTAL_ROUNDS"]:
            new_k = 0.0
        else:
            if hit_rate_unique_targets < CONFIG["HITRATE_THRESHOLD_LOW"]:
                new_k = max(self.k * 0.5, 1.0)
            elif hit_rate_unique_targets > CONFIG["HITRATE_THRESHOLD_HIGH"]:
                new_k = max(self.k * 0.9, 1.0)
            else:
                new_k = max(self.k * 0.5, 1.0)

        self.k = new_k
        if old_k > 0:
            new_hpv_budget_percent = old_hpv_budget_percent * (new_k / old_k)
            CONFIG["HPV_BUDGET_PERCENT"] = max(0.0, min(100.0, new_hpv_budget_percent))

        if self.round_id < CONFIG["TOTAL_ROUNDS"]:
            print(f"[*] Next-round K adjusted to: {self.k:.2f}")
            print(
                f"[*] Next-round HPV budget share adjusted to: "
                f"{CONFIG['HPV_BUDGET_PERCENT']:.4f}% "
                f"(old={old_hpv_budget_percent:.4f}%, K {old_k:.2f}->{self.k:.2f})"
            )


if __name__ == "__main__":
    try:
        pipeline = PipelineController()
        pipeline.run()
    except KeyboardInterrupt:
        print("\n[!] Experiment interrupted by user.")
    except Exception as e:
        print(f"\n[!] CRITICAL ERROR occurred: {e}")
        import traceback

        traceback.print_exc()

