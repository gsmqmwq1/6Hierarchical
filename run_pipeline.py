#!/usr/bin/env python3.10
# -*- coding: utf-8 -*-

"""
6Hierarchical Full Pipeline (run_pipeline.py)

1. Runs TOTAL_ROUNDS feedback rounds (default: 5).
2. Each round:
   - Phase 1 (MGHP): Read seeds -> Build MGHP prefix tree -> Save PKL.
   - Phase 2 (BAG):  Load PKL -> Generate candidate IPs based on K value and budget.
   - Phase 3 (Scan): Call ZMap to scan candidates -> Extract active IPs.
3. Feedback Loop:
   - Merge newly discovered active IPs into the seed pool.
   - Dynamically adjust K value for the next round based on hit rate.
"""

import os
import sys
import time
import shutil
import pickle
import subprocess
from pathlib import Path

import phase1_mghp as phase1_kbc
import phase2_bag as phase2_bag

# =======================================================================
# Global Configuration
# =======================================================================

CONFIG = {
    "INITIAL_SEED_CSV": "test.csv",
    "TOTAL_ROUNDS": 5,
    "BUDGET_PER_ROUND": 200000,
    "INITIAL_K": 20.0,
    "MIN_K": 0.0,
    "HITRATE_THRESHOLD_LOW": 0.01,
    "HITRATE_THRESHOLD_HIGH": 0.05,
    "WORK_DIR": "./pipeline_workspace",
    "ZMAP_SOURCE_IP": "your_local_ipv6_address",
}


# =======================================================================
# Utility Functions
# =======================================================================

def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)


def merge_seeds(csv_path, new_ips_file, output_csv):
    """
    Merge newly discovered IPs (txt) into the seed pool (csv),
    generating a new csv for the next round's Phase 1.
    Note: phase1 requires CSV format with country columns.
    For new IPs lacking WHOIS info, fill with 'Unknown'.
    """
    import pandas as pd

    if os.path.exists(output_csv):
        base_df = pd.read_csv(output_csv)
    else:
        base_df = pd.read_csv(csv_path)

    new_ips = set()
    if os.path.exists(new_ips_file):
        with open(new_ips_file, 'r') as f:
            for line in f:
                ip = line.strip()
                if ip: new_ips.add(ip)

    if not new_ips:
        print("[*] No new IPs to merge, keeping original seed pool.")
        if not os.path.exists(output_csv):
            base_df.to_csv(output_csv, index=False)
        return len(base_df)

    print(f"[*] Merging {len(new_ips)} new IPs into seed pool...")

    new_rows = []
    col_name = 'IPv6' if 'IPv6' in base_df.columns else 'IPv6Address'

    existing_ips = set(base_df[col_name].astype(str))

    count_added = 0
    for ip in new_ips:
        if ip not in existing_ips:
            row = {col: 'Unknown' for col in base_df.columns}
            row[col_name] = ip
            new_rows.append(row)
            count_added += 1

    if new_rows:
        new_df = pd.DataFrame(new_rows)
        combined_df = pd.concat([base_df, new_df], ignore_index=True)
        combined_df.to_csv(output_csv, index=False)
        print(f"[*] Merge complete. Added {count_added} unique IPs. Total seeds: {len(combined_df)}")
        return len(combined_df)
    else:
        print("[*] All new IPs already exist, no addition.")
        return len(base_df)


# =======================================================================
# Core Class: Pipeline Controller
# =======================================================================

class PipelineController:
    def __init__(self):
        self.k = CONFIG["INITIAL_K"]
        self.round_id = 1
        self.work_dir = CONFIG["WORK_DIR"]
        ensure_dir(self.work_dir)

        self.current_seed_csv = os.path.join(self.work_dir, "current_seeds.csv")
        self.pkl_file = os.path.join(self.work_dir, "kbc_root.pkl")
        self.candidates_file = os.path.join(self.work_dir, "candidates.txt")
        self.scan_output_file = os.path.join(self.work_dir, "scan_results.txt")

        if not os.path.exists(self.current_seed_csv):
            print("[Init] Initializing seed pool...")
            shutil.copy(CONFIG["INITIAL_SEED_CSV"], self.current_seed_csv)

    def run(self):
        print(f"=== 6Hierarchical Pipeline Started (Total Rounds: {CONFIG['TOTAL_ROUNDS']}) ===")

        for r in range(1, CONFIG['TOTAL_ROUNDS'] + 1):
            self.round_id = r
            print(f"\n>>> Round {r} Start (K={self.k:.2f}, Budget={CONFIG['BUDGET_PER_ROUND']}) <<<")

            self.run_phase1()
            self.run_phase2()
            active_count = self.run_phase3()
            self.feedback_and_update(active_count)

        print("\n=== Pipeline Finished ===")

    def run_phase1(self):
        print("\n[Phase 1] Building MGHP prefix tree...")
        builder = phase1_kbc.KBCBuilder()
        kbc_root = builder.build_tree(self.current_seed_csv)

        if not kbc_root:
            raise Exception("Phase 1 build failed")

        phase1_kbc.update_node_counts(kbc_root)

        with open(self.pkl_file, 'wb') as f:
            pickle.dump(kbc_root, f)
        print(f"[Phase 1] MGHP prefix tree saved to {self.pkl_file}")

    def run_phase2(self):
        print(f"\n[Phase 2] Generating candidate addresses (K={self.k:.2f})...")
        # Load PKL
        with open(self.pkl_file, 'rb') as f:
            kbc_root = pickle.load(f)

        controller = phase2_bag.BudgetController(
            kbc_root,
            total_budget=CONFIG["BUDGET_PER_ROUND"],
            hpv_k=self.k
        )

        candidates = controller.process()

        unique_candidates = list(set(candidates))
        with open(self.candidates_file, 'w', encoding='utf-8', newline='\n') as f:
            for ip in unique_candidates:
                f.write(ip + '\n')

        print(f"[Phase 2] Generated {len(unique_candidates)} candidate IPs, saved to {self.candidates_file}")
        self.last_gen_count = len(unique_candidates)

    def run_phase3(self):
        print("\n[Phase 3] ZMap scanning...")

        if self.last_gen_count == 0:
            print("[Phase 3] Warning: candidate list is empty, skipping scan.")
            return 0

        cmd = (
            f"sudo zmap --ipv6-source-ip={CONFIG['ZMAP_SOURCE_IP']} "
            f"--ipv6-target-file={self.candidates_file} "
            f"-M icmp6_echoscan -p 80 -q -o {self.scan_output_file}"
        )

        print(f"[Exec] {cmd}")
        try:
            result = subprocess.run(cmd, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"[Error] ZMap scan failed: {e}")

        # Collect results
        active_ips = []
        if os.path.exists(self.scan_output_file):
            with open(self.scan_output_file, 'r') as f:
                active_ips = [line.strip() for line in f if line.strip()]

        print(f"[Phase 3] Scan complete. Found {len(active_ips)} active IPs.")
        return len(active_ips)

    def feedback_and_update(self, active_count):
        print("\n[Feedback] Computing feedback metrics...")

        hit_rate = 0.0
        if self.last_gen_count > 0:
            hit_rate = active_count / self.last_gen_count

        print(f"  -> Generated this round: {self.last_gen_count}")
        print(f"  -> Hit this round: {active_count}")
        print(f"  -> HitRate: {hit_rate:.2%}")

        if active_count > 0:
            merge_seeds(
                self.current_seed_csv,
                self.scan_output_file,
                self.current_seed_csv
            )

        print(f"  -> Current K value: {self.k}")

        if self.round_id == CONFIG['TOTAL_ROUNDS'] - 1:
            print("  -> Next is Round 4 (forced convergence): K set to 1.0")
            self.k = 1.0
        elif self.round_id >= CONFIG['TOTAL_ROUNDS']:
            print("  -> Pipeline finished.")
            self.k = 0.0
        else:
            if hit_rate < CONFIG["HITRATE_THRESHOLD_LOW"]:
                print("  -> Hit rate too low (<1%), guessing failed. K halved.")
                self.k = max(self.k * 0.5, 1.0)
            elif hit_rate > CONFIG["HITRATE_THRESHOLD_HIGH"]:
                print("  -> Hit rate high (>5%), guessing correct. K slightly reduced (*0.9).")
                self.k = max(self.k * 0.9, 1.0)
            else:
                print("  -> Hit rate stable. K halved (*0.5) to reallocate budget.")
                self.k = max(self.k * 0.5, 1.0)

        print(f"  -> Next round K value: {self.k:.2f}")


# =======================================================================
# Entry Point
# =======================================================================

if __name__ == "__main__":
    if not os.path.exists(CONFIG["INITIAL_SEED_CSV"]):
        print(f"Error: Initial seed file not found: {CONFIG['INITIAL_SEED_CSV']}")
        sys.exit(1)

    pipeline = PipelineController()
    pipeline.run()
