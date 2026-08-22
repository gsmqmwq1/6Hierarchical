import ipaddress
import random
import time
from dataclasses import dataclass


# Stage 3: LAPD
@dataclass
class LAPDStats:
    alias_prefixes: int = 0
    probe_count: int = 0
    responsive_count: int = 0
    tested_prefixes: int = 0
    max_depth_reached: int = 0
    depth_count: int = 0
    total_time_sec: float = 0.0
    zmap_time_sec: float = 0.0
    judge_time_sec: float = 0.0


def _prefix_of(ip_str, prefix_len):
    return str(ipaddress.IPv6Network(f"{ip_str}/{prefix_len}", strict=False))


def _generate_random_probe_addrs(prefix_str, prefix_len, count):
    net = ipaddress.IPv6Network(prefix_str, strict=False)
    base_int = int(net.network_address)
    host_bits = 128 - prefix_len
    if host_bits <= 0:
        return []

    addrs = set()
    attempts = 0
    max_attempts = max(count * 5, count + 10)
    while len(addrs) < count and attempts < max_attempts:
        attempts += 1
        rand_suffix = random.getrandbits(host_bits)
        addrs.add(str(ipaddress.IPv6Address(base_int | rand_suffix)))
    return list(addrs)


def detect_alias_prefixes(
    active_addresses, scan_func, n_online=14, tau_a=8, delta_on=16, l_on=112
):
    if n_online <= 0:
        raise ValueError("n_online must be positive")
    if tau_a <= 0:
        raise ValueError("tau_a must be positive")
    if delta_on <= 0:
        raise ValueError("delta_on must be positive")
    if l_on < 64 or l_on > 128:
        raise ValueError("l_on must be in [64, 128]")

    alias_prefixes = set()
    uncertain_addresses = [
        addr.strip() for addr in active_addresses if str(addr).strip()
    ]
    stats = LAPDStats()
    total_start = time.time()

    for prefix_len in range(64, l_on + 1, delta_on):
        if not uncertain_addresses:
            break

        depth_start = time.time()
        input_uncertain_count = len(uncertain_addresses)
        current_prefixes = set()
        for addr in uncertain_addresses:
            try:
                current_prefixes.add(_prefix_of(addr, prefix_len))
            except Exception:
                continue

        uncertain_addresses = []
        stats.max_depth_reached = prefix_len
        stats.depth_count += 1

        prefix_to_probes = {}
        probe_to_prefix = {}
        all_probes = []
        for prefix in current_prefixes:
            probes = _generate_random_probe_addrs(prefix, prefix_len, n_online)
            if not probes:
                continue

            stats.tested_prefixes += 1
            stats.probe_count += len(probes)
            prefix_to_probes[prefix] = probes
            for probe in probes:
                probe_to_prefix[probe] = prefix
            all_probes.extend(probes)

        if not all_probes:
            print(
                f"[A0 LAPD][Depth /{prefix_len}] "
                f"uncertain_addrs={input_uncertain_count}, tested_prefixes=0, probes=0, "
                f"zmap_time=0.00s, judge_time=0.00s, responsive=0, "
                f"alias_prefixes_total={len(alias_prefixes)}, next_uncertain_addrs=0"
            )
            continue

        zmap_start = time.time()
        responsive_all = set(scan_func(all_probes))
        zmap_time = time.time() - zmap_start
        stats.zmap_time_sec += zmap_time

        judge_start = time.time()
        prefix_responsive = {prefix: [] for prefix in prefix_to_probes}
        for responsive_ip in responsive_all:
            prefix = probe_to_prefix.get(responsive_ip)
            if prefix is not None:
                prefix_responsive[prefix].append(responsive_ip)

        depth_alias_added = 0
        for prefix, responsive in prefix_responsive.items():
            response_count = len(responsive)
            stats.responsive_count += response_count

            if response_count >= tau_a:
                alias_prefixes.add(prefix)
                depth_alias_added += 1
            elif response_count == 0:
                continue
            else:
                uncertain_addresses.extend(responsive)
        judge_time = time.time() - judge_start
        stats.judge_time_sec += judge_time

        depth_total = time.time() - depth_start
        print(
            f"[A0 LAPD][Depth /{prefix_len}] "
            f"uncertain_addrs={input_uncertain_count}, "
            f"tested_prefixes={len(prefix_to_probes)}, probes={len(all_probes)}, "
            f"zmap_time={zmap_time:.2f}s, judge_time={judge_time:.2f}s, "
            f"depth_time={depth_total:.2f}s, responsive={len(responsive_all)}, "
            f"alias_added={depth_alias_added}, alias_prefixes_total={len(alias_prefixes)}, "
            f"next_uncertain_addrs={len(uncertain_addresses)}"
        )

    stats.alias_prefixes = len(alias_prefixes)
    stats.total_time_sec = time.time() - total_start
    print(
        "[A0 LAPD][Summary] "
        f"depths={stats.depth_count}, tested_prefixes={stats.tested_prefixes}, "
        f"total_probes={stats.probe_count}, total_responsive={stats.responsive_count}, "
        f"alias_prefixes={stats.alias_prefixes}, zmap_time={stats.zmap_time_sec:.2f}s, "
        f"judge_time={stats.judge_time_sec:.2f}s, total_time={stats.total_time_sec:.2f}s"
    )
    return sorted(alias_prefixes), stats
