# 6Hierarchical

6Hierarchical is a hierarchical multi-pattern approach for active IPv6 address scanning within subnet prefixes, balancing prefix exploration and IID exploitation under a budget-aware multi-round loop.

## WSL Ubuntu Setup

6Hierarchical runs on Ubuntu under WSL2. The commands below assume you are in the repository root, and Python 3.10 or newer is recommended.

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Installing ZMap

IPv6 probing is handled by ZMap, which has to be built from source first. Before starting a scan, please make sure you are allowed to run active measurements from your network.

### Dependencies

```bash
sudo apt-get install -y build-essential cmake libgmp3-dev gengetopt libpcap-dev flex byacc libjson-c-dev pkg-config libunistring-dev
```

### Build from source

```bash
git clone https://github.com/tumi8/zmap.git
cd zmap
cmake .
make -j4
sudo make install
```

## Usage

### Files

| File | Introduction |
|---|---|
| `run_pipeline.py` | Main entry point. |
| `phase1_mghp.py` | Builds the hierarchical prefix tree (MGHP). |
| `phase2_bag.py` | Budget-aware candidate generation (BAG). |
| `lapd.py` | Online alias-prefix pre-screening (LAPD). |
| `gasser_mapd.py` | Final de-aliasing (MAPD). |
| `whois/` | Metadata lookup code. |

### Data

For security and network-compliance reasons, this repository only ships a small test seed set (`test.csv`) for validating the workflow.

If you have your own authorized seed data, point `INITIAL_SEED_CSV` in `CONFIG` to your CSV file. It should contain `IPv6Address` (or `IPv6`) along with `country`, `province`, `city`, `asnum`, `asorg`, `network_prefix`, and `subnet_prefix`.

## GeoIP Database Setup

Metadata lookup relies on three MaxMind GeoLite2 databases, which are not bundled with this repository. Download them from MaxMind (https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) and place them in the `whois/` directory, keeping the file names below so the pipeline can resolve ASN and geolocation for candidate addresses:

| Database file | Purpose |
|---|---|
| `whois/GeoLite2-ASN.mmdb` | ASN and organization lookup. |
| `whois/GeoLite2-City.mmdb` | Country, province, city, and network lookup. |
| `whois/GeoLite2-Country.mmdb` | Country-level fallback lookup. |

## Parameters

### `run_pipeline.py`

| Parameter | Default | Introduction |
|---|---|---|
| `INITIAL_SEED_CSV` | `test.csv` | Seed CSV file. |
| `TOTAL_ROUNDS` | `20` | Number of feedback rounds. |
| `BUDGET_PER_ROUND` | `200000` | Candidate addresses per round. |
| `INITIAL_K` | `15.0` | Initial expansion coefficient. |
| `R_THRESHOLD` | `0.8` | HPV/LPV classification threshold. |
| `ZMAP_SOURCE_IP` | `your_local_ipv6_address` | ZMap source address; set it to yours. |

## Example

### Step 1: Clone the Repository and Install Dependencies in WSL Ubuntu

```bash
git clone https://github.com/gsmqmwq1/6Hierarchical.git
cd 6Hierarchical
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Step 2: Install ZMap

Install ZMap following the instructions in the ZMap installation section above.

### Step 3: Configure GeoIP Databases

Follow the [GeoIP Database Setup](#geoip-database-setup) section and verify that all three database files exist under `whois/`.

### Step 4: Configure the Local IPv6 Source Address and Dataset

Set the local IPv6 source address in `run_pipeline.py`:

```python
"ZMAP_SOURCE_IP": "your_local_ipv6_address"
```

The input seed file can remain `test.csv` for validation, or `INITIAL_SEED_CSV` can be replaced with a repository-relative path to an authorized seed dataset. In WSL, the source address can be inspected with:

```bash
ip -6 addr show dev eth0 scope global
```

### Step 5: Run the Full Pipeline

Run the pipeline as the normal WSL user. The pipeline invokes `sudo zmap` for the scanning subprocess, so the terminal may request the sudo password:

```bash
python3 run_pipeline.py
```

## Running Individual Phases

Running `run_pipeline.py` is recommended, since it handles feedback, LAPD state, and final MAPD validation. The phases can also be run on their own.

### Phase 1: Build the Prefix Tree

```bash
python3 phase1_mghp.py
```

Writes `mghp_root.pkl` and `mghp_tree.txt`.

### Phase 2: Generate Candidates

```bash
python3 phase2_bag.py
```

Reads `mghp_root.pkl` and writes `candidates.txt`.

### Phase 3: Scan with ZMap

```bash
sudo zmap --ipv6-source-ip=your_local_ipv6_address \
    --ipv6-target-file=candidates.txt \
    -M icmp6_echoscan \
    -q -o scan_results.txt
```

## Artifact Status

This repository contains the implementation, a lightweight validation dataset, metadata lookup code, and setup documentation.

Scan results and measurement data are not released, in the interest of responsible network measurement and to discourage unauthorized or abusive scanning. Users are asked to probe only networks they are authorized to test.

## License

The original source code in this repository is released under the MIT License. Third-party software, datasets, GeoIP databases, and external services remain subject to their respective licenses and terms of use. See `LICENSE` for the complete license text.
