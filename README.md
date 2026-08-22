# 6Hierarchical

6Hierarchical is a systematic IPv6 active scanning framework that combines hierarchical prefix analysis, BAG/MGHP candidate generation, ZMap probing, feedback updates, online LAPD screening, and final Gasser MAPD classification.

## WSL Ubuntu Setup

The artifact is intended to run in Ubuntu on WSL2. Run all commands from the repository root. Python 3.10 or newer is recommended.

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## ZMap Installation for IPv6 Scanning

6Hierarchical uses ZMap for IPv6 active probing. Users should ensure that they have permission to conduct active measurements from their local network before running the scanning component.

### Building from Source

```bash
git clone https://github.com/tumi8/zmap.git
cd zmap
```

### Installing ZMap Dependencies in WSL Ubuntu

```bash
sudo apt-get install -y build-essential cmake libgmp3-dev gengetopt libpcap-dev flex byacc libjson-c-dev pkg-config libunistring-dev
```

### Building and Installing ZMap

```bash
cmake .
make -j4
sudo make install
```

## Usage

### Files

| File | Introduction |
|---|---|
| `run_pipeline.py` | Main entry point. Runs MGHP, BAG, ZMap probing, feedback, online LAPD, and final MAPD. |
| `phase1_mghp.py` | Phase 1: builds the hierarchical prefix tree from seed IPv6 addresses and metadata. |
| `phase2_bag.py` | Phase 2: performs budget-aware candidate IPv6 address generation with BAG/MGHP. |
| `lapd.py` | Online lightweight alias-prefix pre-screening. |
| `gasser_mapd.py` | Final MAPD candidate generation and alias classification. |
| `whois/` | Metadata lookup code. GeoIP databases are downloaded separately and are not included in the repository. |
| `test.csv` | Lightweight seed dataset for validation. |
| `requirements.txt` | Python package dependencies required by the artifact. |
| `LICENSE` | MIT License for the original source code in this repository. |

### Data

The repository includes `test.csv`, a lightweight seed dataset for validating the workflow. The large-scale measurement datasets used in the paper are not included due to data size and measurement considerations.

Users may replace `test.csv` with their own authorized IPv6 seed dataset. For the integrated workflow, edit `INITIAL_SEED_CSV` in the `CONFIG` block near the top of `run_pipeline.py`. For standalone Phase 1, edit `CSV_INPUT_FILE` in the `__main__` block of `phase1_mghp.py`. Use repository-relative paths, for example `data/my_seed.csv`.

The input CSV should contain `IPv6Address` or `IPv6`, together with the metadata fields required by the pipeline: `country`, `province`, `city`, `asnum`, `asorg`, `network_prefix`, and `subnet_prefix`.

The local `whois/` directory contains the lookup code used to obtain ASN, country, city, and prefix metadata. The actual GeoIP databases are not included in this repository because they are large and subject to MaxMind licensing terms.

## GeoIP Database Setup

The pipeline requires three local MaxMind databases for metadata lookup:

| Database file | Purpose |
|---|---|
| `whois/GeoLite2-ASN.mmdb` | ASN and organization lookup. |
| `whois/GeoLite2-City.mmdb` | Country, province, city, and network lookup. |
| `whois/GeoLite2-Country.mmdb` | Country-level fallback lookup. |

These files are intentionally excluded from GitHub. Do not commit them to the repository, and do not commit your MaxMind account credentials or license key.

The databases are not provided with this artifact. Each user is responsible for obtaining compatible databases through an authorized source and placing them in the `whois/` directory. This repository does not provide database download information, download links, account credentials, or license keys.

The current pipeline expects the country fallback file to be named `GeoLite2-Country.mmdb`. The final local layout should be:

```text
whois/
|-- IPv6AddMoreInformationRead.py
|-- __init__.py
|-- GeoLite2-ASN.mmdb
|-- GeoLite2-City.mmdb
`-- GeoLite2-Country.mmdb
```

The database files are ignored by `.gitignore` and remain local to each experiment environment. If the databases are missing, metadata lookup and the full pipeline cannot run correctly.

## Parameters

### `run_pipeline.py`

| Parameter | Type | Default | Introduction |
|---|---|---|---|
| `INITIAL_SEED_CSV` | `str` | `test.csv` | Path to the initial seed CSV file. |
| `TOTAL_ROUNDS` | `int` | `20` | Number of feedback rounds. |
| `BUDGET_PER_ROUND` | `int` | `200000` | Number of candidate addresses generated in each round. |
| `INITIAL_K` | `float` | `15.0` | Initial HPV bonus multiplier. |
| `ZMAP_SOURCE_IP` | `str` | `your_local_ipv6_address` | Local IPv6 source address used by ZMap. |
| `LAPD_N_ONLINE` | `int` | `14` | Number of online LAPD probes per prefix. |
| `LAPD_TAU_A` | `int` | `8` | Online LAPD alias decision threshold. |

The configured source address should be a valid local IPv6 address on the machine used for active probing. `ZMAP_INTERFACE` and `ZMAP_GATEWAY_MAC` are optional local-network settings.

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

The integrated entry point is recommended because it manages intermediate artifacts, feedback, online LAPD state, and final MAPD results.

The standalone phase scripts use the relative input and output filenames defined in their configuration blocks.

### Phase 1: Build the MGHP Prefix Tree

```bash
python3 phase1_mghp.py
```

This step reads `test.csv` by default and constructs the hierarchical prefix tree. It writes `mghp_root.pkl` and `mghp_tree.txt` in the repository root.

### Phase 2: Generate Candidate Addresses with BAG

```bash
python3 phase2_bag.py
```

This step loads `mghp_root.pkl` and generates `candidates.txt` under the configured budget. The input and output filenames can be changed in the `BAG_CONFIG` block.

### Phase 3: Scan Candidate Addresses with ZMap

```bash
sudo zmap --ipv6-source-ip=your_local_ipv6_address \
    --ipv6-target-file=candidates.txt \
    -M icmp6_echoscan \
    -q -o scan_results.txt
```

Online LAPD screening, feedback updates, and final MAPD are managed by `run_pipeline.py` after each scan round.

## Artifact Status

This repository provides the main 6Hierarchical workflow for reproducibility checking. It includes the core implementation, a lightweight validation dataset, metadata lookup code, GeoIP setup documentation, and dependency documentation. The MaxMind databases are intentionally distributed separately.

Large-scale measurement datasets and generated scanning outputs are not included. Users should run the workflow only with authorized seed data and a properly configured IPv6 scanning environment.

## License

The original source code in this repository is released under the MIT License. Third-party software, datasets, GeoIP databases, and external services remain subject to their respective licenses and terms of use. See `LICENSE` for the complete license text.
