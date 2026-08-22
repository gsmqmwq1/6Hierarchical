# 6Hierarchical

6Hierarchical is a systematic IPv6 active scanning framework that combines hierarchical prefix analysis, BAG/MGHP candidate generation, ZMap probing, feedback updates, online LAPD screening, and final Gasser MAPD classification.

## Dependencies and Installation

6Hierarchical is compatible with Python 3.10+. The required Python packages can be installed with:

```bash
pip3 install -r requirements.txt
```

## ZMap Installation for IPv6 Scanning

6Hierarchical uses ZMap for IPv6 active probing. Users should ensure that they have permission to conduct active measurements from their local network before running the scanning component.

### Building from Source

```bash
git clone https://github.com/tumi8/zmap.git
cd zmap
```

### Installing ZMap Dependencies

On Debian-based systems, including Ubuntu:

```bash
sudo apt-get install build-essential cmake libgmp3-dev gengetopt libpcap-dev flex byacc libjson-c-dev pkg-config libunistring-dev
```

On RHEL- and Fedora-based systems, including CentOS:

```bash
sudo yum install cmake gmp-devel gengetopt libpcap-devel flex byacc json-c-devel libunistring-devel
```

On macOS systems using Homebrew:

```bash
brew install pkg-config cmake gmp gengetopt json-c byacc libdnet libunistring
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
| `whois/` | Local ASN, country, city, and prefix metadata lookup resources. |
| `test.csv` | Lightweight seed dataset for validation. |
| `requirements.txt` | Python package dependencies required by the artifact. |

### Data

The repository includes `test.csv`, a lightweight seed dataset for validating the workflow. The large-scale measurement datasets used in the paper are not included due to data size and measurement considerations.

Users may replace `test.csv` with their own authorized IPv6 seed dataset. The input CSV should contain `IPv6Address` or `IPv6`, together with the metadata fields required by the pipeline: `country`, `province`, `city`, `asnum`, `asorg`, `network_prefix`, and `subnet_prefix`.

The local `whois/` directory contains the lookup code and databases used to obtain ASN, country, city, and prefix metadata.

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

### Step 1: Clone the Repository and Install Dependencies

```bash
git clone https://github.com/gsmqmwq1/6Hierarchical.git
cd 6Hierarchical
pip3 install -r requirements.txt
```

### Step 2: Install ZMap

Install ZMap following the instructions in the ZMap installation section above.

### Step 3: Configure the Local IPv6 Source Address

Set the local IPv6 source address in `run_pipeline.py`:

```python
"ZMAP_SOURCE_IP": "your_local_ipv6_address"
```

The input seed file can remain `test.csv` for validation, or be replaced with a relative path to an authorized seed dataset.

### Step 4: Run the Full Pipeline

The full pipeline requires root privileges for ZMap-based scanning:

```bash
sudo python3 run_pipeline.py
```

## Running Individual Phases

The integrated entry point is recommended because it manages intermediate artifacts, feedback, online LAPD state, and final MAPD results.

The standalone phase scripts use the relative input and output filenames defined in their configuration blocks.

### Phase 1: Build the MGHP Prefix Tree

```bash
python3 phase1_mghp.py
```

This step reads the configured seed CSV and constructs the hierarchical prefix tree.

### Phase 2: Generate Candidate Addresses with BAG

```bash
python3 phase2_bag.py
```

This step loads the serialized prefix tree and generates candidate IPv6 addresses under the configured budget.

### Phase 3: Scan Candidate Addresses with ZMap

```bash
sudo zmap --ipv6-source-ip=your_local_ipv6_address \
    --ipv6-target-file=candidates.txt \
    -M icmp6_echoscan \
    -q -o scan_results.txt
```

Online LAPD screening, feedback updates, and final MAPD are managed by `run_pipeline.py` after each scan round.

## Artifact Status

This repository provides the main 6Hierarchical workflow for reproducibility checking. It includes the core implementation, a lightweight validation dataset, local metadata lookup resources, and dependency documentation.

Large-scale measurement datasets and generated scanning outputs are not included. Users should run the workflow only with authorized seed data and a properly configured IPv6 scanning environment.
