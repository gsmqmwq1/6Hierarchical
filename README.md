# 6Hierarchical

6Hierarchical is a systematic IPv6 active scanning framework that prioritizes hierarchical prefix analysis over IID pattern mining. It first applies the MGHP algorithm to expand coarse-grained prefixes and identify potentially active /64 subnets. It then uses the BAG strategy to allocate the probing budget and generate candidate IPv6 addresses through targeted IID migration and splicing.

This repository provides a lightweight implementation artifact for validating the main workflow of 6Hierarchical, including hierarchical prefix construction, budget-aware address generation, and ZMap-based active probing.

## Dependencies and Installation

6Hierarchical is compatible with Python 3.10+. The required Python packages can be installed with:

```bash
pip3 install -r requirements.txt
```

## ZMap Installation for IPv6 Scanning

6Hierarchical uses ZMap for active IPv6 probing. Users should ensure that they have permission to conduct active measurements from their local network before running the scanning component.

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
| `run_pipeline.py` | Main entry point of the project. It runs the full pipeline: MGHP -> BAG -> Scan -> Feedback. |
| `phase1_mghp.py` | Phase 1: builds the MGHP hierarchical prefix tree from seed IPv6 addresses and serializes the tree structure. |
| `phase2_bag.py` | Phase 2: performs budget-aware candidate IPv6 address generation from the MGHP prefix tree. |
| `test.csv` | A lightweight seed dataset used for testing and validating the workflow. |
| `requirements.txt` | Python package dependencies required by the artifact. |

### Data

The repository includes `test.csv`, a lightweight seed dataset for validating the execution workflow. The large-scale measurement dataset used in the paper is not included in this repository due to data size and ethical considerations related to Internet-scale IPv6 active probing.

Users may run the pipeline with their own seed addresses and metadata. Example data sources include:

- Public IPv6 hitlists.
- WHOIS/RDAP metadata from Regional Internet Registries (RIRs).
- Locally collected IPv6 seed addresses, subject to the user's measurement policy and network authorization.

The input CSV file should contain seed IPv6 addresses and the metadata fields required by the pipeline. The included `test.csv` provides an example of the expected input format.

## Parameters

### `run_pipeline.py`

| Parameter | Type | Default | Introduction |
|---|---|---|---|
| `INITIAL_SEED_CSV` | `str` | `test.csv` | Path to the initial seed CSV file. |
| `TOTAL_ROUNDS` | `int` | `5` | Number of feedback rounds. |
| `BUDGET_PER_ROUND` | `int` | `200000` | Number of candidate addresses generated in each round. |
| `INITIAL_K` | `float` | `20.0` | Initial HPV bonus multiplier. |
| `ZMAP_SOURCE_IP` | `str` | `your_local_ipv6_address` | Local IPv6 source address used by ZMap. |

### `phase2_bag.py`

| Parameter | Type | Default | Introduction |
|---|---|---|---|
| `TOTAL_BUDGET` | `int` | `1000000` | Total address generation budget. |
| `HPV_BONUS_K` | `float` | `2.0` | Bonus multiplier for HPV nodes. |
| `R_THRESHOLD` | `float` | `0.8` | Ratio threshold for HPV/LPV classification. |
| `ENTROPY_THRESHOLD` | `float` | `0.1` | Nibble entropy threshold for HMLEA. |
| `SMOOTHING_ALPHA` | `float` | `0.01` | Laplace smoothing factor for probability tables. |

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

The configured address should be a valid local IPv6 address on the machine used for active probing.

### Step 4: Run the Full Pipeline

The full pipeline requires root privileges for ZMap-based scanning:

```bash
sudo python3 run_pipeline.py
```

## Running Individual Phases

### Phase 1: Build the MGHP Prefix Tree

```bash
python3 phase1_mghp.py
```

This step reads the seed addresses from the input CSV file and constructs the MGHP hierarchical prefix tree.

### Phase 2: Generate Candidate Addresses with BAG

```bash
python3 phase2_bag.py
```

This step generates candidate IPv6 addresses from the serialized MGHP prefix tree under a given probing budget.

### Phase 3: Scan Candidate Addresses with ZMap

```bash
sudo zmap --ipv6-source-ip=your_local_ipv6_address \
    --ipv6-target-file=candidates.txt \
    -M icmp6_echoscan \
    -q -o scan_results.txt
```

Some local ZMap builds may require additional configuration, such as the network interface, source IPv6 address, or probing permissions. Please verify the local network configuration before running active scans.

## Artifact Status

This repository provides a lightweight implementation artifact of 6Hierarchical for reproducibility checking. It includes the main workflow and a small test dataset for validating the execution process.

The large-scale measurement dataset used in the paper is not included due to data size and ethical considerations related to Internet-scale IPv6 active probing. Users may run the workflow with the provided test dataset or with their own seed addresses and metadata.
