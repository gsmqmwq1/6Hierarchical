# 6Hierarchical

6Hierarchical is a systematic IPv6 active scanning framework that prioritizes hierarchical prefix analysis over IID pattern mining. It employs the MGHP algorithm for hierarchical expansion of coarse-grained prefixes to map out potentially active /64 subnets, then applies a targeted IID migration and splicing strategy to generate probes.

## Dependencies and Installation

6Hierarchical is compatible with Python 3.10+. You can install the required packages through the following command:

```bash
pip3 install -r requirements.txt
```

### zmapv6 installation (ask in IPv4 network)

#### Building from Source

```bash
git clone https://github.com/tumi8/zmap.git
cd zmap
```

#### Installing ZMap Dependencies

On Debian-based systems (including Ubuntu):

```bash
sudo apt-get install build-essential cmake libgmp3-dev gengetopt libpcap-dev flex byacc libjson-c-dev pkg-config libunistring-dev
```

On RHEL- and Fedora-based systems (including CentOS):

```bash
sudo yum install cmake gmp-devel gengetopt libpcap-devel flex byacc json-c-devel libunistring-devel
```

On macOS systems (using Homebrew):

```bash
brew install pkg-config cmake gmp gengetopt json-c byacc libdnet libunistring
```

#### Building and Installing ZMap

```bash
cmake .
make -j4
sudo make install
```

## Usage

### Files

| File | Introduction |
|---|---|
| `run_pipeline.py` | Main entrance. Runs the full pipeline: MGHP -> BAG -> Scan -> Feedback. |
| `phase1_mghp.py` | Phase 1 (MGHP): Builds hierarchical prefix tree from seed addresses and serializes to PKL. |
| `phase2_bag.py` | Phase 2 (BAG): Generates candidate IPv6 addresses from the prefix tree under a given budget. |

### Data

| file | Introduction |
|---|---|
| `test.csv` | Seed IPv6 addresses with WHOIS metadata |

<font color="red">Please note that we have only provided a portion of the seed addresses. For full data, please obtain them from other channels.</font>

<font color="blue">e.g.,</font>

<font color="blue">seed addresses from https://addrminer.github.io/IPv6_hitlist.github.io/# ;</font>

<font color="blue">WHOIS information from the Regional Internet Registry (RIR).</font>

### Parameters

**run_pipeline.py:**

* `INITIAL_SEED_CSV`: type=str, default=`test.csv`, path to the seed CSV file
* `TOTAL_ROUNDS`: type=int, default=5, number of feedback rounds
* `BUDGET_PER_ROUND`: type=int, default=200000, candidate IPs generated per round
* `INITIAL_K`: type=float, default=20.0, initial HPV bonus multiplier
* `ZMAP_SOURCE_IP`: type=str, local IPv6 address for ZMap scanning

**phase2_bag.py:**

* `TOTAL_BUDGET`: type=int, default=1000000, total address generation budget
* `HPV_BONUS_K`: type=float, default=2.0, K multiplier for HPV nodes
* `R_THRESHOLD`: type=float, default=0.8, ratio threshold for HPV/LPV classification
* `ENTROPY_THRESHOLD`: type=float, default=0.1, nibble entropy threshold for HMLEA
* `SMOOTHING_ALPHA`: type=float, default=0.01, Laplace smoothing for probability tables

### Example

**Step 1**: Clone the repository and install dependencies.

```bash
git clone https://github.com/<your-username>/6Hierarchical.git
cd 6Hierarchical
pip3 install -r requirements.txt
```

**Step 2**: Install ZMap (see installation section above).

**Step 3**: Set your local IPv6 address in `run_pipeline.py`:

```python
"ZMAP_SOURCE_IP": "your_local_ipv6_address"
```

**Step 4**: Run the full pipeline (requires root for ZMap scanning).

```bash
sudo python3 run_pipeline.py
```

**Run each phase individually:**

Phase 1 (MGHP) — build prefix tree:

```bash
python3 phase1_mghp.py
```

Phase 2 (BAG) — generate candidate addresses:

```bash
python3 phase2_bag.py
```

Phase 3 (Scan) — scan candidates with ZMap:

```bash
sudo zmap --ipv6-source-ip=your_local_ipv6_address \
    --ipv6-target-file=candidates.txt \
    -M icmp6_echoscan -p 80 -q -o scan_results.txt
```

## Data

Data Access: https://addrminer.github.io/IPv6_hitlist.github.io/#

If you want more data, you can send a request to <your-email@example.com>

The request should include the work department, the purpose of data usage, and the data content obtained.
