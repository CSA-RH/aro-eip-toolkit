# EIP Toolkit

Python toolkit for monitoring Azure Red Hat OpenShift Egress IP assignments and CloudPrivateIPConfig status.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Set environment variables:
```bash
export AZ_SUBSCRIPTION="your-subscription-id"
export AZ_RESOURCE_GROUP="your-resource-group"
```

## Usage

### Commands

```bash
# Monitor EIP and CPIC status
python3 eip_toolkit.py monitor

# Process log files into structured data
python3 eip_toolkit.py merge <directory>

# Generate plots from data files
python3 eip_toolkit.py plot <directory>

# Complete pipeline: monitor → merge → plot
python3 eip_toolkit.py all

# Async monitoring (parallel processing)
python3 eip_toolkit.py monitor-async

# Optimized merge (pandas-based)
python3 eip_toolkit.py merge-optimized <directory>

# Optimized pipeline
python3 eip_toolkit.py all-optimized
```

### Output Structure

```
../runs/YYMMDD_HHMMSS/
├── logs/           # Raw timestamped log files
├── data/           # Processed .dat files
└── plots/          # Generated PNG plots
```

## Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                      EIPToolkit CLI                          │
└───────────┬─────────────────────────────────────────────────┘
            │
    ┌───────┴───────┬───────────────┬──────────────┐
    │               │               │              │
┌───▼────┐    ┌─────▼─────┐   ┌─────▼─────┐   ┌───▼──────┐
│EIPMonitor│   │DataProcessor│  │PlotGenerator│  │  (other) │
└───┬────┘    └─────┬─────┘   └─────┬─────┘   └──────────┘
    │               │               │
    ├───────────────┼───────────────┘
    │               │
┌───▼────┐    ┌─────▼─────┐
│OpenShift│   │  Azure    │
│  Client │   │  Client   │
└───┬────┘    └─────┬─────┘
    │               │
┌───▼────┐    ┌─────▼─────┐
│  oc CLI│    │  az CLI   │
└───┬────┘    └─────┬─────┘
    │               │
┌───▼────┐    ┌─────▼─────┐
│  EIP   │    │  Azure    │
│Resources│    │   NICs    │
└────────┘    └───────────┘

Data Flow:
EIPMonitor → Log Files → DataProcessor → Data Files (.dat) → PlotGenerator → PNG Plots
```

### Core Components

- **OpenShiftClient**: Executes `oc` commands, queries EIP and CPIC resources
- **AzureClient**: Executes `az` commands, queries NIC statistics
- **EIPMonitor**: Main monitoring loop, collects and logs statistics
- **DataProcessor**: Merges log files into structured data files
- **PlotGenerator**: Reads data files and generates time-series plots
- **EIPToolkit**: CLI entry point with command routing

### Data Flow

#### Monitor Command Flow
```
User
 │
 ├─> eip_toolkit.py monitor
     │
     └─> EIPMonitor.monitor_loop()
         │
         ├─> OpenShiftClient.get_eip_stats()
         │   └─> oc get eip -o json
         │       └─> Parse JSON → EIPStats
         │
         ├─> OpenShiftClient.get_cpic_stats()
         │   └─> oc get cloudprivateipconfig -o json
         │       └─> Parse JSON → CPICStats
         │
         ├─> AzureClient.get_node_nic_stats()
         │   └─> az network nic show
         │       └─> Parse JSON → (ips, lbs)
         │
         └─> Write to log files (logs/*.log)
             └─> Repeat every 1 second until complete
```

#### Merge Command Flow
```
User
 │
 ├─> eip_toolkit.py merge <directory>
     │
     └─> DataProcessor.merge_logs()
         │
         ├─> Read log files (logs/*.log)
         │
         ├─> Parse entries (timestamp, value)
         │
         ├─> Group by metric type and node
         │
         └─> Write structured data (data/*.dat)
```

#### Plot Command Flow
```
User
 │
 ├─> eip_toolkit.py plot <directory>
     │
     └─> PlotGenerator.generate_all_plots()
         │
         ├─> Read data files (data/*.dat)
         │
         ├─> Parse sections (node name, data lines)
         │
         ├─> Extract timestamps and values
         │
         └─> Generate matplotlib plots → PNG files (plots/*.png)
```

#### Monitor Command
1. Query OpenShift for EIP-enabled nodes via `oc get nodes`
2. For each iteration:
   - Query EIP resources: `oc get eip -o json`
   - Query CPIC resources: `oc get cloudprivateipconfig -o json`
   - Query Azure NIC stats: `az network nic show`
   - Parse JSON responses and extract statistics
   - Write timestamped values to log files
3. Continue until `assigned == configured` and `cpic_success == configured`

#### Merge Command
1. Read log files from `logs/` directory
2. Parse log entries (timestamp, value pairs)
3. Group by metric type and node
4. Write structured data to `.dat` files in `data/` directory
5. Format: node name header followed by timestamp/value pairs

#### Plot Command
1. Read `.dat` files from `data/` directory
2. Parse sections (node name, data lines)
3. Extract timestamps and values per node
4. Generate matplotlib plots with time-series data
5. Save PNG files to `plots/` directory

### Monitoring Logic

Monitoring loop continues while:
- `eip_stats.assigned != eip_stats.configured` OR
- `cpic_stats.success != eip_stats.configured`

Exits when both conditions are false (all EIPs assigned, all CPICs successful).
