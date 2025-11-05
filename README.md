# EIP Toolkit - Go Implementation

Go toolkit for monitoring Azure Red Hat OpenShift Egress IP assignments and CloudPrivateIPConfig status.

## Installation

```bash
go mod download
make build-main
# Or manually:
go build -o eip-toolkit eip_toolkit.go
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
./eip-toolkit monitor

# Monitor with custom output directory
./eip-toolkit monitor --output-dir /path/to/output
./eip-toolkit monitor -o /path/to/output

# Process log files into structured data
./eip-toolkit merge <directory>

# Generate plots from data files
./eip-toolkit plot <directory>

# Complete pipeline: monitor → merge → plot
./eip-toolkit all

# Complete pipeline with custom output directory
./eip-toolkit all --output-dir /path/to/output

# Async monitoring (parallel processing via goroutines)
./eip-toolkit monitor-async

# Optimized merge
./eip-toolkit merge-optimized <directory>

# Optimized pipeline
./eip-toolkit all-optimized
```

### Output Structure

By default, output is created in the system's temporary directory:
```
${TMPDIR}/eip-toolkit/YYMMDD_HHMMSS/
├── logs/           # Raw timestamped log files
├── data/           # Processed .dat files
└── plots/          # Generated PNG plots
```

You can specify a custom output base directory using the `--output-dir` (or `-o`) flag. The timestamped directory (YYMMDD_HHMMSS) will be automatically appended:

```bash
./eip-toolkit monitor --output-dir /path/to/output
# Creates: /path/to/output/YYMMDD_HHMMSS/

./eip-toolkit all -o /path/to/output
# Creates: /path/to/output/YYMMDD_HHMMSS/
```

The output directory location is printed at the start of monitoring.

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

- **OpenShiftClient**: Executes `oc` commands, queries EIP and CPIC resources with caching
- **AzureClient**: Executes `az` commands, queries NIC statistics
- **EIPMonitor**: Main monitoring loop, collects and logs statistics with parallel processing
- **SmartCache**: TTL-based caching with LRU eviction
- **BufferedLogger**: Buffered file I/O for performance
- **DataProcessor**: Merges log files into structured data files
- **PlotGenerator**: Reads data files and generates PNG plots using gonum/plot

### Data Flow

#### Monitor Command Flow
```
User
 │
 ├─> ./eip-toolkit monitor
     │
     └─> EIPMonitor.MonitorLoop()
         │
         ├─> OpenShiftClient.GetEIPStats()
         │   └─> oc get eip -o json
         │       └─> Parse JSON → EIPStats
         │
         ├─> OpenShiftClient.GetCPICStats()
         │   └─> oc get cloudprivateipconfig -o json
         │       └─> Parse JSON → CPICStats
         │
         ├─> OpenShiftClient.CountMalfunctioningEIPObjects()
         │   └─> DetectEIPCPICMismatches()
         │       └─> Compare EIP status.items vs CPIC assignments
         │
         ├─> OpenShiftClient.CountOvercommittedEIPObjects()
         │   └─> Count EIP resources with configured IPs > available nodes
         │
         ├─> CollectNodeDataParallel() (goroutines)
         │   ├─> OpenShiftClient.GetNodeStats()
         │   │   ├─> Calculate Primary EIPs (first IP from each EIP resource)
         │   │   └─> Calculate Secondary EIPs (CPIC Success - Primary)
         │   ├─> AzureClient.GetNodeNICStats()
         │   │   └─> az network nic show
         │   │       └─> Parse JSON → (ips, lbs)
         │   └─> BufferedLogger.LogStats()
         │       ├─> Log primary/secondary/assigned EIPs per node
         │       ├─> Log malfunctioning EIP count
         │       └─> Log overcommitted EIP count
         │
         ├─> (After 10 iterations without progress)
         │   ├─> DetectEIPCPICMismatches() (if not already done)
         │   └─> DetectUnassignedEIPs() (if no mismatches detected)
         │
         └─> Write to log files (logs/*.log)
             └─> Repeat every 1 second until complete
```

#### Merge Command Flow
```
User
 │
 ├─> ./eip-toolkit merge <directory>
     │
     └─> DataProcessor.MergeLogs()
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
 ├─> ./eip-toolkit plot <directory>
     │
     └─> PlotGenerator.GenerateAllPlots()
         │
         ├─> Parse .dat files (node sections with timestamp/value pairs)
         │
         ├─> Generate time-series line plots per node
         │
         └─> Save PNG files (plots/*.png)
```

### Monitoring Output

The monitoring command displays real-time statistics with:
- **Timestamp**: Each iteration shows the current timestamp at the top
- **Node Statistics**: Per-node CPIC (success/pending/error), Primary EIPs, Secondary EIPs, and Azure NIC stats
- **Summary Stats**: Single-line summary showing Configured EIPs, Successful CPICs, Assigned EIPs, Malfunction EIPs, Overcommitted EIPs, and CNCC status
- **Value Highlighting**: Values that change between iterations are highlighted in yellow/bold
- **In-place Updates**: Console output overwrites previous lines using ANSI escape codes (when output is to a terminal)
- **Warnings**: After 10 iterations without progress, displays:
  - EIP/CPIC mismatches (if any detected)
  - Unassigned EIPs (if any detected)
  - CPIC errors (if any detected)

Example output:
```
2025/11/04 17:55:22
aro-worker-node1 - CPIC: 32/0/0, Primary EIPs: 30, Secondary EIPs: 2, Azure: 32/32, Capacity: 223/255
aro-worker-node2 - CPIC: 33/0/0, Primary EIPs: 31, Secondary EIPs: 2, Azure: 33/33, Capacity: 222/255
Cluster Summary: Configured EIPs: 100, Successful CPICs: 100, Assigned EIPs: 100, Malfunction EIPs: 0, Overcommitted EIPs: 5, CNCC: 2/2, Total Capacity: 445/510
```

**Key Metrics Explained:**
- **Primary EIPs**: The first IP in the `status.items` list of each EIP resource assigned to the node. Each EIP resource contributes at most one Primary EIP.
- **Secondary EIPs**: Additional IPs from the same EIP resource assigned to the node. Calculated as `CPIC Success - Primary EIPs`.
- **Assigned EIPs**: Total assigned IPs (Primary + Secondary) across all nodes. Should match CPIC Success count.
- **Malfunction EIPs**: EIP resources where IPs in `status.items` don't match CPIC assignments (node mismatches or missing in EIP status). Displayed in **red** if > 0.
- **Overcommitted EIPs**: EIP resources that have more IPs configured than available nodes (cannot all be assigned). Displayed in **yellow** if > 0.

### Monitoring Logic

Monitoring loop continues while:
- `eipStats.Assigned != expectedAssignable` OR
- `cpicStats.Success != expectedAssignable`

Where `expectedAssignable = Configured - unassignableIPs` (accounting for overcommitted EIPs).

**Overcommitment Handling:**
- EIP resources with more IPs configured than available nodes cannot assign all IPs
- The monitoring logic accounts for this by calculating how many IPs are legitimately unassignable
- Monitoring exits when all assignable IPs are assigned (not all configured IPs)

**Mismatch Detection:**
- EIP/CPIC mismatches are detected only after 10 iterations without progress
- Overcommitted EIP resources are excluded from mismatch detection to avoid false positives
- Detailed mismatch IP lists are shown only after 10 iterations without progress and hidden immediately when progress is detected

**Unassigned EIP Detection:**
- Unassigned EIPs are detected only after 10 iterations without progress
- Only shown if no mismatches are already detected (to avoid duplicate reporting)

### Logged Metrics

The following metrics are logged to files for tracking and plotting:

**Per-Node Metrics:**
- `{node}_ocp_cpic_success.log`, `{node}_ocp_cpic_pending.log`, `{node}_ocp_cpic_error.log`
- `{node}_ocp_eip_primary.log` - Primary EIPs count
- `{node}_ocp_eip_secondary.log` - Secondary EIPs count
- `{node}_ocp_eip_assigned.log` - Total assigned EIPs (Primary + Secondary)
- `{node}_azure_eips.log`, `{node}_azure_lbs.log`
- `{node}_capacity_capacity.log`

**Cluster-Level Metrics:**
- `ocp_eips_configured.log`, `ocp_eips_assigned.log`, `ocp_eips_unassigned.log`
- `ocp_cpic_success.log`, `ocp_cpic_pending.log`, `ocp_cpic_error.log`
- `cluster_summary_total_primary_eips.log` - Total Primary EIPs across all nodes
- `cluster_summary_total_secondary_eips.log` - Total Secondary EIPs across all nodes
- `cluster_summary_total_assigned_eips.log` - Total Assigned EIPs
- `cluster_summary_total_azure_eips.log`
- `cluster_summary_node_count.log`
- `cluster_summary_avg_eips_per_node.log`
- `malfunctioning_eip_objects_count.log` - Number of EIP resources with mismatches
- `overcommitted_eip_objects_count.log` - Number of EIP resources overcommitted
- `eip_cpic_mismatches_total.log` - Total mismatch count (only logged after 10 iterations without progress)
- `eip_cpic_mismatches_node_mismatch.log` - Node assignment mismatches
- `eip_cpic_mismatches_missing_in_eip.log` - IPs in CPIC but not in EIP status

### Go-Specific Features

- **Goroutines**: Parallel node data collection using goroutines and semaphores
- **SmartCache**: Thread-safe caching with TTL and LRU eviction
- **BufferedLogger**: Concurrent-safe buffered file I/O
- **Error Handling**: Custom error types with proper error wrapping
- **Real-time Console Updates**: ANSI escape codes for in-place output overwriting (terminal-aware)
- **Value Change Highlighting**: Visual feedback for metrics that change between iterations
- **Terminal Detection**: Automatically detects if output is to a terminal and adjusts formatting accordingly
- **Progress Tracking**: Tracks iterations without progress to conditionally display detailed warnings
- **Mismatch Detection**: Detects inconsistencies between EIP and CPIC node assignments
- **Overcommitment Detection**: Identifies EIP resources with more IPs than available nodes
