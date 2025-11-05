# EIP Toolkit

Monitors Azure Red Hat OpenShift Egress IP assignments and CloudPrivateIPConfig status.

## Installation

### Using Pre-built Binaries (Recommended)

Download the pre-built binary for your platform from the [GitHub Releases](https://github.com/CSA-RH/aro-eip-toolkit/releases):

**macOS (Apple Silicon):**
```bash
curl -L -o eip-toolkit https://github.com/CSA-RH/aro-eip-toolkit/releases/download/v0.1.0/eip-toolkit-darwin-arm64
chmod +x eip-toolkit
```

**Linux (x86_64):**
```bash
curl -L -o eip-toolkit https://github.com/CSA-RH/aro-eip-toolkit/releases/download/v0.1.0/eip-toolkit-linux-amd64
chmod +x eip-toolkit
```

Then set environment variables:
```bash
export AZ_SUBSCRIPTION="your-subscription-id"
export AZ_RESOURCE_GROUP="your-resource-group"
```

### Building from Source

If you prefer to build from source:

```bash
go mod download
make build-main
# Or manually:
go build -o eip-toolkit eip_toolkit.go

# Cross-platform builds:
make build-darwin-amd64    # Intel Mac
make build-darwin-arm64    # Apple Silicon
make build-linux-amd64     # Linux x86_64
make build-linux-arm64     # Linux ARM64
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

**Early Exit Behavior:**
- If all EIPs are already properly configured, the tool will:
  - Print the current state once
  - Exit without creating directories, logs, or graphs
  - This allows quick status checks without generating files

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

### Components

- **OpenShiftClient**: Executes `oc` commands, queries EIP and CPIC resources with caching
- **AzureClient**: Executes `az` commands, queries NIC statistics
- **EIPMonitor**: Main monitoring loop, collects and logs statistics with parallel processing
- **Cache**: TTL-based caching with LRU eviction
- **BufferedLogger**: Buffered file I/O
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

The monitoring command displays:
- Timestamp at the top of each iteration
- Per-node statistics: CPIC (success/pending/error), Primary EIPs, Secondary EIPs, Azure NIC stats
- Cluster summary: Configured EIPs, Successful CPICs, Assigned EIPs, Malfunction EIPs, Overcommitted EIPs, CNCC status
- Changed values highlighted in yellow/bold
- Output overwrites previous lines using ANSI escape codes (terminal only)
- After 10 iterations without progress:
  - EIP/CPIC mismatches
  - Unassigned EIPs
  - CPIC errors

Example output:
```
2025/11/04 17:55:22
aro-worker-node1 - CPIC: 32/0/0, Primary EIPs: 30, Secondary EIPs: 2, Azure: 32/32, Capacity: 223/255
aro-worker-node2 - CPIC: 33/0/0, Primary EIPs: 31, Secondary EIPs: 2, Azure: 33/33, Capacity: 222/255
Cluster Summary: Configured EIPs: 100, Successful CPICs: 100, Assigned EIPs: 100, Malfunction EIPs: 0, Overcommitted EIPs: 5, CNCC: 2/2, Total Capacity: 342/512
```

Note: Capacity values show available/total (e.g., "223/255" means 223 available out of 255 total capacity).

**Metrics:**
- **Primary EIPs**: First IP in `status.items` of each EIP resource assigned to the node. Each EIP resource contributes at most one Primary EIP.
- **Secondary EIPs**: Additional IPs from the same EIP resource. Calculated as `CPIC Success - Primary EIPs`.
- **Assigned EIPs**: Total assigned IPs (Primary + Secondary). Should match CPIC Success count.
- **Malfunction EIPs**: EIP resources where `status.items` don't match CPIC assignments. Red if > 0.
- **Overcommitted EIPs**: EIP resources with more IPs configured than available nodes. Yellow if > 0.

### Monitoring Logic

Monitoring loop continues while:
- `eipStats.Assigned != expectedAssignable` OR
- `cpicStats.Success != expectedAssignable`

Where `expectedAssignable = Configured - unassignableIPs` (accounting for overcommitted EIPs).

**Early Exit:**
- If all EIPs are already properly configured, the tool prints current state once and exits
- No directories, logs, or graphs are created when early exit occurs
- This allows quick status checks without generating files

**Overcommitment Handling:**
- EIP resources with more IPs than available nodes cannot assign all IPs
- Monitoring calculates unassignable IPs and exits when all assignable IPs are assigned

**Mismatch Detection:**
- Detected after 10 iterations without progress
- Overcommitted EIP resources excluded to avoid false positives
- Detailed IP lists shown after 10 iterations, hidden when progress detected

**Unassigned EIP Detection:**
- Detected after 10 iterations without progress
- Only shown if no mismatches detected (to avoid duplicate reporting)

### Logged Metrics

All logged metrics are automatically plotted. The following metrics are logged to files for tracking and plotting:

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

**Note:** All metrics listed above are automatically processed into `.dat` files and plotted as PNG charts when using the `plot` or `all` commands.

### Implementation Details

- Parallel node data collection using goroutines and semaphores
- Thread-safe caching with TTL and LRU eviction
- Concurrent-safe buffered file I/O
- Custom error types with error wrapping
- ANSI escape codes for in-place output overwriting (terminal-aware)
- Terminal detection for formatting adjustments
- Progress tracking for conditional warning display
- Mismatch detection between EIP and CPIC node assignments
- Overcommitment detection for EIP resources with more IPs than available nodes
- Early exit with state display when no monitoring needed
- Cross-platform support (Linux x86_64/ARM64, macOS Intel/Apple Silicon)

### Platform Support

The toolkit builds and runs on:
- **macOS**: Intel (x86_64) and Apple Silicon (ARM64)
- **Linux**: x86_64 and ARM64

All dependencies are pure Go with no CGO requirements, ensuring consistent behavior across platforms. External dependencies (`oc` and `az` CLI tools) must be installed separately for the target platform.
