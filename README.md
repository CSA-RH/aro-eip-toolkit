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

# Process log files into structured data
./eip-toolkit merge <directory>

# Generate plots from data files
./eip-toolkit plot <directory>

# Complete pipeline: monitor → merge → plot
./eip-toolkit all

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

You can specify a custom output directory using the `--output-dir` flag (if supported) or by setting the `outputDirVar` variable in the code.

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
         ├─> CollectNodeDataParallel() (goroutines)
         │   ├─> AzureClient.GetNodeNICStats()
         │   │   └─> az network nic show
         │   │       └─> Parse JSON → (ips, lbs)
         │   └─> BufferedLogger.LogStats()
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
- **Node Statistics**: Per-node CPIC (success/pending/error), EIP assigned, and Azure NIC stats
- **Summary Stats**: Single-line summary showing Configured EIPs, Successful CPICs, and Assigned EIPs
- **Value Highlighting**: Values that change between iterations are highlighted in yellow/bold
- **In-place Updates**: Console output overwrites previous lines using ANSI escape codes (when output is to a terminal)

Example output:
```
2025/11/04 17:55:22
aro-worker-node1 - CPIC: 32/0/0, EIP: 32, Azure: 32/32
aro-worker-node2 - CPIC: 33/0/0, EIP: 33, Azure: 33/33
Configured EIPs: 100, Successful CPICs: 100, Assigned EIPs: 100
```

### Monitoring Logic

Monitoring loop continues while:
- `eipStats.Assigned != eipStats.Configured` OR
- `cpicStats.Success != eipStats.Configured`

Exits when both conditions are false (all EIPs assigned, all CPICs successful).

### Go-Specific Features

- **Goroutines**: Parallel node data collection using goroutines and semaphores
- **SmartCache**: Thread-safe caching with TTL and LRU eviction
- **BufferedLogger**: Concurrent-safe buffered file I/O
- **Error Handling**: Custom error types with proper error wrapping
- **Real-time Console Updates**: ANSI escape codes for in-place output overwriting (terminal-aware)
- **Value Change Highlighting**: Visual feedback for metrics that change between iterations
- **Terminal Detection**: Automatically detects if output is to a terminal and adjusts formatting accordingly
