# EIP Toolkit - Simple Version (Go)

Simplified Go version with core monitoring, logging, and data processing features.

## Installation

```bash
go mod download
make build-simple
# Or manually:
go build -o eip-toolkit-simple eip_toolkit_simple.go
```

Set environment variables:
```bash
export AZ_SUBSCRIPTION="your-subscription-id"
export AZ_RESOURCE_GROUP="your-resource-group"
```

## Usage

```bash
# Monitor EIP and CPIC status
./eip-toolkit-simple monitor

# Merge log files into structured data
./eip-toolkit-simple merge <directory>

# Generate plots from data files (placeholder - requires external tools)
./eip-toolkit-simple plot <directory>

# Complete pipeline
./eip-toolkit-simple all
```

## Architecture

### Components

- **EIPMonitor**: Main struct with monitoring functionality
  - `runOCCommand()`: Execute OpenShift CLI commands
  - `runAZCommand()`: Execute Azure CLI commands
  - `getEIPStats()`: Extract EIP statistics from JSON
  - `getCPICStats()`: Extract CPIC statistics from JSON
  - `getNodes()`: Get list of EIP-enabled nodes
  - `logStats()`: Write timestamped statistics to log files
  - `runMonitor()`: Main monitoring loop
  - `runMergeLogs()`: Process log files into data files
  - `runCreatePlots()`: Placeholder for plotting (requires external tools)

### Data Flow

#### Monitor
1. Query OpenShift for EIP-enabled nodes
2. Loop until completion:
   - Query EIP and CPIC resources
   - Extract statistics
   - Write to log files (`logs/ocp_eips_*.log`, `logs/ocp_cpic_*.log`)
   - Check completion condition

#### Merge
1. Read log files from `logs/` directory
2. Identify node-specific files (format: `{node}_{metric}.log`)
3. Group by metric type
4. Write structured `.dat` files to `data/` directory

#### Plot
1. Read `.dat` files from `data/` directory
2. Placeholder - plotting requires external tools (gnuplot, matplotlib, etc.)
