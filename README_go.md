# EIP Toolkit - Go Implementation

Go implementation of the EIP monitoring toolkit for Azure Red Hat OpenShift.

## Installation

```bash
go mod download
go build -o eip-toolkit-ultra-simple eip_toolkit_ultra_simple.go
go build -o eip-toolkit-simple eip_toolkit_simple.go
```

Set environment variables:
```bash
export AZ_SUBSCRIPTION="your-subscription-id"
export AZ_RESOURCE_GROUP="your-resource-group"
```

## Usage

### Ultra Simple Version

```bash
./eip-toolkit-ultra-simple
```

Monitors EIP assignments and outputs to console. No dependencies required.

### Simple Version

```bash
# Monitor EIP and CPIC status
./eip-toolkit-simple monitor

# Merge log files into structured data
./eip-toolkit-simple merge <directory>

# Generate plots (placeholder - requires external tools)
./eip-toolkit-simple plot <directory>

# Complete pipeline
./eip-toolkit-simple all
```

## Architecture

### Ultra Simple Version

Single package with functions:
- `runOC()`: Execute oc commands
- `runAZ()`: Execute az commands
- `getEIPStats()`: Extract EIP statistics
- `getCPICStats()`: Extract CPIC statistics
- `getNodes()`: Get EIP-enabled nodes
- `getAzureNICStats()`: Get Azure NIC statistics
- `monitor()`: Main monitoring loop

### Simple Version

Uses cobra CLI framework:
- `monitorCmd()`: Monitoring with file logging
- `mergeLogsCmd()`: Process log files into data files
- `createPlotsCmd()`: Placeholder for plotting (requires external tools)

## Data Flow

### Monitor Command Flow
```
User
 │
 ├─> eip-toolkit-simple monitor
     │
     └─> monitorCmd()
         │
         ├─> runOCCommand(get eip)
         │   └─> Parse JSON → EIPStats
         │
         ├─> runOCCommand(get cloudprivateipconfig)
         │   └─> Parse JSON → CPICStats
         │
         └─> Write to log files (logs/*.log)
             └─> Repeat every 1 second until complete
```

### Merge Command Flow
```
User
 │
 ├─> eip-toolkit-simple merge <directory>
     │
     └─> mergeLogsCmd()
         │
         ├─> Read log files (logs/*.log)
         │
         ├─> Parse entries (timestamp, value)
         │
         ├─> Group by metric type and node
         │
         └─> Write structured data (data/*.dat)
```

## Differences from Python Version

- Uses `encoding/json` for JSON parsing
- Uses `os/exec` for command execution
- Uses `cobra` for CLI framework
- Plotting requires external tools (not implemented in Go)
- No async operations (uses standard goroutines if needed)

## Building

```bash
# Build ultra-simple version
go build -o eip-toolkit-ultra-simple eip_toolkit_ultra_simple.go

# Build simple version
go build -o eip-toolkit-simple eip_toolkit_simple.go
```

## Dependencies

- Go 1.21+
- `github.com/spf13/cobra` (for simple version only)

