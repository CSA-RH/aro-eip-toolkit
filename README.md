# EIP Toolkit

Monitors Azure Red Hat OpenShift Egress IP assignments and CloudPrivateIPConfig status.

## Installation

### Using Pre-built Binaries (Recommended)

Download the pre-built binary for your platform from the [GitHub Releases](https://github.com/CSA-RH/aro-eip-toolkit/releases):

**macOS (Apple Silicon):**
```bash
curl -L -o eip-toolkit https://github.com/CSA-RH/aro-eip-toolkit/releases/download/v0.2.0/eip-toolkit-darwin-arm64
chmod +x eip-toolkit
```

**Linux (x86_64):**
```bash
curl -L -o eip-toolkit https://github.com/CSA-RH/aro-eip-toolkit/releases/download/v0.2.0/eip-toolkit-linux-amd64
chmod +x eip-toolkit
```

**Windows (x86_64):**
```powershell
# Using PowerShell
Invoke-WebRequest -Uri "https://github.com/CSA-RH/aro-eip-toolkit/releases/download/v0.2.0/eip-toolkit-windows-amd64.exe" -OutFile "eip-toolkit.exe"
```

Or using curl (if available):
```cmd
curl -L -o eip-toolkit.exe https://github.com/CSA-RH/aro-eip-toolkit/releases/download/v0.2.0/eip-toolkit-windows-amd64.exe
```

Then set environment variables:

**Linux/macOS:**
```bash
export AZ_SUBSCRIPTION="your-subscription-id"
export AZ_RESOURCE_GROUP="your-resource-group"
```

**Windows (PowerShell):**
```powershell
$env:AZ_SUBSCRIPTION="your-subscription-id"
$env:AZ_RESOURCE_GROUP="your-resource-group"
```

**Windows (CMD):**
```cmd
set AZ_SUBSCRIPTION=your-subscription-id
set AZ_RESOURCE_GROUP=your-resource-group
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
make build-windows-amd64   # Windows x86_64
make build-windows-arm64   # Windows ARM64

# Or manually for Windows:
GOOS=windows GOARCH=amd64 go build -o eip-toolkit.exe eip_toolkit.go
```

Set environment variables (see Installation section above for platform-specific syntax).

## Usage

### Commands

**Linux/macOS:**
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

**Windows:**
```powershell
# Monitor EIP and CPIC status
.\eip-toolkit.exe monitor

# Monitor with custom output directory
.\eip-toolkit.exe monitor --output-dir C:\path\to\output
.\eip-toolkit.exe monitor -o C:\path\to\output

# Process log files into structured data
.\eip-toolkit.exe merge <directory>

# Generate plots from data files
.\eip-toolkit.exe plot <directory>

# Complete pipeline: monitor → merge → plot
.\eip-toolkit.exe all

# Complete pipeline with custom output directory
.\eip-toolkit.exe all --output-dir C:\path\to\output

# Async monitoring (parallel processing via goroutines)
.\eip-toolkit.exe monitor-async

# Optimized merge
.\eip-toolkit.exe merge-optimized <directory>

# Optimized pipeline
.\eip-toolkit.exe all-optimized
```

**Early Exit Behavior:**
- If all EIPs are already properly configured, the tool will:
  - Print the current state once
  - Exit without creating directories, logs, or graphs
  - This allows quick status checks without generating files

### Shell Completion

The toolkit supports shell completion for improved usability:

**Bash (Linux/macOS):**
```bash
# For current session
source <(eip-toolkit completion bash)

# For permanent installation (bash)
eip-toolkit completion bash > $(brew --prefix)/etc/bash_completion.d/eip-toolkit  # macOS
# or
eip-toolkit completion bash > /etc/bash_completion.d/eip-toolkit  # Linux
```

**Zsh (Linux/macOS):**
```bash
# First, ensure zsh completion system is initialized
autoload -Uz compinit && compinit

# For current session
source <(eip-toolkit completion zsh)

# For permanent installation (zsh)
# Option 1: Using custom completion directory (recommended)
mkdir -p ~/.zsh/completion
eip-toolkit completion zsh > ~/.zsh/completion/_eip-toolkit
# Then add to ~/.zshrc:
# fpath=(~/.zsh/completion $fpath)
# autoload -Uz compinit && compinit

# Option 2: Direct to fpath directory (if fpath is already set)
eip-toolkit completion zsh > "${fpath[1]}/_eip-toolkit"
# Then reload completions:
rm -f ~/.zcompdump* && compinit
```

**PowerShell (Windows):**
```powershell
# Generate completion script
.\eip-toolkit.exe completion powershell | Out-String | Invoke-Expression

# For permanent installation, add to your PowerShell profile:
.\eip-toolkit.exe completion powershell >> $PROFILE
```

**Fish:**
```bash
eip-toolkit completion fish > ~/.config/fish/completions/eip-toolkit.fish
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
         │   ├─> OpenShiftClient.GetNodeStatsFromData()
         │   │   ├─> Calculate Primary EIPs (first IP from each EIP resource)
         │   │   └─> Calculate Secondary EIPs (CPIC Success - Primary)
         │   ├─> AzureClient.GetNodeNICStats()
         │   │   └─> az network nic show
         │   │       └─> Parse JSON → (ips, lbs)
         │   ├─> AzureClient.GetNodeNICIPs()
         │   │   └─> az network nic show
         │   │       └─> Get actual IP addresses list
         │   ├─> DetectCPICAzureDiscrepancy()
         │   │   └─> Compare CPIC Success IPs vs Azure NIC IPs
         │   └─> BufferedLogger.LogStats()
         │       ├─> Log primary/secondary/assigned EIPs per node
         │       ├─> Log malfunctioning EIP count
         │       └─> Log overcommitted EIP count
         │
         ├─> (After 10 iterations without progress)
         │   ├─> DetectEIPCPICMismatches() (if not already done)
         │   ├─> Display CPIC/Azure discrepancies (per-node)
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
- Per-node statistics: CPIC (success/pending/error), Assigned EIP (primary/secondary), Azure NIC stats
- Cluster summary: Configured EIPs, Successful CPICs, Assigned EIP (primary/secondary), Malfunction EIPs, Overcommitted EIPs, CNCC status
- Changed values highlighted in yellow/bold
- Output overwrites previous lines using ANSI escape codes (terminal only)
- After 10 iterations without progress:
  - EIP/CPIC mismatches
  - CPIC/Azure discrepancies (when CPIC Success, Total Assigned EIPs, and Azure IPs don't match)
  - Unassigned EIPs
  - CPIC errors

Example output:
```
2025/11/04 17:55:22
aro-worker-node1 - CPIC: 32/0/0, Assigned EIP: 30/2, Azure: 32/0, Capacity: 223/255
aro-worker-node2 - CPIC: 33/0/0, Assigned EIP: 31/2, Azure: 33/0, Capacity: 222/255
Cluster Summary: Configured EIPs: 100, Requested EIPs: 100, Successful CPICs: 100, Assigned EIP: 61/4, Malfunction EIPs: 0, Overcommitted EIPs: 5, CNCC: 2/2, Total Capacity: 342/512
```

Example with CPIC/Azure discrepancy:
```
2025/11/04 17:55:22
aro-worker-node1 - CPIC: 120/0/0, Assigned EIP: 79/41, Azure: 85/0, Capacity: 135/255
⚠️  CPIC/Azure Discrepancy: CPIC Success (120) > Azure IPs (85), 35 IPs missing in Azure
   Missing in Azure (10 shown of 35):
   - 10.0.2.45 (namespace1/eip-resource-1)
   - 10.0.2.46 (namespace1/eip-resource-1)
   - 10.0.2.47 (namespace2/eip-resource-2)
   ...
```

Note: Capacity values show available/total (e.g., "223/255" means 223 available out of 255 total capacity).

**Metrics:**
- **Primary EIPs**: First IP in `status.items` of each EIP resource assigned to the node. Each EIP resource contributes at most one Primary EIP.
- **Secondary EIPs**: Additional IPs from the same EIP resource. Calculated as `CPIC Success - Primary EIPs`.
- **Assigned EIP**: Displayed as "x/y" where x is Primary EIPs and y is Secondary EIPs. Total (x+y) should match CPIC Success count.
- **Azure IPs**: Actual secondary IPs configured on the Azure NIC. Should match CPIC Success and Total Assigned EIPs.
- **Malfunction EIPs**: EIP resources where `status.items` don't match CPIC assignments. Red if > 0.
- **Overcommitted EIPs**: EIP resources with more IPs configured than available nodes. Yellow if > 0.

**Expected Relationships:**
- CPIC Success = Total Assigned EIPs (Primary + Secondary) = Azure IPs
- When these values don't match, a discrepancy is detected and reported
- Azure IPs are the source of truth - if CPIC Success > Azure IPs, some IPs are reported as successful in CPIC but not actually on the Azure NIC

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

**CPIC/Azure Discrepancy Detection:**
- Detects when CPIC Success, Total Assigned EIPs, and Azure IPs don't match
- Azure is the source of truth - discrepancies indicate CPIC reporting IPs that aren't actually on the Azure NIC
- Detected per-node and displayed when:
  - Discrepancy detected (values don't match)
  - AND no progress detected for 10 iterations (same condition as yellow highlighting)
- Shows detailed information:
  - Which IPs are in CPIC Success but not on Azure NIC (with EIP resource names if available)
  - Which IPs are on Azure NIC but not in CPIC Success
  - Discrepancy count and message
- Node output highlighted in yellow when discrepancy detected and no progress for 10 iterations

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
- CPIC/Azure discrepancy detection to identify IPs reported in CPIC but not on Azure NIC
- Overcommitment detection for EIP resources with more IPs than available nodes
- Early exit with state display when no monitoring needed
- Optimized API calls: EIP and CPIC data fetched once per iteration and reused for all nodes
- Cross-platform support (Linux x86_64/ARM64, macOS Intel/Apple Silicon, Windows x86_64/ARM64)

### Platform Support

The toolkit builds and runs on:
- **macOS**: Intel (x86_64) and Apple Silicon (ARM64)
- **Linux**: x86_64 and ARM64
- **Windows**: x86_64 and ARM64

All dependencies are pure Go with no CGO requirements, ensuring consistent behavior across platforms. External dependencies (`oc` and `az` CLI tools) must be installed separately for the target platform.

**Windows Notes:**
- Requires Windows 10/11 or Windows Server 2016+
- PowerShell completion is supported natively
- Works best with Windows Terminal or modern PowerShell (for ANSI color support)
- Ensure `oc` and `az` CLI tools are installed and available in PATH
