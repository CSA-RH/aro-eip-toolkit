# EIP Toolkit

A unified command-line tool for monitoring, analyzing, and visualizing Azure Red Hat OpenShift (ARO) Egress IP (EIP) assignments and CloudPrivateIPConfig (CPIC) status.

## 📋 Overview

The EIP Toolkit combines three essential functions into a single, easy-to-use script:

- **🔍 Monitoring**: Real-time EIP and CPIC status tracking
- **📊 Analysis**: Log merging and data processing
- **📈 Visualization**: Automatic graph generation

## 🛠️ Prerequisites

### Required Tools
- **OpenShift CLI (`oc`)** - Connected to your ARO cluster
- **Azure CLI (`az`)** - Authenticated to your Azure subscription
- **jq** - JSON processing tool
- **gnuplot** - Graph generation tool
- **bc** - Basic calculator for numerical operations
- **gdate** - GNU date (on macOS: `brew install coreutils`)

### Required Permissions
- **OpenShift**: Cluster-level permissions to access:
  - Nodes (`nodes`)
  - EgressIPs (`egressips`)
  - CloudPrivateIPConfigs (`cloudprivateipconfigs`)
- **Azure**: Read access to network interface cards in your resource group

## ⚙️ Setup

### 1. Environment Variables

Set the required environment variables:

```bash
# Azure Subscription ID
export AZ_SUBSCRIPTION=$(az account show --query id -o tsv)

# Azure Resource Group containing your ARO cluster
export AZ_RESOURCE_GROUP="your-aro-resource-group-name"

# Example:
export AZ_RESOURCE_GROUP="aro-jjohanss-rg-managed"
```

### 2. Make Script Executable

```bash
chmod +x eip-toolkit.sh
```

### 3. Verify Setup

```bash
./eip-toolkit.sh help
```

## 🚀 Usage

### Commands Overview

```bash
./eip-toolkit.sh <command> [options]
```

| Command | Short | Description |
|---------|-------|-------------|
| `all` | `-a` | Run complete pipeline: monitor → merge → plot |
| `monitor` | `-m` | Monitor EIP and CPIC status only |
| `merge` | `-g` | Merge log files into data files |
| `plot` | `-p` | Generate plots from data files |
| `help` | `-h` | Show help information |

### 1. Complete Pipeline (Recommended)

Run the entire workflow automatically:

```bash
./eip-toolkit.sh all
```

This will:
1. **Monitor** EIP assignments until completion
2. **Merge** the generated logs into data files  
3. **Plot** graphs from the merged data

### 2. Individual Commands

#### Monitor EIPs
```bash
./eip-toolkit.sh monitor
```
- Tracks EIP assignments in real-time
- Stops when all EIPs are properly assigned
- Creates timestamped logs in `../runs/YYMMDD_HHMMSS/logs/`

#### Merge Logs
```bash
./eip-toolkit.sh merge ../runs/241021_143022/
```
- Converts raw log files into plottable data format
- Input: Directory containing `.log` files
- Output: `.dat` files in `data/` subdirectory

#### Generate Plots
```bash
./eip-toolkit.sh plot ../runs/241021_143022/
```
- Creates time-series graphs from data files
- Input: Directory containing `.dat` files
- Output: PNG images in `plots/` subdirectory

## 📁 Output Structure

The toolkit creates organized output directories:

```
../runs/YYMMDD_HHMMSS/
├── logs/                    # 📝 Raw monitoring data
│   ├── ocp_eips_configured.log
│   ├── ocp_eips_assigned.log
│   ├── ocp_cpic_success.log
│   ├── node1_azure_eips.log
│   └── ... (per-node logs)
├── data/                    # 📊 Processed data files
│   ├── ocp_eip_assigned.dat
│   ├── ocp_cpic_success.dat
│   ├── azure_eips.dat
│   └── ... (merged data)
└── plots/                   # 📈 Generated visualizations
    ├── ocp_eip_assigned-plot.png
    ├── ocp_cpic_success-plot.png
    ├── azure_eips-plot.png
    └── ... (time-series graphs)
```

## 🎯 Common Workflows

### Full Monitoring Session
```bash
# Set up environment (one time)
export AZ_SUBSCRIPTION=$(az account show --query id -o tsv)
export AZ_RESOURCE_GROUP="aro-jjohanss-rg-managed"

# Run complete pipeline
./eip-toolkit.sh all

# Results will be in ../runs/YYMMDD_HHMMSS/
```

### Process Existing Logs
```bash
# If you have logs from a previous run
./eip-toolkit.sh merge ../runs/241021_143022/
./eip-toolkit.sh plot ../runs/241021_143022/
```

### Monitor Only (for continuous monitoring)
```bash
./eip-toolkit.sh monitor
# Use Ctrl+C to stop when needed
```

## 📊 Generated Graphs

The toolkit automatically creates normalized, readable graph titles:

| Data File | Graph Title |
|-----------|-------------|
| `ocp_eip_assigned.dat` | "OpenShift EIP Assigned" |
| `ocp_cpic_success.dat` | "OpenShift CPIC Success" |
| `azure_lbs.dat` | "Azure Load Balancers" |
| `azure_eips.dat` | "Azure EIPs" |

All graphs include:
- Time-series visualization
- Properly formatted timestamps
- Multiple data series (color-coded)
- High-resolution PNG output (1680x1050)

## ⚠️ Troubleshooting

### Permission Errors
```
Error: Cannot access OpenShift nodes
```
**Solution**: Ask your cluster administrator to grant you cluster-level permissions:
```bash
oc adm policy add-cluster-role-to-user cluster-admin your-username
```

### Environment Variable Errors
```
Error: AZ_SUBSCRIPTION environment variable not set
```
**Solution**: Set the required environment variables:
```bash
export AZ_SUBSCRIPTION=$(az account show --query id -o tsv)
export AZ_RESOURCE_GROUP="your-resource-group"
```

### No EIP Resources Found
```
Error: Cannot access EIP resources
```
**Possible causes**:
- EIP feature not installed/configured in your cluster
- Insufficient permissions to access EIP resources
- Connected to wrong cluster

### Azure CLI Issues
```
Error: Cannot access Azure resources
```
**Solution**: Ensure Azure CLI is properly authenticated:
```bash
az login
az account set --subscription "your-subscription-id"
```

## 🔧 Advanced Usage

### Persistent Environment Setup
Add to your shell profile (`~/.bashrc`, `~/.zshrc`):
```bash
export AZ_SUBSCRIPTION=$(az account show --query id -o tsv 2>/dev/null)
export AZ_RESOURCE_GROUP="aro-jjohanss-rg-managed"
```

### Custom Output Directory
The script uses `../runs/` by default. To change this, modify the `TEMP_DIR` variable in the script.

### Background Monitoring
For long-running monitoring sessions:
```bash
nohup ./eip-toolkit.sh monitor > monitor.out 2>&1 &
```

## 📈 Understanding the Data

### Key Metrics Tracked
- **EIPs Configured**: Total EIPs defined in OpenShift
- **EIPs Assigned**: EIPs successfully assigned to nodes  
- **EIPs Unassigned**: EIPs waiting for assignment
- **CPIC Success**: CloudPrivateIPConfigs with successful Azure responses
- **CPIC Pending**: CloudPrivateIPConfigs waiting for Azure responses
- **CPIC Error**: CloudPrivateIPConfigs with Azure errors
- **Azure EIPs**: Secondary IP addresses configured on Azure NICs
- **Azure Load Balancers**: IPs associated with load balancer pools

### Monitoring Loop
The monitoring continues until:
- All configured EIPs are assigned (`EIPs_ASSIGNED == EIPs_CONFIGURED`)
- All CPICs have successful responses (`CPIC_SUCCESS == EIPs_CONFIGURED`)

## 🤝 Contributing

Feel free to submit issues and enhancement requests!

## 📝 License

This project is provided as-is for ARO EIP monitoring and analysis.
