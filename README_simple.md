# EIP Toolkit - Simple Version

Simplified version with core monitoring, logging, and visualization features.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements_simple.txt
```

Set environment variables:
```bash
export AZ_SUBSCRIPTION="your-subscription-id"
export AZ_RESOURCE_GROUP="your-resource-group"
```

## Usage

```bash
# Monitor EIP and CPIC status
python3 eip_toolkit_simple.py monitor

# Merge log files into structured data
python3 eip_toolkit_simple.py merge <directory>

# Generate plots from data files
python3 eip_toolkit_simple.py plot <directory>

# Complete pipeline
python3 eip_toolkit_simple.py all
```

## Architecture

### Components

- **EIPMonitor**: Single class containing all functionality
  - `run_oc_command()`: Execute OpenShift CLI commands
  - `run_az_command()`: Execute Azure CLI commands
  - `get_eip_stats()`: Extract EIP statistics from JSON
  - `get_cpic_stats()`: Extract CPIC statistics from JSON
  - `get_nodes()`: Get list of EIP-enabled nodes
  - `log_stats()`: Write timestamped statistics to log files
  - `monitor()`: Main monitoring loop
  - `merge_logs()`: Process log files into data files
  - `create_plots()`: Generate plots from data files

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
2. Parse node sections and data lines
3. Extract timestamps and values
4. Generate matplotlib plots
5. Save PNG files to `plots/` directory
