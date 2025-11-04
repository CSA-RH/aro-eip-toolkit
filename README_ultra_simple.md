# EIP Toolkit - Ultra Simple Version

Minimal monitoring script with console output only. No dependencies required.

## Installation

```bash
# Optional: create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

Set environment variables:
```bash
export AZ_SUBSCRIPTION="your-subscription-id"
export AZ_RESOURCE_GROUP="your-resource-group"
```

## Usage

```bash
python3 eip_toolkit_ultra_simple.py
```

Output:
```
Starting EIP monitoring...
Found EIP-enabled nodes: ['node1', 'node2', 'node3']
[14:30:15] EIPs: 3/5, CPIC: 2, Azure: node1:2/1, node2:1/0, node3:0/0
[14:30:16] EIPs: 4/5, CPIC: 3, Azure: node1:2/1, node2:2/1, node3:1/0
[14:30:17] EIPs: 5/5, CPIC: 5, Azure: node1:2/1, node2:2/1, node3:1/1
✅ All EIPs assigned and CPIC issues resolved!
```

## Architecture

### Functions

- `run_oc(cmd)`: Execute OpenShift CLI command, return JSON
- `run_az(cmd)`: Execute Azure CLI command, return JSON
- `get_eip_stats()`: Query EIP resources, return (assigned, configured)
- `get_cpic_stats()`: Query CPIC resources, return success count
- `get_nodes()`: Get EIP-enabled nodes via label selector
- `get_azure_nic_stats(node)`: Query Azure NIC, return (secondary_ips, lb_ips)
- `monitor()`: Main loop

### Data Flow

1. Query OpenShift for EIP-enabled nodes
2. Loop until completion:
   - Query EIP resources: `oc get eip -o json`
   - Query CPIC resources: `oc get cloudprivateipconfig -o json`
   - For each node: query Azure NIC stats
   - Print formatted status line
   - Check: `assigned == configured` and `cpic_success == configured`
3. Exit when conditions met

No file I/O, all output to console.
