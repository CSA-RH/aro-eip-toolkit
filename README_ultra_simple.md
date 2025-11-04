# EIP Toolkit - Ultra Simple Version (Go)

Minimal Go monitoring application with console output only. Single binary, no external dependencies.

## Installation

```bash
go mod download
make build-ultra-simple
# Or manually:
go build -o eip-toolkit-ultra-simple eip_toolkit_ultra_simple.go
```

Set environment variables:
```bash
export AZ_SUBSCRIPTION="your-subscription-id"
export AZ_RESOURCE_GROUP="your-resource-group"
```

## Usage

```bash
./eip-toolkit-ultra-simple
```

Output:
```
Starting EIP monitoring...
Found EIP-enabled nodes: [node1 node2 node3]
[14:30:15] EIPs: 3/5, CPIC: 2, Azure: node1:2/1, node2:1/0, node3:0/0
[14:30:16] EIPs: 4/5, CPIC: 3, Azure: node1:2/1, node2:2/1, node3:1/0
[14:30:17] EIPs: 5/5, CPIC: 5, Azure: node1:2/1, node2:2/1, node3:1/1
✅ All EIPs assigned and CPIC issues resolved!
```

## Architecture

### Functions

- `runOC(cmd)`: Execute OpenShift CLI command, return JSON
- `runAZ(cmd)`: Execute Azure CLI command, return JSON
- `getEIPStats()`: Query EIP resources, return (assigned, configured)
- `getCPICStats()`: Query CPIC resources, return success count
- `getNodes()`: Get EIP-enabled nodes via label selector
- `getAzureNICStats(node)`: Query Azure NIC, return (secondaryIPs, lbIPs)
- `monitor()`: Main loop

### Data Flow

1. Query OpenShift for EIP-enabled nodes
2. Loop until completion:
   - Query EIP resources: `oc get eip -o json`
   - Query CPIC resources: `oc get cloudprivateipconfig -o json`
   - For each node: query Azure NIC stats
   - Print formatted status line
   - Check: `assigned == configured` and `cpicSuccess == configured`
3. Exit when conditions met

No file I/O, all output to console. Single binary, no dependencies beyond Go standard library.
