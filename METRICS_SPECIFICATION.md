# EIP Monitoring Metrics Specification

This document provides a detailed specification of all metrics captured by the EIP Toolkit, including their calculation methods, data sources, and file formats. This specification can be used to implement the same metrics in other tools.

## Table of Contents

1. [Data Sources](#data-sources)
2. [Cluster-Level Metrics](#cluster-level-metrics)
3. [Per-Node Metrics](#per-node-metrics)
4. [Health Status Metrics](#health-status-metrics)
5. [Data File Formats](#data-file-formats)
6. [Calculation Algorithms](#calculation-algorithms)

---

## Data Sources

### OpenShift Resources

1. **EgressIP (EIP) Resources**
   - API: `oc get eip --all-namespaces -o json`
   - Key fields:
     - `spec.egressIPs[]`: Array of configured IP addresses
     - `status.items[]`: Array of assignment status items
       - Each item contains: `ip`, `node`, `status`
     - `metadata.name`: Resource name
     - `metadata.namespace`: Resource namespace

2. **CloudPrivateIPConfig (CPIC) Resources**
   - API: `oc get cloudprivateipconfig -o json`
   - Key fields:
     - `spec.node`: Node name assignment
     - `status.conditions[]`: Array of condition objects
       - Each condition has: `reason` (CloudResponseSuccess, CloudResponsePending, CloudResponseError)

3. **Node Resources**
   - API: `oc get node <node-name> -o json`
   - Key fields:
     - `metadata.annotations["cloud.network.openshift.io/egress-ipconfig"]`: JSON string containing capacity information
     - `metadata.labels["egress-assignable"]`: Label indicating if node can host EIPs

### Azure Resources

1. **Network Interface Cards (NICs)**
   - API: `az network nic show --resource-group <rg> --name <node-name>-nic --query "{ipConfigs:ipConfigurations}"`
   - Key fields:
     - `ipConfigurations[]`: Array of IP configurations
       - `privateIPAddress`: IP address
       - `loadBalancerBackendAddressPools[]`: Load balancer associations

---

## Cluster-Level Metrics

### EIP Statistics

#### 1. Configured EIPs (`ocp_eips_configured`)

**Description**: Total number of IP addresses configured across all EIP resources.

**Calculation**:
```
configured = 0
for each EIP resource:
    configured += len(spec.egressIPs)
```

**Data Source**: EIP resources (`spec.egressIPs`)

**File**: `ocp_eips_configured.log` → `ocp_eips_configured.dat`

**Format**: Single time series (cluster-level)

---

#### 2. Assigned EIPs (`ocp_eips_assigned`)

**Description**: Total number of IP addresses that have been assigned to nodes.

**Calculation**:
```
assigned = 0
for each EIP resource:
    if status.items exists:
        for each item in status.items:
            if item.node exists and item.node != nil:
                assigned++
```

**Data Source**: EIP resources (`status.items[]`)

**File**: `ocp_eips_assigned.log` → `ocp_eips_assigned.dat`

**Format**: Single time series (cluster-level)

---

#### 3. Unassigned EIPs (`ocp_eips_unassigned`)

**Description**: Total number of configured IP addresses that have not been assigned to any node.

**Calculation**:
```
unassigned = configured - assigned
```

**Data Source**: Derived from Configured and Assigned metrics

**File**: `ocp_eips_unassigned.log` → `ocp_eips_unassigned.dat`

**Format**: Single time series (cluster-level)

---

### CPIC Statistics

#### 4. CPIC Success (`ocp_cpic_success`)

**Description**: Total number of CPIC resources with `CloudResponseSuccess` condition.

**Calculation**:
```
success = 0
for each CPIC resource:
    if status.conditions exists:
        for each condition in status.conditions:
            if condition.reason == "CloudResponseSuccess":
                success++
```

**Data Source**: CPIC resources (`status.conditions[]`)

**File**: `ocp_cpic_success.log` → `ocp_cpic_success.dat`

**Format**: Single time series (cluster-level)

---

#### 5. CPIC Pending (`ocp_cpic_pending`)

**Description**: Total number of CPIC resources with `CloudResponsePending` condition.

**Calculation**:
```
pending = 0
for each CPIC resource:
    if status.conditions exists:
        for each condition in status.conditions:
            if condition.reason == "CloudResponsePending":
                pending++
```

**Data Source**: CPIC resources (`status.conditions[]`)

**File**: `ocp_cpic_pending.log` → `ocp_cpic_pending.dat`

**Format**: Single time series (cluster-level)

---

#### 6. CPIC Error (`ocp_cpic_error`)

**Description**: Total number of CPIC resources with `CloudResponseError` condition.

**Calculation**:
```
error = 0
for each CPIC resource:
    if status.conditions exists:
        for each condition in status.conditions:
            if condition.reason == "CloudResponseError":
                error++
```

**Data Source**: CPIC resources (`status.conditions[]`)

**File**: `ocp_cpic_error.log` → `ocp_cpic_error.dat`

**Format**: Single time series (cluster-level)

---

### Health Status Metrics

#### 7. Malfunctioning EIP Objects (`malfunctioning_eip_objects_count`)

**Description**: Number of EIP resources that have mismatches between their `status.items` and CPIC assignments.

**Calculation**:
```
1. Detect all EIP-CPIC mismatches (see Mismatch Detection Algorithm)
2. Collect unique EIP resource names that have mismatches
3. malfunctioning = count(unique resources with mismatches)
```

**Mismatch Detection**:
- An IP in `status.items` has a node assignment, but CPIC shows a different node (or no assignment)
- An IP in CPIC has a node assignment, but is missing from `status.items` (and resource is not at capacity)

**Data Source**: EIP resources + CPIC resources

**File**: `malfunctioning_eip_objects_count.log` → `malfunctioning_eip_objects_count.dat`

**Format**: Single time series (cluster-level)

---

#### 8. Overcommitted EIP Objects (`overcommitted_eip_objects_count`)

**Description**: Total number of overcommitted IPs across all EIP resources. An EIP resource is overcommitted if it has more configured IPs than available nodes.

**Calculation**:
```
availableNodes = count(nodes with label "egress-assignable")
overcommittedIPs = 0
for each EIP resource:
    configuredCount = len(spec.egressIPs)
    if configuredCount > availableNodes:
        overcommittedIPs += (configuredCount - availableNodes)
```

**Data Source**: EIP resources + Node labels

**File**: `overcommitted_eip_objects_count.log` → `overcommitted_eip_objects_count.dat`

**Format**: Single time series (cluster-level)

---

#### 9. Critical EIP Objects (`critical_eip_objects_count`)

**Description**: Number of EIP resources that have no working node assignments (all assignments are misaligned or missing).

**Calculation**:
```
1. Detect all EIP-CPIC mismatches
2. Build map of IPs with mismatches by resource
3. critical = 0
   for each EIP resource:
       if status.items is empty:
           critical++
       else:
           allIPsHaveMismatches = true
           for each item in status.items:
               if item has node assignment:
                   if item.ip not in mismatch map for this resource:
                       allIPsHaveMismatches = false
                       break
           if allIPsHaveMismatches:
               critical++
```

**Data Source**: EIP resources + CPIC resources

**File**: `critical_eip_objects_count.log` → `critical_eip_objects_count.dat`

**Format**: Single time series (cluster-level)

---

#### 10. EIP-CPIC Mismatches (`eip_cpic_mismatches_*`)

**Description**: Detailed breakdown of mismatches between EIP and CPIC.

**Sub-metrics**:
- `eip_cpic_mismatches_total`: Total count of all mismatches
- `eip_cpic_mismatches_node_mismatch`: IPs where EIP and CPIC show different node assignments
- `eip_cpic_mismatches_missing_in_eip`: IPs in CPIC but missing from EIP `status.items`

**Calculation**: See [Mismatch Detection Algorithm](#mismatch-detection-algorithm)

**Data Source**: EIP resources + CPIC resources

**Files**: 
- `eip_cpic_mismatches_total.log` → `eip_cpic_mismatches_total.dat`
- `eip_cpic_mismatches_node_mismatch.log` → `eip_cpic_mismatches_node_mismatch.dat`
- `eip_cpic_mismatches_missing_in_eip.log` → `eip_cpic_mismatches_missing_in_eip.dat`

**Format**: Single time series (cluster-level)

**Note**: These metrics are only logged after 10 iterations without progress to avoid duplicate reporting.

---

### Cluster Summary Metrics

#### 11. Total Primary EIPs (`cluster_summary_total_primary_eips`)

**Description**: Sum of all Primary EIPs across all nodes.

**Calculation**:
```
totalPrimary = 0
for each node:
    totalPrimary += node.primaryEIPs
```

**Data Source**: Per-node Primary EIP counts

**File**: `cluster_summary_total_primary_eips.log` → `cluster_summary_total_primary_eips.dat`

**Format**: Single time series (cluster-level)

---

#### 12. Total Secondary EIPs (`cluster_summary_total_secondary_eips`)

**Description**: Sum of all Secondary EIPs across all nodes.

**Calculation**:
```
totalSecondary = 0
for each node:
    totalSecondary += node.secondaryEIPs
```

**Data Source**: Per-node Secondary EIP counts

**File**: `cluster_summary_total_secondary_eips.log` → `cluster_summary_total_secondary_eips.dat`

**Format**: Single time series (cluster-level)

---

#### 13. Total Assigned EIPs (`cluster_summary_total_assigned_eips`)

**Description**: Sum of all assigned EIPs (Primary + Secondary) across all nodes.

**Calculation**:
```
totalAssigned = totalPrimary + totalSecondary
```

**Data Source**: Derived from Primary and Secondary totals

**File**: `cluster_summary_total_assigned_eips.log` → `cluster_summary_total_assigned_eips.dat`

**Format**: Single time series (cluster-level)

---

#### 14. Total Azure EIPs (`cluster_summary_total_azure_eips`)

**Description**: Sum of all Azure EIPs across all nodes.

**Calculation**:
```
totalAzureEIPs = 0
for each node:
    totalAzureEIPs += node.azureEIPs
```

**Data Source**: Per-node Azure EIP counts

**File**: `cluster_summary_total_azure_eips.log` → `cluster_summary_total_azure_eips.dat`

**Format**: Single time series (cluster-level)

---

#### 15. Node Count (`cluster_summary_node_count`)

**Description**: Total number of nodes with egress-assignable label.

**Calculation**:
```
nodeCount = count(nodes with label "egress-assignable")
```

**Data Source**: Node resources

**File**: `cluster_summary_node_count.log` → `cluster_summary_node_count.dat`

**Format**: Single time series (cluster-level)

---

#### 16. Average EIPs per Node (`cluster_summary_avg_eips_per_node`)

**Description**: Average number of assigned EIPs per node.

**Calculation**:
```
avgEIPsPerNode = totalAssigned / nodeCount
```

**Data Source**: Derived from Total Assigned and Node Count

**File**: `cluster_summary_avg_eips_per_node.log` → `cluster_summary_avg_eips_per_node.dat`

**Format**: Single time series (cluster-level)

---

## Per-Node Metrics

### CPIC Metrics (Per-Node)

#### 17. CPIC Success (`{node}_ocp_cpic_success`)

**Description**: Number of CPIC resources assigned to this node with `CloudResponseSuccess` condition.

**Calculation**:
```
cpicSuccess = 0
for each CPIC resource:
    if spec.node == nodeName:
        if status.conditions exists:
            for each condition in status.conditions:
                if condition.reason == "CloudResponseSuccess":
                    cpicSuccess++
```

**Data Source**: CPIC resources filtered by `spec.node`

**File**: `{node}_ocp_cpic_success.log` → `{node}_ocp_cpic_success.dat`

**Format**: Per-node time series

---

#### 18. CPIC Pending (`{node}_ocp_cpic_pending`)

**Description**: Number of CPIC resources assigned to this node with `CloudResponsePending` condition.

**Calculation**: Same as CPIC Success, but count `CloudResponsePending` conditions.

**Data Source**: CPIC resources filtered by `spec.node`

**File**: `{node}_ocp_cpic_pending.log` → `{node}_ocp_cpic_pending.dat`

**Format**: Per-node time series

---

#### 19. CPIC Error (`{node}_ocp_cpic_error`)

**Description**: Number of CPIC resources assigned to this node with `CloudResponseError` condition.

**Calculation**: Same as CPIC Success, but count `CloudResponseError` conditions.

**Data Source**: CPIC resources filtered by `spec.node`

**File**: `{node}_ocp_cpic_error.log` → `{node}_ocp_cpic_error.dat`

**Format**: Per-node time series

---

### EIP Metrics (Per-Node)

#### 20. Primary EIPs (`{node}_ocp_eip_primary`)

**Description**: Number of Primary EIPs assigned to this node. A Primary EIP is the first IP in `status.items` of each EIP resource.

**Calculation**:
```
primaryEIPs = 0

// Method 1: Count from EIP status.items
for each EIP resource:
    if status.items exists and len(status.items) > 0:
        firstItem = status.items[0]
        if firstItem.node == nodeName:
            primaryEIPs++

// Method 2: Count from CPIC for resources without status.items yet
// (If first configured IP is in CPIC assigned to this node but not in status.items)
for each EIP resource not already counted:
    firstConfiguredIP = spec.egressIPs[0]
    if firstConfiguredIP is in CPIC with spec.node == nodeName:
        if firstConfiguredIP has CloudResponseSuccess condition:
            primaryEIPs++
```

**Key Rule**: Each EIP resource contributes exactly ONE Primary EIP (the first IP).

**Data Source**: EIP resources (`status.items[0]`) + CPIC resources

**File**: `{node}_ocp_eip_primary.log` → `{node}_ocp_eip_primary.dat`

**Format**: Per-node time series

---

#### 21. Secondary EIPs (`{node}_ocp_eip_secondary`)

**Description**: Number of Secondary EIPs assigned to this node. Secondary EIPs are all IPs beyond the Primary EIP.

**Calculation**:
```
secondaryEIPs = max(0, cpicSuccess - primaryEIPs)
```

**Key Rule**: Secondary EIPs = CPIC Success - Primary EIPs

**Data Source**: Derived from CPIC Success and Primary EIPs

**File**: `{node}_ocp_eip_secondary.log` → `{node}_ocp_eip_secondary.dat`

**Format**: Per-node time series

---

#### 22. Total Assigned EIPs (`{node}_ocp_eip_assigned`)

**Description**: Total number of EIPs assigned to this node (Primary + Secondary).

**Calculation**:
```
assigned = primaryEIPs + secondaryEIPs
```

**Data Source**: Derived from Primary and Secondary EIPs

**File**: `{node}_ocp_eip_assigned.log` → `{node}_ocp_eip_assigned.dat`

**Format**: Per-node time series

---

### Azure Metrics (Per-Node)

#### 23. Azure EIPs (`{node}_azure_eips`)

**Description**: Number of secondary IP addresses on the Azure NIC (excluding the primary IP).

**Calculation**:
```
1. Get NIC data: az network nic show --name {node-name}-nic
2. ipConfigs = ipConfigurations array
3. totalIPs = len(ipConfigs)
4. azureEIPs = max(0, totalIPs - 1)  // Exclude primary IP
```

**Data Source**: Azure NIC (`ipConfigurations[]`)

**File**: `{node}_azure_eips.log` → `{node}_azure_eips.dat`

**Format**: Per-node time series

---

#### 24. Azure Load Balancers (`{node}_azure_lbs`)

**Description**: Number of IP configurations associated with load balancers (excluding the primary IP).

**Calculation**:
```
1. Get NIC data: az network nic show --name {node-name}-nic
2. lbAssociated = 0
   for each ipConfiguration:
       if loadBalancerBackendAddressPools exists and len > 0:
           lbAssociated++
3. azureLBs = max(0, lbAssociated - 1)  // Exclude primary IP
```

**Data Source**: Azure NIC (`ipConfigurations[].loadBalancerBackendAddressPools[]`)

**File**: `{node}_azure_lbs.log` → `{node}_azure_lbs.dat`

**Format**: Per-node time series

---

### Capacity Metrics (Per-Node)

#### 25. Node Capacity (`{node}_capacity_capacity`)

**Description**: Maximum number of IP addresses that can be assigned to this node (from subnet configuration).

**Calculation**:
```
1. Get node annotation: metadata.annotations["cloud.network.openshift.io/egress-ipconfig"]
2. Parse JSON array of configs
3. capacity = 0
   for each config:
       if ifaddr.ipv4 exists:
           // Parse CIDR (e.g., "10.0.2.0/23")
           subnetSize = calculateSubnetSize(ifaddr.ipv4)
           capacity += subnetSize
           break  // Use first interface's subnet
```

**Subnet Size Calculation**:
```
CIDR format: "a.b.c.d/mask"
maskBits = parseInt(mask)
hostBits = 32 - maskBits
subnetSize = 2^hostBits
```

**Example**: `10.0.2.0/23` → mask=23, hostBits=9, size=512 IPs

**Data Source**: Node annotation (`cloud.network.openshift.io/egress-ipconfig`)

**File**: `{node}_capacity_capacity.log` → `{node}_capacity_capacity.dat`

**Format**: Per-node time series

---

### Cluster Capacity

#### 26. Cluster Capacity

**Description**: Total IP capacity of the cluster (calculated from subnet CIDR).

**Calculation**: Same as Node Capacity, but calculated once from the first node's annotation (assuming all nodes share the same subnet).

**Data Source**: Node annotation (from first node)

**Note**: This is displayed in the summary but not logged to a separate file.

---

## Health Status Metrics

### Status Events

#### 27. Node Status Events (`status_event`)

**Description**: Timestamped events when node status changes (e.g., Ready → NotReady, SchedulingDisabled).

**Event Format**: `status_change:{fromState}:{toState}`

**Examples**:
- `status_change:Ready:NotReady`
- `status_change:NotReady:SchedulingDisabled`
- `status_change:SchedulingDisabled:Ready`

**Calculation**:
```
1. Get current node status from node resource
2. Compare with previous status
3. If status changed:
   log event: "status_change:{previousStatus}:{currentStatus}"
```

**Data Source**: Node resources (`status.conditions[]`)

**File**: `status_event.log` → `status_event.dat`

**Format**: Per-node event log with timestamps

---

## Data File Formats

### Log File Format (`.log`)

Log files contain timestamped metric values in space-separated format:

**Per-Node Format**:
```
"node-name"
2025-01-15T10:30:00Z 42
2025-01-15T10:31:00Z 43
2025-01-15T10:32:00Z 42

"another-node-name"
2025-01-15T10:30:00Z 15
2025-01-15T10:31:00Z 16
```

**Cluster-Level Format**:
```
2025-01-15T10:30:00Z 100
2025-01-15T10:31:00Z 101
2025-01-15T10:32:00Z 100
```

**Event Format** (`status_event.log`):
```
"node-name"
2025-01-15T10:30:00Z status_change:Ready:NotReady
2025-01-15T10:35:00Z status_change:NotReady:Ready
```

### Data File Format (`.dat`)

Data files are processed versions of log files, used for plotting:

**Per-Node Format**:
```
"node-name"
2025-01-15T10:30:00Z 42.0
2025-01-15T10:31:00Z 43.0
2025-01-15T10:32:00Z 42.0

"another-node-name"
2025-01-15T10:30:00Z 15.0
2025-01-15T10:31:00Z 16.0
```

**Cluster-Level Format**:
```
2025-01-15T10:30:00Z 100.0
2025-01-15T10:31:00Z 101.0
2025-01-15T10:32:00Z 100.0
```

**Event Format** (`status_event.dat`):
```
"node-name"
2025-01-15T10:30:00Z status_change:Ready:NotReady
2025-01-15T10:35:00Z status_change:NotReady:Ready
```

**Timestamp Formats Accepted**:
- RFC3339: `2025-01-15T10:30:00Z` or `2025-01-15T10:30:00+01:00`
- Compact: `250115_103000` (YYMMDD_HHMMSS)

---

## Calculation Algorithms

### Primary EIP Calculation (Detailed)

The Primary EIP count for a node is calculated as follows:

1. **From EIP status.items**:
   ```
   primaryEIPs = 0
   for each EIP resource:
       if status.items exists and len(status.items) > 0:
           firstItem = status.items[0]
           if firstItem.node == nodeName:
               primaryEIPs++
   ```

2. **From CPIC (for resources without status.items)**:
   ```
   // Build map of EIP resources that already have Primary EIP from status.items
   eipResourcesWithPrimaryEIP = {}
   for each EIP resource with status.items[0].node == nodeName:
       eipResourcesWithPrimaryEIP[resourceName] = true
   
   // Check CPIC for resources not yet counted
   for each EIP resource not in eipResourcesWithPrimaryEIP:
       firstConfiguredIP = spec.egressIPs[0]
       for each CPIC resource:
           if CPIC.spec.ip == firstConfiguredIP:
               if CPIC.spec.node == nodeName:
                   if CPIC has CloudResponseSuccess condition:
                       primaryEIPs++
                       break
   ```

**Key Points**:
- Each EIP resource contributes exactly ONE Primary EIP
- The Primary EIP is always the first IP in `spec.egressIPs`
- If the first IP is assigned to a node (in `status.items[0]` or in CPIC), it counts as a Primary EIP for that node

### Secondary EIP Calculation

Secondary EIPs are calculated as:

```
secondaryEIPs = max(0, cpicSuccess - primaryEIPs)
```

**Rationale**: 
- CPIC Success represents all IPs successfully assigned to the node
- Primary EIPs are the first IP from each EIP resource
- Remaining IPs (CPIC Success - Primary) are Secondary EIPs

### Mismatch Detection Algorithm

Mismatches between EIP and CPIC are detected as follows:

```
mismatches = []

// Build CPIC IP -> node mapping
cpicIPToNode = {}
for each CPIC resource:
    if spec.ip exists and spec.node exists:
        cpicIPToNode[spec.ip] = spec.node

// Build EIP IP -> node mapping from status.items
eipIPToNode = {}
eipIPToResource = {}
for each EIP resource:
    resourceName = namespace/name
    if status.items exists:
        for each item in status.items:
            if item.node exists:
                eipIPToNode[item.ip] = item.node
                eipIPToResource[item.ip] = resourceName

// Detect mismatches
for each IP in cpicIPToNode:
    cpicNode = cpicIPToNode[IP]
    eipNode = eipIPToNode[IP]
    
    if eipNode exists:
        if eipNode != cpicNode:
            // Node mismatch
            mismatches.append({
                type: "node_mismatch",
                ip: IP,
                eipNode: eipNode,
                cpicNode: cpicNode,
                resource: eipIPToResource[IP]
            })
    else:
        // IP in CPIC but not in EIP status.items
        // Check if resource is at capacity
        resource = findResourceForIP(IP)
        if resource not at capacity:
            mismatches.append({
                type: "missing_in_eip",
                ip: IP,
                cpicNode: cpicNode,
                resource: resource
            })

// Also check for IPs in EIP status.items but not in CPIC
for each IP in eipIPToNode:
    if IP not in cpicIPToNode:
        // IP in EIP but not in CPIC
        mismatches.append({
            type: "missing_in_cpic",
            ip: IP,
            eipNode: eipIPToNode[IP],
            resource: eipIPToResource[IP]
        })
```

**At Capacity Check**:
```
resource is at capacity if:
    assignedIPsCount >= availableNodeCount
where:
    assignedIPsCount = count of IPs in status.items with node assignments
    availableNodeCount = count of nodes with "egress-assignable" label
```

### Overcommitted Calculation

```
availableNodes = count(nodes with label "egress-assignable")
overcommittedIPs = 0

for each EIP resource:
    configuredCount = len(spec.egressIPs)
    if configuredCount > availableNodes:
        overcommittedIPs += (configuredCount - availableNodes)
```

**Rationale**: Each node can host at most one IP from each EIP resource. If a resource has more IPs configured than available nodes, the excess IPs cannot be assigned.

### Critical EIP Detection

An EIP resource is critical if:

1. **No assignments**: `status.items` is empty or has no items with node assignments
2. **All assignments misaligned**: All IPs in `status.items` have mismatches with CPIC

```
critical = 0
for each EIP resource:
    if status.items is empty or no items have node assignments:
        critical++
    else:
        allIPsHaveMismatches = true
        for each item in status.items:
            if item has node assignment:
                if item.ip not in mismatch map for this resource:
                    allIPsHaveMismatches = false
                    break
        if allIPsHaveMismatches:
            critical++
```

---

## Implementation Notes

### Performance Optimizations

1. **Data Fetching**: Fetch EIP and CPIC data once per iteration, then compute all metrics from cached data
2. **Caching**: Cache node capacity and status (5-minute TTL) as they change infrequently
3. **Parallel Processing**: Compute cluster-level and per-node metrics in parallel using goroutines

### Edge Cases

1. **Missing Status**: If `status.items` is missing or empty, the resource is not counted as assigned
2. **Nil Node Assignments**: Items in `status.items` without a `node` field are not counted as assigned
3. **Overcommitted Resources**: Overcommitted IPs are excluded from mismatch detection to avoid false positives
4. **Capacity Unknown**: If node capacity cannot be determined, it's shown as "?" in output

### Validation Rules

1. **Primary EIP Constraint**: Sum of Primary EIPs across all nodes should not exceed the number of unique EIP resources (with exceptions for multi-node assignments)
2. **CPIC-EIP Alignment**: In a healthy state, CPIC Success should equal Total Assigned EIPs
3. **Azure Alignment**: Azure EIPs should equal CPIC Success (when Azure cleanup is complete)

---

## Metric Relationships

### Key Relationships

1. **Assigned = Primary + Secondary**
   - `assigned = primaryEIPs + secondaryEIPs`
   - Applies to both per-node and cluster-level

2. **Secondary = CPIC Success - Primary**
   - `secondaryEIPs = cpicSuccess - primaryEIPs`
   - Applies to per-node metrics

3. **Unassigned = Configured - Assigned**
   - `unassigned = configured - assigned`
   - Applies to cluster-level metrics

4. **Expected Assignable = Configured - Overcommitted**
   - `expectedAssignable = configured - overcommittedIPs`
   - Used for monitoring completion criteria

### Health Indicators

- **Healthy State**:
  - CPIC Success = Total Assigned EIPs
  - Azure EIPs = CPIC Success (or 0 if cleanup pending)
  - Malfunctioning = 0
  - Critical = 0
  - Overcommitted = 0 (or known and accounted for)

- **Warning State**:
  - Malfunctioning > 0 (some mismatches detected)
  - Overcommitted > 0 (some resources overcommitted)

- **Critical State**:
  - Critical > 0 (some resources have no working assignments)
  - CPIC Error > 0 (some IPs failed to assign)

---

## File Naming Conventions

### Per-Node Files
- Pattern: `{node-name}_{metric-name}.log` → `{node-name}_{metric-name}.dat`
- Example: `worker-eastus1-sd681_ocp_eip_primary.log`

### Cluster-Level Files
- Pattern: `{metric-name}.log` → `{metric-name}.dat`
- Example: `ocp_eips_configured.log`

### Special Files
- `status_event.log` → `status_event.dat` (node status change events)
- `cluster_summary_*.log` → `cluster_summary_*.dat` (aggregated cluster metrics)

---

## API Endpoints Summary

### OpenShift API Calls

1. `oc get eip --all-namespaces -o json` - Get all EIP resources
2. `oc get cloudprivateipconfig -o json` - Get all CPIC resources
3. `oc get node <node-name> -o json` - Get node details
4. `oc get node -l egress-assignable -o json` - Get egress-assignable nodes

### Azure CLI Calls

1. `az network nic show --resource-group <rg> --name <node-name>-nic --query "{ipConfigs:ipConfigurations}"` - Get NIC IP configurations

---

## Revision History

- **v1.0** (2025-01-15): Initial specification document

---

## References

- OpenShift Egress IP Documentation
- CloudPrivateIPConfig API Reference
- Azure Network Interface Documentation

