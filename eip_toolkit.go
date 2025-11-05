package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"image/color"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/vg"
)

// EIPToolkitError represents toolkit-specific errors
type EIPToolkitError struct {
	Message string
}

func (e *EIPToolkitError) Error() string {
	return e.Message
}

// Stats types
type EIPStats struct {
	Configured int
	Assigned   int
	Unassigned int
}

type CPICStats struct {
	Success int
	Pending int
	Error   int
}

type NodeStats struct {
	CPICSuccess   int
	CPICPending   int
	CPICError     int
	EIPAssigned   int // Primary EIPs (first IP from each EIP resource on this node)
	SecondaryEIPs int // Secondary EIPs (remaining IPs: CPIC Success - Primary)
	AzureEIPs     int
	AzureLBs      int
}

// SmartCache provides intelligent caching with TTL and LRU eviction
type SmartCache struct {
	mu          sync.RWMutex
	defaultTTL  time.Duration
	maxSize     int
	cache       map[string]cacheEntry
	accessTimes map[string]time.Time
}

type cacheEntry struct {
	data      interface{}
	timestamp time.Time
	ttl       time.Duration
}

func NewSmartCache(defaultTTL time.Duration, maxSize int) *SmartCache {
	return &SmartCache{
		defaultTTL:  defaultTTL,
		maxSize:     maxSize,
		cache:       make(map[string]cacheEntry),
		accessTimes: make(map[string]time.Time),
	}
}

func (c *SmartCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	entry, exists := c.cache[key]
	if !exists {
		c.mu.RUnlock()
		return nil, false
	}

	now := time.Now()
	isExpired := now.Sub(entry.timestamp) > entry.ttl
	c.mu.RUnlock()

	if isExpired {
		c.mu.Lock()
		delete(c.cache, key)
		delete(c.accessTimes, key)
		c.mu.Unlock()
		return nil, false
	}

	// Update access time with write lock
	c.mu.Lock()
	c.accessTimes[key] = now
	c.mu.Unlock()
	return entry.data, true
}

func (c *SmartCache) Set(key string, data interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.cache) >= c.maxSize {
		c.evictLRU()
	}

	if ttl == 0 {
		ttl = c.defaultTTL
	}

	c.cache[key] = cacheEntry{
		data:      data,
		timestamp: time.Now(),
		ttl:       ttl,
	}
	c.accessTimes[key] = time.Now()
}

func (c *SmartCache) evictLRU() {
	if len(c.accessTimes) == 0 {
		return
	}

	var lruKey string
	var lruTime time.Time
	first := true

	for key, t := range c.accessTimes {
		if first || t.Before(lruTime) {
			lruKey = key
			lruTime = t
			first = false
		}
	}

	delete(c.cache, lruKey)
	delete(c.accessTimes, lruKey)
}

// BufferedLogger provides buffered file I/O
type BufferedLogger struct {
	mu         sync.Mutex
	logsDir    string
	buffers    map[string][]string
	bufferSize int
}

func NewBufferedLogger(logsDir string, bufferSize int) *BufferedLogger {
	return &BufferedLogger{
		logsDir:    logsDir,
		buffers:    make(map[string][]string),
		bufferSize: bufferSize,
	}
}

func (bl *BufferedLogger) LogStats(timestamp, statsType string, stats map[string]interface{}) error {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	for statName, value := range stats {
		key := fmt.Sprintf("%s_%s", statsType, statName)
		if bl.buffers[key] == nil {
			bl.buffers[key] = make([]string, 0, bl.bufferSize)
		}

		line := fmt.Sprintf("%s %v\n", timestamp, value)
		bl.buffers[key] = append(bl.buffers[key], line)

		if len(bl.buffers[key]) >= bl.bufferSize {
			if err := bl.flushBuffer(key); err != nil {
				return err
			}
		}
	}

	return nil
}

func (bl *BufferedLogger) flushBuffer(key string) error {
	lines := bl.buffers[key]
	if len(lines) == 0 {
		return nil
	}

	logFile := filepath.Join(bl.logsDir, fmt.Sprintf("%s.log", key))
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, line := range lines {
		if _, err := f.WriteString(line); err != nil {
			return err
		}
	}

	bl.buffers[key] = bl.buffers[key][:0]
	return nil
}

func (bl *BufferedLogger) FlushAll() error {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	for key := range bl.buffers {
		if err := bl.flushBuffer(key); err != nil {
			return err
		}
	}

	return nil
}

// OpenShiftClient handles OpenShift CLI operations with caching
type OpenShiftClient struct {
	cache *SmartCache
}

func NewOpenShiftClient() *OpenShiftClient {
	return &OpenShiftClient{
		cache: NewSmartCache(5*time.Second, 1000),
	}
}

func (oc *OpenShiftClient) RunCommand(cmd []string) (map[string]interface{}, error) {
	cacheKey := strings.Join(cmd, " ")

	if data, found := oc.cache.Get(cacheKey); found {
		return data.(map[string]interface{}), nil
	}

	cmdObj := exec.Command("oc", cmd...)
	output, err := cmdObj.Output()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("OpenShift command failed: %s", string(exitError.Stderr))
		}
		return nil, fmt.Errorf("OpenShift command failed: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	oc.cache.Set(cacheKey, result, 5*time.Second)
	return result, nil
}

func (oc *OpenShiftClient) GetEIPEnabledNodes() ([]string, error) {
	cmd := exec.Command("oc", "get", "nodes", "-l", "k8s.ovn.org/egress-assignable=true", "-o", "name")
	output, err := cmd.Output()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return nil, &EIPToolkitError{Message: fmt.Sprintf("Cannot access OpenShift nodes: %s", string(exitError.Stderr))}
		}
		return nil, fmt.Errorf("cannot access OpenShift nodes: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	nodes := make([]string, 0, len(lines))

	for _, line := range lines {
		if line == "" {
			continue
		}
		nodeName := strings.TrimPrefix(line, "node/")
		if nodeName != "" {
			nodes = append(nodes, nodeName)
		}
	}

	if len(nodes) == 0 {
		return nil, &EIPToolkitError{Message: "No EIP-enabled nodes found"}
	}

	return nodes, nil
}

func (oc *OpenShiftClient) GetEIPStats() (*EIPStats, error) {
	data, err := oc.RunCommand([]string{"get", "eip", "--all-namespaces", "-o", "json"})
	if err != nil {
		return nil, err
	}

	items, ok := data["items"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid items format")
	}

	// Count configured EIPs: sum up the number of IPs in spec.egressIPs for each EIP resource
	// Each EIP resource can have multiple IPs configured (e.g., 2 IPs per namespace)
	configured := 0
	assigned := 0
	unassigned := 0

	for _, item := range items {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		// Count IPs in spec.egressIPs (each EIP resource can have multiple IPs)
		spec, ok := itemMap["spec"].(map[string]interface{})
		if ok {
			if egressIPs, ok := spec["egressIPs"].([]interface{}); ok {
				configured += len(egressIPs)
			}
		}

		// Count assigned IPs from status.items (only count items with node assigned)
		status, ok := itemMap["status"].(map[string]interface{})
		if !ok {
			continue
		}

		statusItems, ok := status["items"].([]interface{})
		if ok {
			// Only count items that have a node assigned (actually assigned)
			for _, statusItem := range statusItems {
				statusItemMap, ok := statusItem.(map[string]interface{})
				if !ok {
					continue
				}
				nodeValue, hasNode := statusItemMap["node"]
				if hasNode && nodeValue != nil {
					assigned++
				}
			}
		}
	}

	unassigned = configured - assigned

	return &EIPStats{
		Configured: configured,
		Assigned:   assigned,
		Unassigned: unassigned,
	}, nil
}

func (oc *OpenShiftClient) GetCPICStats() (*CPICStats, error) {
	data, err := oc.RunCommand([]string{"get", "cloudprivateipconfig", "--all-namespaces", "-o", "json"})
	if err != nil {
		return nil, err
	}

	items, ok := data["items"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid items format")
	}

	success := 0
	pending := 0
	errorCount := 0

	for _, item := range items {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		status, ok := itemMap["status"].(map[string]interface{})
		if !ok {
			continue
		}

		conditions, ok := status["conditions"].([]interface{})
		if !ok {
			continue
		}

		for _, cond := range conditions {
			condMap, ok := cond.(map[string]interface{})
			if !ok {
				continue
			}

			reason, ok := condMap["reason"].(string)
			if !ok {
				continue
			}

			switch reason {
			case "CloudResponseSuccess":
				success++
			case "CloudResponsePending":
				pending++
			case "CloudResponseError":
				errorCount++
			}
		}
	}

	return &CPICStats{
		Success: success,
		Pending: pending,
		Error:   errorCount,
	}, nil
}

type CNCCStats struct {
	PodsRunning int
	PodsReady   int
	PodsTotal   int
	QueueDepth  int // Work queue depth (if available via metrics)
}

func (oc *OpenShiftClient) GetCNCCStats() (*CNCCStats, error) {
	// Get CNCC pods status
	podData, err := oc.RunCommand([]string{"get", "pods", "-n", "openshift-cloud-network-config-controller", "-o", "json"})
	if err != nil {
		return nil, fmt.Errorf("failed to get CNCC pods: %w", err)
	}

	items, ok := podData["items"].([]interface{})
	if !ok {
		return &CNCCStats{}, nil
	}

	running := 0
	ready := 0
	total := len(items)

	for _, item := range items {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		status, ok := itemMap["status"].(map[string]interface{})
		if !ok {
			continue
		}

		phase, _ := status["phase"].(string)
		if phase == "Running" {
			running++
		}

		// Check if all containers are ready
		conditions, ok := status["conditions"].([]interface{})
		if ok {
			allReady := true
			for _, cond := range conditions {
				condMap, ok := cond.(map[string]interface{})
				if !ok {
					continue
				}
				typeStr, _ := condMap["type"].(string)
				statusStr, _ := condMap["status"].(string)
				if typeStr == "Ready" && statusStr != "True" {
					allReady = false
					break
				}
			}
			if allReady && phase == "Running" {
				ready++
			}
		}
	}

	// Try to get work queue depth from CNCC metrics (if available)
	// This checks if CNCC exposes metrics endpoint with workqueue_depth metric
	queueDepth := 0
	// Note: Queue depth would typically come from Prometheus metrics
	// For now, we'll check if we can infer from pod status or use a placeholder
	// In a full implementation, you'd query the metrics endpoint: /metrics on CNCC pod

	return &CNCCStats{
		PodsRunning: running,
		PodsReady:   ready,
		PodsTotal:   total,
		QueueDepth:  queueDepth,
	}, nil
}

func (oc *OpenShiftClient) GetNodeCapacity(nodeName string) (int, error) {
	// Get node annotations to check IP capacity (it's in annotations, not labels)
	nodeData, err := oc.RunCommand([]string{"get", "node", nodeName, "-o", "json"})
	if err != nil {
		return 0, err
	}

	metadata, ok := nodeData["metadata"].(map[string]interface{})
	if !ok {
		return 0, fmt.Errorf("invalid metadata format")
	}

	// Get egress IP config from annotations
	annotations, ok := metadata["annotations"].(map[string]interface{})
	if !ok {
		return 0, nil // No annotations, return 0 (unknown capacity)
	}

	egressIPConfig, ok := annotations["cloud.network.openshift.io/egress-ipconfig"].(string)
	if !ok || egressIPConfig == "" {
		return 0, nil // No egress IP config annotation
	}

	// Parse the annotation/label JSON to extract capacity
	// The value is a JSON string like: [{"interface":"...","ifaddr":{"ipv4":"10.0.2.0/23"},"capacity":{"ip":255}}]
	var configs []map[string]interface{}
	if err := json.Unmarshal([]byte(egressIPConfig), &configs); err != nil {
		return 0, nil // Failed to parse, return 0
	}

	// Sum up all capacities from all interfaces
	totalCapacity := 0
	for _, config := range configs {
		capacity, ok := config["capacity"].(map[string]interface{})
		if !ok {
			continue
		}
		ip, ok := capacity["ip"].(float64)
		if ok {
			totalCapacity += int(ip)
		}
	}

	return totalCapacity, nil
}

func (oc *OpenShiftClient) GetNodeStatus(nodeName string) (NodeStatus, error) {
	// Get node to check status
	nodeData, err := oc.RunCommand([]string{"get", "node", nodeName, "-o", "json"})
	if err != nil {
		return NodeStatusUnknown, err
	}

	// Check for unschedulable taint (SchedulingDisabled)
	spec, ok := nodeData["spec"].(map[string]interface{})
	if ok {
		unschedulable, ok := spec["unschedulable"].(bool)
		if ok && unschedulable {
			return NodeStatusSchedulingDisabled, nil
		}
	}

	// Check Ready condition
	status, ok := nodeData["status"].(map[string]interface{})
	if !ok {
		return NodeStatusUnknown, nil
	}

	conditions, ok := status["conditions"].([]interface{})
	if !ok {
		return NodeStatusUnknown, nil
	}

	for _, cond := range conditions {
		condMap, ok := cond.(map[string]interface{})
		if !ok {
			continue
		}

		typeStr, _ := condMap["type"].(string)
		if typeStr == "Ready" {
			statusStr, _ := condMap["status"].(string)
			if statusStr == "True" {
				return NodeStatusReady, nil
			} else {
				return NodeStatusNotReady, nil
			}
		}
	}

	// If no Ready condition found, check if node is marked as unschedulable
	// This could also mean the node is not ready
	return NodeStatusNotReady, nil
}

// GetIPToNodeMapping builds a mapping of IP addresses to assigned nodes from CPIC objects
// This is more accurate than relying on EIP status.items which may be incomplete
func (oc *OpenShiftClient) GetIPToNodeMapping() (map[string]string, error) {
	cpicData, err := oc.RunCommand([]string{"get", "cloudprivateipconfig", "--all-namespaces", "-o", "json"})
	if err != nil {
		return nil, err
	}

	ipToNode := make(map[string]string)
	items, ok := cpicData["items"].([]interface{})
	if !ok {
		return ipToNode, nil
	}

	for _, item := range items {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		// Get IP address - try spec.ip first, fall back to resource name
		var ipStr string
		spec, ok := itemMap["spec"].(map[string]interface{})
		if ok {
			ipValue, ok := spec["ip"]
			if ok {
				switch v := ipValue.(type) {
				case string:
					ipStr = v
				case nil:
					// spec.ip is null, try resource name
					break
				default:
					ipStr = fmt.Sprintf("%v", v)
				}
			}
		}

		// If spec.ip is null or empty, try using the resource name as the IP
		if ipStr == "" {
			metadata, ok := itemMap["metadata"].(map[string]interface{})
			if ok {
				if name, ok := metadata["name"].(string); ok && name != "" {
					ipStr = name
				}
			}
		}

		if ipStr == "" {
			continue
		}

		// Get the node assignment
		nodeValue, ok := spec["node"]
		if !ok {
			continue
		}
		nodeStr := ""
		switch v := nodeValue.(type) {
		case string:
			nodeStr = v
		case nil:
			continue
		default:
			nodeStr = fmt.Sprintf("%v", v)
		}
		if nodeStr == "" {
			continue
		}

		// Check if CPIC has CloudResponseSuccess status (assigned)
		status, ok := itemMap["status"].(map[string]interface{})
		if ok {
			conditions, ok := status["conditions"].([]interface{})
			if ok {
				for _, cond := range conditions {
					condMap, ok := cond.(map[string]interface{})
					if !ok {
						continue
					}
					reason, _ := condMap["reason"].(string)
					if reason == "CloudResponseSuccess" {
						ipToNode[ipStr] = nodeStr
						break
					}
				}
			}
		}
	}

	return ipToNode, nil
}

// EIPCPICMismatch represents a mismatch between EIP status and CPIC status
type EIPCPICMismatch struct {
	IP           string
	EIPNode      string // Node from EIP status
	CPICNode     string // Node from CPIC status
	EIPResource  string // EIP resource name/namespace
	MismatchType string // "node_mismatch", "missing_in_cpic", "missing_in_eip"
}

// UnassignedEIP represents an EIP that is configured but not assigned
type UnassignedEIP struct {
	IP         string
	Resource   string // EIP resource name/namespace
	Reason     string // Why it's not assigned
	CPICStatus string // CPIC status if available (pending, error, missing)
	CPICReason string // CPIC condition reason if available
}

// DetectEIPCPICMismatches compares EIP status.items node assignments with CPIC CloudResponseSuccess assignments
// Returns a list of mismatches where the same IP is assigned to different nodes
// Accounts for the constraint that only one IP can be assigned per node (to avoid false positives)
func (oc *OpenShiftClient) DetectEIPCPICMismatches() ([]EIPCPICMismatch, error) {
	var mismatches []EIPCPICMismatch

	// Get count of available nodes (nodes with egress-assignable label)
	// This is needed to determine if unassigned IPs are legitimate (due to node capacity) or mismatches
	availableNodes, err := oc.GetEIPEnabledNodes()
	availableNodeCount := 0
	if err == nil {
		availableNodeCount = len(availableNodes)
	}

	// Get CPIC IP->node mapping (already exists)
	cpicIPToNode, err := oc.GetIPToNodeMapping()
	if err != nil {
		return nil, fmt.Errorf("failed to get CPIC IP to node mapping: %w", err)
	}

	// Get EIP data and build EIP IP->node mapping
	eipData, err := oc.RunCommand([]string{"get", "eip", "--all-namespaces", "-o", "json"})
	if err != nil {
		return nil, fmt.Errorf("failed to get EIP data: %w", err)
	}

	// Build EIP IP->node mapping
	// EIP structure: spec.egressIPs[i] should correspond to status.items[i]
	eipIPToNode := make(map[string]string)
	eipIPToResource := make(map[string]string)

	// Track EIP resources: configured IPs count and assigned IPs count per resource
	eipResourceConfig := make(map[string]int)   // resource -> configured IP count
	eipResourceAssigned := make(map[string]int) // resource -> assigned IP count (in status.items with node)

	items, ok := eipData["items"].([]interface{})
	if !ok {
		return mismatches, nil
	}

	// First pass: identify overcommitted EIP resources and build the set
	overcommittedResources := make(map[string]bool)
	for _, item := range items {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		// Get EIP resource name/namespace
		metadata, ok := itemMap["metadata"].(map[string]interface{})
		var resourceName string
		if ok {
			name, _ := metadata["name"].(string)
			namespace, _ := metadata["namespace"].(string)
			if namespace != "" {
				resourceName = fmt.Sprintf("%s/%s", namespace, name)
			} else {
				resourceName = name
			}
		}

		// Get configured IPs from spec.egressIPs
		spec, ok := itemMap["spec"].(map[string]interface{})
		if !ok {
			continue
		}

		configuredCount := 0
		if egressIPs, ok := spec["egressIPs"].([]interface{}); ok {
			configuredCount = len(egressIPs)
		}

		// Mark resource as overcommitted if configured IPs > available nodes
		if availableNodeCount > 0 && configuredCount > availableNodeCount {
			overcommittedResources[resourceName] = true
		}
	}

	// Second pass: build EIP IP->node mapping, excluding overcommitted resources
	for _, item := range items {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		// Get EIP resource name/namespace
		metadata, ok := itemMap["metadata"].(map[string]interface{})
		var resourceName string
		if ok {
			name, _ := metadata["name"].(string)
			namespace, _ := metadata["namespace"].(string)
			if namespace != "" {
				resourceName = fmt.Sprintf("%s/%s", namespace, name)
			} else {
				resourceName = name
			}
		}

		// Skip overcommitted resources entirely
		if overcommittedResources[resourceName] {
			continue
		}

		// Get configured IPs from spec.egressIPs
		spec, ok := itemMap["spec"].(map[string]interface{})
		var configuredIPs []string
		if ok {
			if egressIPs, ok := spec["egressIPs"].([]interface{}); ok {
				for _, ip := range egressIPs {
					if ipStr, ok := ip.(string); ok {
						configuredIPs = append(configuredIPs, ipStr)
					}
				}
			}
		}
		// Track configured IP count for this resource
		eipResourceConfig[resourceName] = len(configuredIPs)

		// Get assigned IPs from status.items
		status, ok := itemMap["status"].(map[string]interface{})
		if !ok {
			continue
		}

		statusItems, ok := status["items"].([]interface{})
		if !ok {
			continue
		}

		// Map each status.item to its IP and node
		// First try to get IP directly from status.item (if it has an egressIP field)
		// Otherwise, fall back to positional mapping with spec.egressIPs
		for i, statusItem := range statusItems {
			statusItemMap, ok := statusItem.(map[string]interface{})
			if !ok {
				continue
			}

			// Get node from status.item
			nodeValue, ok := statusItemMap["node"]
			if !ok {
				continue
			}

			var nodeStr string
			switch v := nodeValue.(type) {
			case string:
				nodeStr = v
			case nil:
				continue
			default:
				nodeStr = fmt.Sprintf("%v", v)
			}

			if nodeStr == "" {
				continue
			}

			// Try to get IP directly from status.item (egressIP field)
			var ip string
			if egressIPValue, hasIP := statusItemMap["egressIP"]; hasIP {
				switch v := egressIPValue.(type) {
				case string:
					ip = v
				default:
					ip = fmt.Sprintf("%v", v)
				}
			} else {
				// Fall back to positional mapping if egressIP field doesn't exist
				if i < len(configuredIPs) {
					ip = configuredIPs[i]
				} else {
					continue // Skip if no IP can be determined
				}
			}

			if ip == "" {
				continue
			}

			eipIPToNode[ip] = nodeStr
			eipIPToResource[ip] = resourceName
		}
	}

	// Count assigned IPs per resource (after building the maps)
	for _, resName := range eipIPToResource {
		if resName != "" {
			eipResourceAssigned[resName]++
		}
	}

	// Compare EIP and CPIC mappings
	// Flag actual node assignment mismatches (where same IP is on different nodes)
	// Also flag IPs in CPIC with CloudResponseSuccess but not in EIP status.items
	// Exclude IPs from overcommitted resources
	for ip, eipNode := range eipIPToNode {
		// Skip IPs from overcommitted resources
		resourceName := eipIPToResource[ip]
		if resourceName != "" && overcommittedResources[resourceName] {
			continue
		}

		cpicNode, existsInCPIC := cpicIPToNode[ip]
		if existsInCPIC && eipNode != cpicNode {
			// IP assigned to different nodes - this is a real mismatch
			mismatches = append(mismatches, EIPCPICMismatch{
				IP:           ip,
				EIPNode:      eipNode,
				CPICNode:     cpicNode,
				EIPResource:  resourceName,
				MismatchType: "node_mismatch",
			})
		}
	}

	// Check for IPs in CPIC (CloudResponseSuccess) but not in EIP status.items
	// This indicates CPIC succeeded but EIP status hasn't been updated
	// Try to find which EIP resource this IP belongs to by checking spec.egressIPs
	// Exclude overcommitted resources from this mapping
	eipResourceMap := make(map[string]string) // IP -> resource name
	for _, item := range items {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		metadata, ok := itemMap["metadata"].(map[string]interface{})
		var resourceName string
		if ok {
			name, _ := metadata["name"].(string)
			namespace, _ := metadata["namespace"].(string)
			if namespace != "" {
				resourceName = fmt.Sprintf("%s/%s", namespace, name)
			} else {
				resourceName = name
			}
		}

		// Skip overcommitted resources
		if overcommittedResources[resourceName] {
			continue
		}

		spec, ok := itemMap["spec"].(map[string]interface{})
		if ok {
			if egressIPs, ok := spec["egressIPs"].([]interface{}); ok {
				for _, ipVal := range egressIPs {
					if ipStr, ok := ipVal.(string); ok {
						eipResourceMap[ipStr] = resourceName
					}
				}
			}
		}
	}

	// Check for IPs in CPIC with CloudResponseSuccess but not in EIP status.items
	// This indicates CPIC succeeded but EIP status hasn't been updated
	// BUT: Don't flag if the EIP resource is already at capacity (one IP per available node)
	// Also exclude IPs from overcommitted resources
	for ip, cpicNode := range cpicIPToNode {
		_, existsInEIP := eipIPToNode[ip]
		if !existsInEIP {
			// IP is in CPIC with CloudResponseSuccess but not in EIP status.items
			resourceName := eipResourceMap[ip]

			// Skip IPs from overcommitted resources
			if resourceName != "" && overcommittedResources[resourceName] {
				continue
			}

			if resourceName != "" {
				// Check if this EIP resource is at capacity (has assigned IPs equal to available nodes)
				// If so, unassigned IPs are legitimate (due to node capacity constraint)
				assignedCount := eipResourceAssigned[resourceName]
				configuredCount := eipResourceConfig[resourceName]

				// Only flag as mismatch if:
				// The resource has fewer assigned IPs than the maximum possible (min(configuredCount, availableNodeCount))
				// This means: if assignedCount >= min(configuredCount, availableNodeCount), then remaining IPs are legitimately unassigned
				isAtCapacity := false
				if availableNodeCount > 0 {
					maxPossibleAssignments := configuredCount
					if configuredCount > availableNodeCount {
						maxPossibleAssignments = availableNodeCount
					}
					if assignedCount >= maxPossibleAssignments {
						isAtCapacity = true
					}
				}

				if !isAtCapacity {
					// This is a mismatch - CPIC shows it's assigned but EIP doesn't, and resource isn't at capacity
					mismatches = append(mismatches, EIPCPICMismatch{
						IP:           ip,
						EIPNode:      "",
						CPICNode:     cpicNode,
						EIPResource:  resourceName,
						MismatchType: "missing_in_eip",
					})
				}
			} else {
				// IP is in CPIC but we can't determine which EIP resource it belongs to
				// Still flag as mismatch (orphaned CPIC)
				mismatches = append(mismatches, EIPCPICMismatch{
					IP:           ip,
					EIPNode:      "",
					CPICNode:     cpicNode,
					EIPResource:  "",
					MismatchType: "missing_in_eip",
				})
			}
		}
	}

	// Also check IPs that are configured in EIP spec.egressIPs but missing from EIP status.items
	// If they have a CPIC with a node assigned (regardless of status), it's a mismatch
	cpicAllData, err := oc.RunCommand([]string{"get", "cloudprivateipconfig", "--all-namespaces", "-o", "json"})
	if err == nil {
		cpicAllItems, ok := cpicAllData["items"].([]interface{})
		if ok {
			// Build map of all CPIC IPs with node assignments
			cpicAllIPToNode := make(map[string]string)
			for _, item := range cpicAllItems {
				itemMap, ok := item.(map[string]interface{})
				if !ok {
					continue
				}

				// Get IP address - try spec.ip first, fall back to resource name
				var ipStr string
				spec, ok := itemMap["spec"].(map[string]interface{})
				if ok {
					ipValue, ok := spec["ip"]
					if ok {
						switch v := ipValue.(type) {
						case string:
							ipStr = v
						case nil:
							// spec.ip is null, try resource name
							break
						default:
							ipStr = fmt.Sprintf("%v", v)
						}
					}
				}

				// If spec.ip is null or empty, try using the resource name as the IP
				if ipStr == "" {
					metadata, ok := itemMap["metadata"].(map[string]interface{})
					if ok {
						if name, ok := metadata["name"].(string); ok && name != "" {
							ipStr = name
						}
					}
				}

				if ipStr == "" {
					continue
				}

				nodeValue, ok := spec["node"]
				if !ok {
					continue
				}
				nodeStr := ""
				switch v := nodeValue.(type) {
				case string:
					nodeStr = v
				case nil:
					continue
				default:
					nodeStr = fmt.Sprintf("%v", v)
				}
				if nodeStr != "" {
					cpicAllIPToNode[ipStr] = nodeStr
				}
			}

			// Check IPs configured in EIP spec but not in EIP status.items
			for ip, resourceName := range eipResourceMap {
				_, existsInEIPStatus := eipIPToNode[ip]
				if !existsInEIPStatus {
					// IP is configured in EIP spec but not in EIP status.items
					// Check if it has a CPIC with node assignment
					if cpicNode, hasCPICNode := cpicAllIPToNode[ip]; hasCPICNode {
						// IP has CPIC with node assignment but not in EIP status.items
						// Check if we already reported this IP (from CloudResponseSuccess check above)
						alreadyReported := false
						for _, m := range mismatches {
							if m.IP == ip && m.MismatchType == "missing_in_eip" {
								alreadyReported = true
								break
							}
						}
						if !alreadyReported {
							// Check if this EIP resource is at capacity
							assignedCount := eipResourceAssigned[resourceName]
							configuredCount := eipResourceConfig[resourceName]
							isAtCapacity := false
							if availableNodeCount > 0 {
								maxPossibleAssignments := configuredCount
								if configuredCount > availableNodeCount {
									maxPossibleAssignments = availableNodeCount
								}
								if assignedCount >= maxPossibleAssignments {
									isAtCapacity = true
								}
							}

							if !isAtCapacity {
								// This is a mismatch - IP has CPIC node assignment but not in EIP status.items, and resource isn't at capacity
								mismatches = append(mismatches, EIPCPICMismatch{
									IP:           ip,
									EIPNode:      "",
									CPICNode:     cpicNode,
									EIPResource:  resourceName,
									MismatchType: "missing_in_eip",
								})
							}
						}
					}
				}
			}

			// Also check IPs in CPIC with node assignment but not in EIP status.items
			// (This catches cases where IP might not be in eipResourceMap but is in CPIC)
			// Exclude overcommitted resources
			for ip, cpicNode := range cpicAllIPToNode {
				_, existsInEIPStatus := eipIPToNode[ip]
				if !existsInEIPStatus {
					// IP is in CPIC with node assignment but not in EIP status.items
					resourceName := eipResourceMap[ip]

					// Skip IPs from overcommitted resources
					if resourceName != "" && overcommittedResources[resourceName] {
						continue
					}

					// Check if we already reported this IP
					alreadyReported := false
					for _, m := range mismatches {
						if m.IP == ip && m.MismatchType == "missing_in_eip" {
							alreadyReported = true
							break
						}
					}
					if !alreadyReported {
						if resourceName != "" {
							// Check if this EIP resource is at capacity
							assignedCount := eipResourceAssigned[resourceName]
							configuredCount := eipResourceConfig[resourceName]
							isAtCapacity := false
							if availableNodeCount > 0 {
								maxPossibleAssignments := configuredCount
								if configuredCount > availableNodeCount {
									maxPossibleAssignments = availableNodeCount
								}
								if assignedCount >= maxPossibleAssignments {
									isAtCapacity = true
								}
							}

							if !isAtCapacity {
								mismatches = append(mismatches, EIPCPICMismatch{
									IP:           ip,
									EIPNode:      "",
									CPICNode:     cpicNode,
									EIPResource:  resourceName,
									MismatchType: "missing_in_eip",
								})
							}
						} else {
							// IP is in CPIC but we can't determine which EIP resource it belongs to
							// Still flag as mismatch (orphaned CPIC)
							mismatches = append(mismatches, EIPCPICMismatch{
								IP:           ip,
								EIPNode:      "",
								CPICNode:     cpicNode,
								EIPResource:  "",
								MismatchType: "missing_in_eip",
							})
						}
					}
				}
			}
		}
	}

	return mismatches, nil
}

// CountOvercommittedEIPObjects counts EIP objects (resources) that have more IPs configured than available nodes
// An EIP resource is overcommitted if configured IPs > number of nodes with egress-assignable label
func (oc *OpenShiftClient) CountOvercommittedEIPObjects() (int, error) {
	// Get count of available nodes
	availableNodes, err := oc.GetEIPEnabledNodes()
	availableNodeCount := 0
	if err == nil {
		availableNodeCount = len(availableNodes)
	}

	if availableNodeCount == 0 {
		return 0, nil // No nodes available, can't determine overcommitment
	}

	// Get EIP data
	eipData, err := oc.RunCommand([]string{"get", "eip", "--all-namespaces", "-o", "json"})
	if err != nil {
		return 0, fmt.Errorf("failed to get EIP data: %w", err)
	}

	items, ok := eipData["items"].([]interface{})
	if !ok {
		return 0, nil
	}

	overcommittedCount := 0
	for _, item := range items {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		// Get configured IPs from spec.egressIPs
		spec, ok := itemMap["spec"].(map[string]interface{})
		if !ok {
			continue
		}

		configuredCount := 0
		if egressIPs, ok := spec["egressIPs"].([]interface{}); ok {
			configuredCount = len(egressIPs)
		}

		// Resource is overcommitted if configured IPs > available nodes
		if configuredCount > availableNodeCount {
			overcommittedCount++
		}
	}

	return overcommittedCount, nil
}

// CountMalfunctioningEIPObjects counts EIP objects (resources) that have mismatches between their status.items and CPIC
// An EIP object is malfunctioning if any of its IPs in status.items don't match CPIC assignments
func (oc *OpenShiftClient) CountMalfunctioningEIPObjects() (int, error) {
	mismatches, err := oc.DetectEIPCPICMismatches()
	if err != nil {
		return 0, err
	}

	// Collect unique EIP resource names that have mismatches
	malfunctioningResources := make(map[string]bool)
	for _, m := range mismatches {
		if m.EIPResource != "" {
			malfunctioningResources[m.EIPResource] = true
		}
	}

	return len(malfunctioningResources), nil
}

// DetectUnassignedEIPs finds EIPs that are configured but not assigned, and determines why
// Uses the same logic as GetEIPStats: configured = len(spec.egressIPs), assigned = len(status.items with node)
func (oc *OpenShiftClient) DetectUnassignedEIPs() ([]UnassignedEIP, error) {
	var unassigned []UnassignedEIP

	// Get EIP data
	eipData, err := oc.RunCommand([]string{"get", "eip", "--all-namespaces", "-o", "json"})
	if err != nil {
		return nil, fmt.Errorf("failed to get EIP data: %w", err)
	}

	// Get CPIC data to check status of unassigned IPs
	cpicData, err := oc.RunCommand([]string{"get", "cloudprivateipconfig", "--all-namespaces", "-o", "json"})
	if err != nil {
		return nil, fmt.Errorf("failed to get CPIC data: %w", err)
	}

	// Build CPIC status map (IP -> status info)
	cpicStatus := make(map[string]map[string]string) // IP -> {"status": "...", "reason": "..."}
	cpicItems, ok := cpicData["items"].([]interface{})
	if ok {
		for _, item := range cpicItems {
			itemMap, ok := item.(map[string]interface{})
			if !ok {
				continue
			}

			spec, ok := itemMap["spec"].(map[string]interface{})
			if !ok {
				continue
			}

			ipValue, ok := spec["ip"]
			if !ok {
				continue
			}

			var ipStr string
			switch v := ipValue.(type) {
			case string:
				ipStr = v
			default:
				ipStr = fmt.Sprintf("%v", v)
			}

			if ipStr == "" {
				continue
			}

			// Check CPIC status conditions
			status, ok := itemMap["status"].(map[string]interface{})
			if ok {
				conditions, ok := status["conditions"].([]interface{})
				if ok {
					for _, cond := range conditions {
						condMap, ok := cond.(map[string]interface{})
						if !ok {
							continue
						}
						reason, _ := condMap["reason"].(string)
						statusStr, _ := condMap["status"].(string)
						message, _ := condMap["message"].(string)

						// Determine CPIC status
						var cpicStatusVal, cpicReason string
						switch reason {
						case "CloudResponseSuccess":
							cpicStatusVal = "success"
						case "CloudResponsePending":
							cpicStatusVal = "pending"
							cpicReason = message
						case "CloudResponseError":
							cpicStatusVal = "error"
							cpicReason = message
						default:
							if statusStr != "" {
								cpicStatusVal = statusStr
								cpicReason = message
							}
						}

						if cpicStatusVal != "" {
							cpicStatus[ipStr] = map[string]string{
								"status": cpicStatusVal,
								"reason": cpicReason,
							}
							break
						}
					}
				}
			}
		}
	}

	// Analyze EIP resources
	items, ok := eipData["items"].([]interface{})
	if !ok {
		return unassigned, nil
	}

	for _, item := range items {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		// Get resource name
		metadata, ok := itemMap["metadata"].(map[string]interface{})
		var resourceName string
		if ok {
			name, _ := metadata["name"].(string)
			namespace, _ := metadata["namespace"].(string)
			if namespace != "" {
				resourceName = fmt.Sprintf("%s/%s", namespace, name)
			} else {
				resourceName = name
			}
		}

		// Get configured IPs
		spec, ok := itemMap["spec"].(map[string]interface{})
		var configuredIPs []string
		if ok {
			if egressIPs, ok := spec["egressIPs"].([]interface{}); ok {
				for _, ip := range egressIPs {
					if ipStr, ok := ip.(string); ok {
						configuredIPs = append(configuredIPs, ipStr)
					}
				}
			}
		}

		// Count assigned IPs from status.items (same logic as GetEIPStats)
		// Each status.item with a node represents an assigned IP
		// Skip resources without status (same as GetEIPStats)
		status, ok := itemMap["status"].(map[string]interface{})
		if !ok {
			continue // Skip resources without status (GetEIPStats does this too)
		}

		assignedCount := 0
		assignedIPs := make(map[string]bool)
		statusItems, ok := status["items"].([]interface{})
		if ok {
			// Count items that have a node assigned
			for i, statusItem := range statusItems {
				statusItemMap, ok := statusItem.(map[string]interface{})
				if !ok {
					continue
				}

				// Check if this status item has a node assigned
				nodeValue, hasNode := statusItemMap["node"]
				if !hasNode || nodeValue == nil {
					continue // Skip items without node assignment
				}

				assignedCount++

				// Try to identify the IP for this status item
				var ip string
				if egressIPValue, hasIP := statusItemMap["egressIP"]; hasIP {
					switch v := egressIPValue.(type) {
					case string:
						ip = v
					default:
						ip = fmt.Sprintf("%v", v)
					}
				} else {
					// Fall back to positional mapping if egressIP field doesn't exist
					if i < len(configuredIPs) {
						ip = configuredIPs[i]
					}
				}

				if ip != "" {
					assignedIPs[ip] = true
				}
			}
		}

		// Calculate unassigned count (same as GetEIPStats logic)
		configuredCount := len(configuredIPs)
		unassignedCount := configuredCount - assignedCount

		// Check EIP status conditions for more context
		var eipConditionReason string
		if status != nil {
			conditions, ok := status["conditions"].([]interface{})
			if ok {
				for _, cond := range conditions {
					condMap, ok := cond.(map[string]interface{})
					if !ok {
						continue
					}
					typeStr, _ := condMap["type"].(string)
					reason, _ := condMap["reason"].(string)
					message, _ := condMap["message"].(string)

					// Look for assignment-related conditions
					if typeStr == "Assigned" || reason != "" {
						if reason != "" {
							eipConditionReason = reason
							if message != "" {
								eipConditionReason = fmt.Sprintf("%s: %s", reason, message)
							}
						}
					}
				}
			}
		}

		// Find unassigned IPs - only report if we have fewer assigned than configured
		// Only report up to unassignedCount per resource to avoid over-counting
		if unassignedCount > 0 {
			// Find which specific IPs are unassigned (limit to unassignedCount for this resource)
			reportedForResource := 0
			for _, ip := range configuredIPs {
				if reportedForResource >= unassignedCount {
					break // Stop after reporting all unassigned for this resource
				}
				if !assignedIPs[ip] {
					// This IP is configured but not in assignedIPs map
					reason := "Not in EIP status.items"
					cpicStatusVal := "missing"
					cpicReasonVal := ""

					// Check CPIC status
					if cpicInfo, exists := cpicStatus[ip]; exists {
						cpicStatusVal = cpicInfo["status"]
						cpicReasonVal = cpicInfo["reason"]

						// Refine reason based on CPIC status
						switch cpicStatusVal {
						case "pending":
							reason = "CPIC pending"
							if cpicReasonVal != "" {
								reason = fmt.Sprintf("CPIC pending: %s", cpicReasonVal)
							}
						case "error":
							reason = "CPIC error"
							if cpicReasonVal != "" {
								reason = fmt.Sprintf("CPIC error: %s", cpicReasonVal)
							}
						case "success":
							reason = "CPIC succeeded but not in EIP status"
						}
					} else {
						// Check if there's an EIP condition reason
						if eipConditionReason != "" {
							reason = eipConditionReason
						}
					}

					unassigned = append(unassigned, UnassignedEIP{
						IP:         ip,
						Resource:   resourceName,
						Reason:     reason,
						CPICStatus: cpicStatusVal,
						CPICReason: cpicReasonVal,
					})
					reportedForResource++
				}
			}

			// If we couldn't identify specific IPs (e.g., no egressIP field), report generic count
			if reportedForResource < unassignedCount {
				remaining := unassignedCount - reportedForResource
				for i := 0; i < remaining && i < len(configuredIPs); i++ {
					ip := configuredIPs[i]
					if !assignedIPs[ip] {
						unassigned = append(unassigned, UnassignedEIP{
							IP:         ip,
							Resource:   resourceName,
							Reason:     "Not in EIP status.items",
							CPICStatus: "unknown",
							CPICReason: "",
						})
						reportedForResource++
						if reportedForResource >= unassignedCount {
							break
						}
					}
				}
			}
		}
		// Note: If status is not available, we skip this resource (same as GetEIPStats)
		// This prevents false positives when status hasn't been created yet
	}

	return unassigned, nil
}

func (oc *OpenShiftClient) GetNodeStats(nodeName string) (*NodeStats, error) {
	// Get CPIC stats for the node
	cpicData, err := oc.RunCommand([]string{"get", "cloudprivateipconfig", "--all-namespaces", "-o", "json"})
	if err != nil {
		return nil, err
	}

	cpicSuccess := 0
	cpicPending := 0
	cpicError := 0

	items, ok := cpicData["items"].([]interface{})
	if ok {
		for _, item := range items {
			itemMap, ok := item.(map[string]interface{})
			if !ok {
				continue
			}

			spec, ok := itemMap["spec"].(map[string]interface{})
			if !ok {
				continue
			}

			// Compare node field - handle both string and interface{} types
			nodeValue, ok := spec["node"]
			if !ok {
				continue
			}

			var nodeStr string
			switch v := nodeValue.(type) {
			case string:
				nodeStr = v
			case nil:
				continue
			default:
				nodeStr = fmt.Sprintf("%v", v)
			}

			if nodeStr != nodeName {
				continue
			}

			status, ok := itemMap["status"].(map[string]interface{})
			if !ok {
				continue
			}

			conditions, ok := status["conditions"].([]interface{})
			if !ok {
				continue
			}

			for _, cond := range conditions {
				condMap, ok := cond.(map[string]interface{})
				if !ok {
					continue
				}

				reason, ok := condMap["reason"].(string)
				if !ok {
					continue
				}

				switch reason {
				case "CloudResponseSuccess":
					cpicSuccess++
				case "CloudResponsePending":
					cpicPending++
				case "CloudResponseError":
					cpicError++
				}
			}
		}
	}

	// Get EIP stats for the node
	// Primary EIP = the first IP in status.items of each EIP resource
	// Each EIP resource contributes exactly ONE Primary EIP (the first IP in its status.items)
	// Secondary EIPs = CPIC Success - Primary EIPs

	// First, get EIP resources and their configured IPs to map IP -> resource
	eipData, err := oc.RunCommand([]string{"get", "eip", "--all-namespaces", "-o", "json"})
	if err != nil {
		return nil, err
	}

	// Build IP -> EIP resource map from spec.egressIPs
	ipToEIPResource := make(map[string]string)
	eipItems, ok := eipData["items"].([]interface{})
	if ok {
		for _, item := range eipItems {
			itemMap, ok := item.(map[string]interface{})
			if !ok {
				continue
			}

			metadata, ok := itemMap["metadata"].(map[string]interface{})
			var resourceName string
			if ok {
				name, _ := metadata["name"].(string)
				namespace, _ := metadata["namespace"].(string)
				if namespace != "" {
					resourceName = fmt.Sprintf("%s/%s", namespace, name)
				} else {
					resourceName = name
				}
			}

			spec, ok := itemMap["spec"].(map[string]interface{})
			if ok {
				if egressIPs, ok := spec["egressIPs"].([]interface{}); ok {
					for _, ipVal := range egressIPs {
						if ipStr, ok := ipVal.(string); ok {
							ipToEIPResource[ipStr] = resourceName
						}
					}
				}
			}
		}
	}

	// Count primary EIPs: the first IP in status.items of each EIP resource
	// Only count if that first IP is assigned to this node
	primaryEIPs := 0
	if ok {
		for _, item := range eipItems {
			itemMap, ok := item.(map[string]interface{})
			if !ok {
				continue
			}

			status, ok := itemMap["status"].(map[string]interface{})
			if !ok {
				continue
			}

			statusItems, ok := status["items"].([]interface{})
			if !ok || len(statusItems) == 0 {
				continue
			}

			// Get the FIRST status item (Primary EIP)
			firstStatusItem, ok := statusItems[0].(map[string]interface{})
			if !ok {
				continue
			}

			// Check if the first IP is assigned to this node
			nodeValue, ok := firstStatusItem["node"]
			if !ok {
				continue
			}

			var nodeStr string
			switch v := nodeValue.(type) {
			case string:
				nodeStr = v
			case nil:
				continue
			default:
				nodeStr = fmt.Sprintf("%v", v)
			}

			if nodeStr == nodeName {
				primaryEIPs++
			}
		}
	}

	// Also check CPIC data for EIP resources that don't have status.items yet
	// If an EIP resource's first configured IP is in CPIC (assigned to this node) but not in EIP status.items,
	// it should count as a Primary EIP on this node
	cpicItems, ok := cpicData["items"].([]interface{})
	if ok {
		// Build map of EIP resources that already have a Primary EIP counted from status.items
		eipResourcesWithPrimaryEIP := make(map[string]bool)
		for _, item := range eipItems {
			itemMap, ok := item.(map[string]interface{})
			if !ok {
				continue
			}

			status, ok := itemMap["status"].(map[string]interface{})
			if !ok {
				continue
			}

			statusItems, ok := status["items"].([]interface{})
			if !ok || len(statusItems) == 0 {
				continue
			}

			// Get resource name
			metadata, ok := itemMap["metadata"].(map[string]interface{})
			var resourceName string
			if ok {
				name, _ := metadata["name"].(string)
				namespace, _ := metadata["namespace"].(string)
				if namespace != "" {
					resourceName = fmt.Sprintf("%s/%s", namespace, name)
				} else {
					resourceName = name
				}
			}

			// Check if first status item has a node assigned
			firstStatusItem, ok := statusItems[0].(map[string]interface{})
			if ok {
				nodeValue, ok := firstStatusItem["node"]
				if ok && nodeValue != nil {
					eipResourcesWithPrimaryEIP[resourceName] = true
				}
			}
		}

		// Check CPIC for EIP resources that don't have status.items yet
		// Find the first configured IP from each EIP resource and check if it's in CPIC assigned to this node
		for _, item := range eipItems {
			itemMap, ok := item.(map[string]interface{})
			if !ok {
				continue
			}

			// Get resource name
			metadata, ok := itemMap["metadata"].(map[string]interface{})
			var resourceName string
			if ok {
				name, _ := metadata["name"].(string)
				namespace, _ := metadata["namespace"].(string)
				if namespace != "" {
					resourceName = fmt.Sprintf("%s/%s", namespace, name)
				} else {
					resourceName = name
				}
			}

			// Skip if this resource already has a Primary EIP counted from status.items
			if eipResourcesWithPrimaryEIP[resourceName] {
				continue
			}

			// Get the first configured IP from spec.egressIPs
			spec, ok := itemMap["spec"].(map[string]interface{})
			if !ok {
				continue
			}

			var firstConfiguredIP string
			if egressIPs, ok := spec["egressIPs"].([]interface{}); ok && len(egressIPs) > 0 {
				if ipStr, ok := egressIPs[0].(string); ok {
					firstConfiguredIP = ipStr
				}
			}

			if firstConfiguredIP == "" {
				continue
			}

			// Check if this first IP is in CPIC assigned to this node
			for _, cpicItem := range cpicItems {
				cpicItemMap, ok := cpicItem.(map[string]interface{})
				if !ok {
					continue
				}

				cpicSpec, ok := cpicItemMap["spec"].(map[string]interface{})
				if !ok {
					continue
				}

				// Get IP from CPIC
				var cpicIPStr string
				if ipValue, ok := cpicSpec["ip"]; ok {
					switch v := ipValue.(type) {
					case string:
						cpicIPStr = v
					case nil:
						// spec.ip is null, try resource name
						if cpicMetadata, ok := cpicItemMap["metadata"].(map[string]interface{}); ok {
							if name, ok := cpicMetadata["name"].(string); ok && name != "" {
								cpicIPStr = name
							}
						}
					default:
						cpicIPStr = fmt.Sprintf("%v", v)
					}
				} else {
					// spec.ip doesn't exist, try resource name
					if cpicMetadata, ok := cpicItemMap["metadata"].(map[string]interface{}); ok {
						if name, ok := cpicMetadata["name"].(string); ok && name != "" {
							cpicIPStr = name
						}
					}
				}

				if cpicIPStr != firstConfiguredIP {
					continue
				}

				// Check if assigned to this node
				nodeValue, ok := cpicSpec["node"]
				if !ok {
					continue
				}

				var cpicNodeStr string
				switch v := nodeValue.(type) {
				case string:
					cpicNodeStr = v
				case nil:
					continue
				default:
					cpicNodeStr = fmt.Sprintf("%v", v)
				}

				if cpicNodeStr != nodeName {
					continue
				}

				// Check if CPIC has CloudResponseSuccess
				cpicStatus, ok := cpicItemMap["status"].(map[string]interface{})
				if !ok {
					continue
				}

				conditions, ok := cpicStatus["conditions"].([]interface{})
				if !ok {
					continue
				}

				hasCloudResponseSuccess := false
				for _, cond := range conditions {
					condMap, ok := cond.(map[string]interface{})
					if !ok {
						continue
					}
					reason, _ := condMap["reason"].(string)
					if reason == "CloudResponseSuccess" {
						hasCloudResponseSuccess = true
						break
					}
				}

				if hasCloudResponseSuccess {
					// This EIP resource's first IP is in CPIC assigned to this node but not in EIP status.items
					primaryEIPs++
					break // Only count once per EIP resource
				}
			}
		}
	}

	// Secondary EIPs = remaining IPs (CPIC Success - Primary EIPs)
	secondaryEIPs := 0
	if cpicSuccess > primaryEIPs {
		secondaryEIPs = cpicSuccess - primaryEIPs
	}

	return &NodeStats{
		CPICSuccess:   cpicSuccess,
		CPICPending:   cpicPending,
		CPICError:     cpicError,
		EIPAssigned:   primaryEIPs,
		SecondaryEIPs: secondaryEIPs,
		AzureEIPs:     0, // Will be filled by Azure client
		AzureLBs:      0, // Will be filled by Azure client
	}, nil
}

// AzureClient handles Azure CLI operations
type AzureClient struct {
	subscriptionID string
	resourceGroup  string
}

func NewAzureClient(subscriptionID, resourceGroup string) *AzureClient {
	return &AzureClient{
		subscriptionID: subscriptionID,
		resourceGroup:  resourceGroup,
	}
}

func (ac *AzureClient) RunCommand(cmd []string) (interface{}, error) {
	args := append([]string{}, cmd...)
	args = append(args, "--subscription", ac.subscriptionID)
	cmdObj := exec.Command("az", args...)
	output, err := cmdObj.Output()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("Azure command failed: %s", string(exitError.Stderr))
		}
		return nil, fmt.Errorf("Azure command failed: %w", err)
	}

	var result interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return result, nil
}

func (ac *AzureClient) GetNodeNICStats(nodeName string) (int, int, error) {
	nicName := fmt.Sprintf("%s-nic", nodeName)

	// Get IP configurations
	ipConfigsResult, err := ac.RunCommand([]string{"network", "nic", "show",
		"--resource-group", ac.resourceGroup,
		"--name", nicName,
		"--query", "ipConfigurations[].privateIPAddress"})
	if err != nil {
		return 0, 0, err
	}

	ipConfigs, ok := ipConfigsResult.([]interface{})
	if !ok {
		return 0, 0, nil
	}

	// Get load balancer associations
	lbConfigsResult, err := ac.RunCommand([]string{"network", "nic", "show",
		"--resource-group", ac.resourceGroup,
		"--name", nicName,
		"--query", "ipConfigurations[].{pools:loadBalancerBackendAddressPools[].id}"})
	if err != nil {
		return max(0, len(ipConfigs)-1), 0, nil
	}

	lbConfigs, ok := lbConfigsResult.([]interface{})
	if !ok {
		return max(0, len(ipConfigs)-1), 0, nil
	}

	totalIPs := len(ipConfigs)
	lbAssociated := 0

	for _, cfg := range lbConfigs {
		cfgMap, ok := cfg.(map[string]interface{})
		if !ok {
			continue
		}

		pools, ok := cfgMap["pools"].([]interface{})
		if ok && len(pools) > 0 {
			lbAssociated++
		}
	}

	secondaryIPs := max(0, totalIPs-1)
	secondaryLBIPs := max(0, lbAssociated-1)

	return secondaryIPs, secondaryLBIPs, nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// calculateSubnetSize calculates the number of IPs in a subnet from CIDR notation
// e.g., "10.0.2.0/23" -> 512 IPs
func calculateSubnetSize(cidr string) int {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return 0
	}

	maskBits, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0
	}

	// Calculate 2^(32-maskBits) for IPv4
	if maskBits < 0 || maskBits > 32 {
		return 0
	}

	hostBits := 32 - maskBits
	if hostBits >= 63 {
		return 0 // Prevent overflow
	}

	return 1 << hostBits // 2^hostBits
}

// EIPMonitor handles monitoring operations
type EIPMonitor struct {
	outputDir      string
	logsDir        string
	dataDir        string
	plotsDir       string
	ocClient       *OpenShiftClient
	azClient       *AzureClient
	bufferedLogger *BufferedLogger
}

func NewEIPMonitor(outputDir, subscriptionID, resourceGroup string) (*EIPMonitor, error) {
	logsDir := filepath.Join(outputDir, "logs")
	dataDir := filepath.Join(outputDir, "data")
	plotsDir := filepath.Join(outputDir, "plots")

	for _, dir := range []string{logsDir, dataDir, plotsDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return &EIPMonitor{
		outputDir:      outputDir,
		logsDir:        logsDir,
		dataDir:        dataDir,
		plotsDir:       plotsDir,
		ocClient:       NewOpenShiftClient(),
		azClient:       NewAzureClient(subscriptionID, resourceGroup),
		bufferedLogger: NewBufferedLogger(logsDir, 100),
	}, nil
}

func (em *EIPMonitor) ShouldContinueMonitoring(eipStats *EIPStats, cpicStats *CPICStats, overcommittedEIPs int) bool {
	// Stats are already printed in MonitorLoop, no need to log here

	// If there are overcommitted EIPs, calculate expected assignable IPs
	// Overcommitted resources have more IPs configured than available nodes
	// Those extra IPs cannot be assigned, so we need to account for them
	expectedAssignable := eipStats.Configured

	if overcommittedEIPs > 0 {
		// Get available nodes count to calculate unassignable IPs
		availableNodes, err := em.ocClient.GetEIPEnabledNodes()
		availableNodeCount := 0
		if err == nil {
			availableNodeCount = len(availableNodes)
		}

		if availableNodeCount > 0 {
			// Get EIP data to calculate total unassignable IPs
			eipData, err := em.ocClient.RunCommand([]string{"get", "eip", "--all-namespaces", "-o", "json"})
			if err == nil {
				if items, ok := eipData["items"].([]interface{}); ok {
					unassignableIPs := 0
					for _, item := range items {
						itemMap, ok := item.(map[string]interface{})
						if !ok {
							continue
						}

						spec, ok := itemMap["spec"].(map[string]interface{})
						if !ok {
							continue
						}

						configuredCount := 0
						if egressIPs, ok := spec["egressIPs"].([]interface{}); ok {
							configuredCount = len(egressIPs)
						}

						// If this resource is overcommitted, calculate unassignable IPs
						if configuredCount > availableNodeCount {
							unassignableIPs += configuredCount - availableNodeCount
						}
					}

					// Expected assignable = configured - unassignable due to overcommitment
					expectedAssignable = eipStats.Configured - unassignableIPs
				}
			}
		}
	}

	// Continue monitoring if:
	// 1. Assigned IPs don't match expected assignable (accounting for overcommitment), OR
	// 2. CPIC success doesn't match expected assignable
	return eipStats.Assigned != expectedAssignable || cpicStats.Success != expectedAssignable
}

type NodeStatus string

const (
	NodeStatusReady              NodeStatus = "Ready"
	NodeStatusSchedulingDisabled NodeStatus = "SchedulingDisabled"
	NodeStatusNotReady           NodeStatus = "NotReady"
	NodeStatusUnknown            NodeStatus = "Unknown"
)

type NodeEIPData struct {
	Node          string
	EIPAssigned   int // Primary EIPs (first IP from each EIP resource on this node)
	SecondaryEIPs int // Secondary EIPs (remaining IPs: CPIC Success - Primary)
	AzureEIPs     int
	AzureLBs      int
	CPICSuccess   int
	CPICPending   int
	CPICError     int
	Capacity      int        // IP capacity from node annotations
	Status        NodeStatus // Node readiness status
}

func (em *EIPMonitor) CollectSingleNodeData(node, timestamp string) *NodeEIPData {
	nodeStats, err := em.ocClient.GetNodeStats(node)
	if err != nil {
		log.Printf("Error monitoring node %s: %v", node, err)
		return nil
	}

	azureEIPs, azureLBs, err := em.azClient.GetNodeNICStats(node)
	if err != nil {
		log.Printf("Error getting Azure stats for node %s: %v", node, err)
		azureEIPs, azureLBs = 0, 0
	}

	nodeStats.AzureEIPs = azureEIPs
	nodeStats.AzureLBs = azureLBs

	// Get node IP capacity
	capacity, err := em.ocClient.GetNodeCapacity(node)
	if err != nil {
		log.Printf("Error getting capacity for node %s: %v", node, err)
		capacity = 0 // Unknown capacity
	}

	// Get node status
	nodeStatus, err := em.ocClient.GetNodeStatus(node)
	if err != nil {
		log.Printf("Error getting status for node %s: %v", node, err)
		nodeStatus = NodeStatusUnknown
	}

	// Log node statistics
	em.bufferedLogger.LogStats(timestamp, fmt.Sprintf("%s_ocp_cpic", node), map[string]interface{}{
		"success": nodeStats.CPICSuccess,
		"pending": nodeStats.CPICPending,
		"error":   nodeStats.CPICError,
	})

	em.bufferedLogger.LogStats(timestamp, fmt.Sprintf("%s_ocp_eip", node), map[string]interface{}{
		"primary":   nodeStats.EIPAssigned,
		"secondary": nodeStats.SecondaryEIPs,
		"assigned":  nodeStats.EIPAssigned + nodeStats.SecondaryEIPs, // Total assigned (Primary + Secondary)
	})

	em.bufferedLogger.LogStats(timestamp, fmt.Sprintf("%s_azure", node), map[string]interface{}{
		"eips": nodeStats.AzureEIPs,
		"lbs":  nodeStats.AzureLBs,
	})

	em.bufferedLogger.LogStats(timestamp, fmt.Sprintf("%s_capacity", node), map[string]interface{}{
		"capacity": capacity,
	})

	// Don't log here - will log after sorting in MonitorLoop

	return &NodeEIPData{
		Node:          node,
		EIPAssigned:   nodeStats.EIPAssigned,
		SecondaryEIPs: nodeStats.SecondaryEIPs,
		AzureEIPs:     azureEIPs,
		AzureLBs:      azureLBs,
		CPICSuccess:   nodeStats.CPICSuccess,
		CPICPending:   nodeStats.CPICPending,
		CPICError:     nodeStats.CPICError,
		Capacity:      capacity,
		Status:        nodeStatus,
	}
}

func (em *EIPMonitor) CollectNodeDataParallel(nodes []string, timestamp string) []*NodeEIPData {
	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make([]*NodeEIPData, 0, len(nodes))

	maxWorkers := len(nodes)
	if maxWorkers > 10 {
		maxWorkers = 10
	}

	sem := make(chan struct{}, maxWorkers)

	for _, node := range nodes {
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			sem <- struct{}{}        // Acquire semaphore
			defer func() { <-sem }() // Release semaphore

			data := em.CollectSingleNodeData(n, timestamp)
			if data != nil {
				mu.Lock()
				results = append(results, data)
				mu.Unlock()
			}
		}(node)
	}

	wg.Wait()

	// Sort results by node name for consistent ordering
	sort.Slice(results, func(i, j int) bool {
		return results[i].Node < results[j].Node
	})

	return results
}

func (em *EIPMonitor) LogClusterSummary(timestamp string, nodeData []*NodeEIPData) error {
	totalPrimaryEIPs := 0
	totalSecondaryEIPs := 0
	totalAssignedEIPs := 0
	totalAzureEIPs := 0
	for _, data := range nodeData {
		totalPrimaryEIPs += data.EIPAssigned
		totalSecondaryEIPs += data.SecondaryEIPs
		totalAssignedEIPs += data.EIPAssigned + data.SecondaryEIPs
		totalAzureEIPs += data.AzureEIPs
	}

	nodeCount := len(nodeData)
	avgEIPs := float64(totalAssignedEIPs)
	if nodeCount > 0 {
		avgEIPs = avgEIPs / float64(nodeCount)
	}

	em.bufferedLogger.LogStats(timestamp, "cluster_summary", map[string]interface{}{
		"total_primary_eips":   totalPrimaryEIPs,
		"total_secondary_eips": totalSecondaryEIPs,
		"total_assigned_eips":  totalAssignedEIPs,
		"total_azure_eips":     totalAzureEIPs,
		"node_count":           nodeCount,
		"avg_eips_per_node":    avgEIPs,
	})

	// Write detailed summary
	summaryFile := filepath.Join(em.logsDir, "cluster_eip_details.log")
	f, err := os.OpenFile(summaryFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintf(f, "%s CLUSTER_SUMMARY\n", timestamp)

	// Sort node data for consistent ordering
	sortedNodeData := make([]*NodeEIPData, len(nodeData))
	copy(sortedNodeData, nodeData)
	sort.Slice(sortedNodeData, func(i, j int) bool {
		return sortedNodeData[i].Node < sortedNodeData[j].Node
	})

	for _, data := range sortedNodeData {
		fmt.Fprintf(f, "%s %s %d %d %d %d\n", timestamp, data.Node, data.EIPAssigned, data.SecondaryEIPs, data.EIPAssigned+data.SecondaryEIPs, data.AzureEIPs)
	}
	fmt.Fprintf(f, "%s TOTAL %d %d %d %d\n\n", timestamp, totalPrimaryEIPs, totalSecondaryEIPs, totalAssignedEIPs, totalAzureEIPs)

	return nil
}

func (em *EIPMonitor) MonitorLoop() error {
	log.Println("Starting EIP monitoring loop...")

	nodes, err := em.ocClient.GetEIPEnabledNodes()
	if err != nil {
		return err
	}
	sort.Strings(nodes) // Ensure consistent ordering
	log.Printf("Found EIP-enabled nodes: %v", nodes)

	// Track number of lines we've printed (for overwriting)
	linesPrinted := 0

	// Track previous values for highlighting changes
	prevValues := make(map[string]*NodeEIPData)

	// Track previous summary stats for highlighting
	var prevSummary struct {
		configured, successful, assigned, cpicError int
		cnccRunning, cnccReady                      int
		initialized                                 bool
	}

	// Track progress detection for OVN-Kube warning
	var progressTracker struct {
		iterationsWithoutProgress int
		baselineSet               bool
		baselineEIPAssigned       int
		baselineCPICSuccess       int
		baselineCPICPending       int
		baselineNodeEIPs          map[string]int // node -> EIP assigned count
		warningShown              bool           // Track if warning was already shown for current baseline
	}
	progressTracker.baselineNodeEIPs = make(map[string]int)

	for {
		timestamp := time.Now().Format(time.RFC3339)

		// Get global statistics once per iteration
		eipStats, err := em.ocClient.GetEIPStats()
		if err != nil {
			return err
		}

		cpicStats, err := em.ocClient.GetCPICStats()
		if err != nil {
			return err
		}

		// Get CNCC stats (pod health and queue depth)
		cnccStats, err := em.ocClient.GetCNCCStats()
		if err != nil {
			// Log error but don't fail - CNCC stats are optional
			fmt.Fprintf(os.Stderr, "Warning: Failed to get CNCC stats: %v\n", err)
			cnccStats = &CNCCStats{} // Use empty stats
		}

		// Get malfunctioning EIP objects count
		malfunctioningEIPs, err := em.ocClient.CountMalfunctioningEIPObjects()
		if err != nil {
			// Log error but don't fail - malfunctioning count is optional
			fmt.Fprintf(os.Stderr, "Warning: Failed to count malfunctioning EIP objects: %v\n", err)
			malfunctioningEIPs = 0
		}

		// Get overcommitted EIP objects count
		overcommittedEIPs, err := em.ocClient.CountOvercommittedEIPObjects()
		if err != nil {
			// Log error but don't fail - overcommitted count is optional
			fmt.Fprintf(os.Stderr, "Warning: Failed to count overcommitted EIP objects: %v\n", err)
			overcommittedEIPs = 0
		}

		// Log global statistics
		em.bufferedLogger.LogStats(timestamp, "ocp_eips", map[string]interface{}{
			"configured": eipStats.Configured,
			"assigned":   eipStats.Assigned,
			"unassigned": eipStats.Unassigned,
		})

		em.bufferedLogger.LogStats(timestamp, "ocp_cpic", map[string]interface{}{
			"success": cpicStats.Success,
			"pending": cpicStats.Pending,
			"error":   cpicStats.Error,
		})

		em.bufferedLogger.LogStats(timestamp, "malfunctioning_eip_objects", map[string]interface{}{
			"count": malfunctioningEIPs,
		})

		// Collect node data in parallel
		nodeData := em.CollectNodeDataParallel(nodes, timestamp)

		// Check if stdout is a terminal (for ANSI escape codes)
		isTerminal := term.IsTerminal(int(os.Stdout.Fd()))

		// Move cursor up to overwrite previous lines (if any)
		if linesPrinted > 0 && isTerminal {
			fmt.Printf("\033[%dA", linesPrinted) // Move up N lines to get back to first line
		}

		// Print timestamp for this iteration
		timestampStr := time.Now().Format("2006/01/02 15:04:05")
		clearLine := ""
		if isTerminal {
			clearLine = "\033[K"
		}
		fmt.Printf("%s%s\n", clearLine, timestampStr)

		// Print node statistics in sorted order (using \033[K to clear line if terminal)
		for _, data := range nodeData {
			prev, hasPrev := prevValues[data.Node]

			// Format values with highlighting if changed
			cpicSuccessStr := formatValue(data.CPICSuccess, prev != nil && prev.CPICSuccess != data.CPICSuccess, isTerminal)
			cpicPendingStr := formatValue(data.CPICPending, prev != nil && prev.CPICPending != data.CPICPending, isTerminal)
			// Use red highlighting for CPIC errors
			cpicErrorStr := formatValueError(data.CPICError, prev != nil && prev.CPICError != data.CPICError, isTerminal)
			eipStr := formatValue(data.EIPAssigned, prev != nil && prev.EIPAssigned != data.EIPAssigned, isTerminal)
			secondaryEIPStr := formatValue(data.SecondaryEIPs, prev != nil && prev.SecondaryEIPs != data.SecondaryEIPs, isTerminal)
			azureEIPsStr := formatValue(data.AzureEIPs, prev != nil && prev.AzureEIPs != data.AzureEIPs, isTerminal)
			azureLBsStr := formatValue(data.AzureLBs, prev != nil && prev.AzureLBs != data.AzureLBs, isTerminal)

			// Format capacity: show as "X/Y" where X is available capacity (total - assigned), Y is total capacity
			// Always show capacity, even if unknown (show as "?")
			capacityStr := ""
			if data.Capacity > 0 {
				totalAssigned := data.EIPAssigned + data.SecondaryEIPs
				availableCapacity := data.Capacity - totalAssigned
				if availableCapacity < 0 {
					availableCapacity = 0 // Don't show negative
				}
				capacityChanged := prev != nil && (prev.Capacity != data.Capacity || prev.EIPAssigned != data.EIPAssigned || prev.SecondaryEIPs != data.SecondaryEIPs)
				capacityStr = fmt.Sprintf(", Capacity: %s/%d",
					formatValue(availableCapacity, capacityChanged, isTerminal),
					data.Capacity)
			} else {
				// Capacity unknown or 0, show as "?"
				capacityStr = ", Capacity: ?/?"
			}

			// Format node name with color based on status
			nodeNameStr := formatNodeName(data.Node, data.Status, isTerminal)

			fmt.Printf("%s%s - CPIC: %s/%s/%s, Primary EIPs: %s, Secondary EIPs: %s, Azure: %s/%s%s\n",
				clearLine, nodeNameStr, cpicSuccessStr, cpicPendingStr, cpicErrorStr,
				eipStr, secondaryEIPStr, azureEIPsStr, azureLBsStr, capacityStr)

			// Store current values for next iteration
			if !hasPrev {
				prevValues[data.Node] = &NodeEIPData{}
			}
			*prevValues[data.Node] = *data
		}

		// Calculate total cluster capacity from subnet CIDR
		// Get subnet from first node's annotation (assuming all nodes share same subnet)
		clusterCapacity := 0
		if len(nodeData) > 0 {
			firstNode := nodeData[0].Node
			nodeDataRaw, err := em.ocClient.RunCommand([]string{"get", "node", firstNode, "-o", "json"})
			if err == nil {
				if metadata, ok := nodeDataRaw["metadata"].(map[string]interface{}); ok {
					annotations, ok := metadata["annotations"].(map[string]interface{})
					if ok {
						egressIPConfig, ok := annotations["cloud.network.openshift.io/egress-ipconfig"].(string)
						if ok && egressIPConfig != "" {
							var configs []map[string]interface{}
							if err := json.Unmarshal([]byte(egressIPConfig), &configs); err == nil {
								for _, config := range configs {
									if ifaddr, ok := config["ifaddr"].(map[string]interface{}); ok {
										if ipv4, ok := ifaddr["ipv4"].(string); ok {
											// Parse CIDR (e.g., "10.0.2.0/23")
											clusterCapacity = calculateSubnetSize(ipv4)
											break // Use first interface's subnet
										}
									}
								}
							}
						}
					}
				}
			}
		}

		// Calculate assigned EIPs by summing per-node counts (to ensure consistency)
		// Total assigned = Primary + Secondary across all nodes
		totalAssignedEIPs := 0
		totalPrimaryEIPs := 0
		for _, data := range nodeData {
			totalAssignedEIPs += data.EIPAssigned + data.SecondaryEIPs
			totalPrimaryEIPs += data.EIPAssigned
		}

		// Validation: Sum of Primary EIPs across nodes should not exceed number of unique EIP resources
		// (A resource can be counted on multiple nodes if it has IPs on multiple nodes, but this is a sanity check)
		// Get unique EIP resource count for validation
		eipResourceCount := 0
		if eipData, err := em.ocClient.RunCommand([]string{"get", "eip", "--all-namespaces", "-o", "json"}); err == nil {
			if items, ok := eipData["items"].([]interface{}); ok {
				eipResourceCount = len(items)
			}
		}
		// Log warning if sum exceeds resource count (might indicate a bug, or legitimate multi-node resource distribution)
		if totalPrimaryEIPs > eipResourceCount && eipResourceCount > 0 {
			log.Printf("Warning: Sum of Primary EIPs (%d) exceeds unique EIP resource count (%d). This may indicate double-counting or legitimate multi-node resource distribution.", totalPrimaryEIPs, eipResourceCount)
		}

		// Format summary stats with highlighting
		configuredStr := formatValue(eipStats.Configured, prevSummary.initialized && prevSummary.configured != eipStats.Configured, isTerminal)
		successfulStr := formatValue(cpicStats.Success, prevSummary.initialized && prevSummary.successful != cpicStats.Success, isTerminal)
		assignedStr := formatValue(totalAssignedEIPs, prevSummary.initialized && prevSummary.assigned != totalAssignedEIPs, isTerminal)

		// Format malfunctioning EIPs - red if > 0
		malfunctionStr := fmt.Sprintf("%d", malfunctioningEIPs)
		if malfunctioningEIPs > 0 && isTerminal {
			malfunctionStr = fmt.Sprintf("\033[31;1m%d\033[0m", malfunctioningEIPs)
		}

		// Format overcommitted EIPs - yellow if > 0 (warning, not error)
		overcommittedStr := fmt.Sprintf("%d", overcommittedEIPs)
		if overcommittedEIPs > 0 && isTerminal {
			overcommittedStr = fmt.Sprintf("\033[33;1m%d\033[0m", overcommittedEIPs)
		}

		// Format CNCC stats with highlighting
		cnccRunningStr := formatValue(cnccStats.PodsRunning, prevSummary.initialized && prevSummary.cnccRunning != cnccStats.PodsRunning, isTerminal)
		cnccReadyStr := formatValue(cnccStats.PodsReady, prevSummary.initialized && prevSummary.cnccReady != cnccStats.PodsReady, isTerminal)
		cnccQueueStr := ""
		if cnccStats.QueueDepth > 0 {
			cnccQueueStr = fmt.Sprintf(", Queue: %d", cnccStats.QueueDepth)
		}

		// Format total capacity: show available/total (available = total - assigned)
		// Use totalAssignedEIPs for consistency with displayed value
		capacityStr := ""
		if clusterCapacity > 0 {
			availableCapacity := clusterCapacity - totalAssignedEIPs
			if availableCapacity < 0 {
				availableCapacity = 0 // Don't show negative
			}
			capacityStr = fmt.Sprintf(", Total Capacity: %d/%d", availableCapacity, clusterCapacity)
		}

		// Determine cluster summary color based on status
		// Check progress status first (before it gets updated below)
		noProgressDetected := false
		if progressTracker.baselineSet && progressTracker.iterationsWithoutProgress >= 10 {
			noProgressDetected = true
		}

		summaryLabel := "Cluster Summary:"
		if isTerminal {
			if cpicStats.Error > 0 {
				// Red if CPIC errors exist (same lighter red as CPIC error message)
				summaryLabel = fmt.Sprintf("\033[31;1m%s\033[0m", summaryLabel)
			} else if noProgressDetected {
				// Yellow if no progress in 10 iterations
				summaryLabel = fmt.Sprintf("\033[33m%s\033[0m", summaryLabel)
			} else {
				// Green if everything is OK
				summaryLabel = fmt.Sprintf("\033[32m%s\033[0m", summaryLabel)
			}
		}

		fmt.Printf("%s%s Configured EIPs: %s, Successful CPICs: %s, Assigned EIPs: %s, Malfunction EIPs: %s, Overcommitted EIPs: %s, CNCC: %s/%s%s%s\n",
			clearLine, summaryLabel, configuredStr, successfulStr, assignedStr, malfunctionStr, overcommittedStr, cnccRunningStr, cnccReadyStr, cnccQueueStr, capacityStr)

		// Track if we need to display error/warning messages
		hasErrorMessage := false
		var mismatchCount int
		var mismatches []EIPCPICMismatch // Store mismatches for detailed display later
		var unassignedCount int

		// Check for EIP/CPIC mismatches only after 10 iterations without progress
		if progressTracker.baselineSet && progressTracker.iterationsWithoutProgress >= 10 {
			detectedMismatches, err := em.ocClient.DetectEIPCPICMismatches()
			if err != nil {
				log.Printf("Warning: Failed to detect EIP/CPIC mismatches: %v", err)
			} else {
				// Always log mismatch stats (even if count is 0) so we can track when they're resolved
				mismatchCount = len(detectedMismatches)
				// Count mismatches by type
				nodeMismatches := 0
				missingInEIP := 0
				for _, m := range detectedMismatches {
					if m.MismatchType == "node_mismatch" {
						nodeMismatches++
					} else if m.MismatchType == "missing_in_eip" {
						missingInEIP++
					}
				}

				// Log mismatch statistics
				em.bufferedLogger.LogStats(timestamp, "eip_cpic_mismatches", map[string]interface{}{
					"total":          mismatchCount,
					"node_mismatch":  nodeMismatches,
					"missing_in_eip": missingInEIP,
				})

				if len(detectedMismatches) > 0 {
					mismatches = detectedMismatches

					// Show summary and detailed IPs (only displayed after 10 iterations without progress)
					var parts []string
					if nodeMismatches > 0 {
						parts = append(parts, fmt.Sprintf("%d node mismatch(es)", nodeMismatches))
					}
					if missingInEIP > 0 {
						parts = append(parts, fmt.Sprintf("%d in CPIC but not in EIP", missingInEIP))
					}

					fmt.Printf("%s\033[33;1m⚠️  EIP/CPIC Mismatch: %d IP(s) - %s\033[0m\n",
						clearLine, len(mismatches), strings.Join(parts, ", "))

					// Show detailed IPs
					if progressTracker.iterationsWithoutProgress > 0 {
						// Collect and format IPs for display (limit to first 20 for readability)
						type ipDisplay struct {
							ip      string
							display string
						}
						var nodeMismatchIPs []ipDisplay
						var missingInEIPIPs []ipDisplay
						maxDisplay := 20

						for _, m := range mismatches {
							if m.MismatchType == "node_mismatch" {
								if len(nodeMismatchIPs) < maxDisplay {
									nodeMismatchIPs = append(nodeMismatchIPs, ipDisplay{
										ip:      m.IP,
										display: fmt.Sprintf("%s (EIP: %s, CPIC: %s)", m.IP, m.EIPNode, m.CPICNode),
									})
								}
							} else if m.MismatchType == "missing_in_eip" {
								if len(missingInEIPIPs) < maxDisplay {
									var display string
									if m.EIPResource != "" {
										display = fmt.Sprintf("%s (%s → %s)", m.IP, m.EIPResource, m.CPICNode)
									} else {
										display = fmt.Sprintf("%s (→ %s)", m.IP, m.CPICNode)
									}
									missingInEIPIPs = append(missingInEIPIPs, ipDisplay{
										ip:      m.IP,
										display: display,
									})
								}
							}
						}

						// Sort by IP address for consistent output between iterations
						sort.Slice(nodeMismatchIPs, func(i, j int) bool {
							return nodeMismatchIPs[i].ip < nodeMismatchIPs[j].ip
						})
						sort.Slice(missingInEIPIPs, func(i, j int) bool {
							return missingInEIPIPs[i].ip < missingInEIPIPs[j].ip
						})

						// Display detailed IPs in a readable format
						if len(nodeMismatchIPs) > 0 {
							displayCount := len(nodeMismatchIPs)
							if nodeMismatches > maxDisplay {
								fmt.Printf("%s   Node mismatches (%d shown of %d):\n", clearLine, displayCount, nodeMismatches)
							} else {
								fmt.Printf("%s   Node mismatches:\n", clearLine)
							}
							for _, item := range nodeMismatchIPs {
								fmt.Printf("%s   - %s\n", clearLine, item.display)
							}
						}

						if len(missingInEIPIPs) > 0 {
							displayCount := len(missingInEIPIPs)
							if missingInEIP > maxDisplay {
								fmt.Printf("%s   Missing in EIP (%d shown of %d):\n", clearLine, displayCount, missingInEIP)
							} else {
								fmt.Printf("%s   Missing in EIP:\n", clearLine)
							}
							for _, item := range missingInEIPIPs {
								fmt.Printf("%s   - %s\n", clearLine, item.display)
							}
						}
					}

					hasErrorMessage = true
				}
			}
		}

		// Check for unassigned EIPs only after 10 iterations without progress
		// Calculate actual unassigned: Configured - Assigned (where Assigned = CPIC Success = totalAssignedEIPs)
		// Skip unassigned detection if we already have mismatches (to avoid duplicate reporting)
		actualUnassigned := eipStats.Configured - totalAssignedEIPs
		if actualUnassigned > 0 && progressTracker.baselineSet && progressTracker.iterationsWithoutProgress >= 10 && mismatchCount == 0 {
			unassignedEIPs, err := em.ocClient.DetectUnassignedEIPs()
			if err != nil {
				log.Printf("Warning: Failed to detect unassigned EIPs: %v", err)
			} else {
				// Limit to the actual unassigned count (Configured - Assigned)
				// Use totalAssignedEIPs (which matches CPIC Success) as source of truth
				displayUnassigned := unassignedEIPs
				if len(unassignedEIPs) > actualUnassigned {
					// Only show the first N unassigned IPs where N = actualUnassigned
					displayUnassigned = unassignedEIPs[:actualUnassigned]
				}

				if len(displayUnassigned) > 0 {
					unassignedCount = len(displayUnassigned)
					// Build display with IP addresses and reasons
					var parts []string
					for _, unassigned := range displayUnassigned {
						if unassigned.Resource != "" {
							parts = append(parts, fmt.Sprintf("%s (%s: %s)", unassigned.IP, unassigned.Resource, unassigned.Reason))
						} else {
							parts = append(parts, fmt.Sprintf("%s (%s)", unassigned.IP, unassigned.Reason))
						}
					}

					// Use actualUnassigned (Configured - totalAssignedEIPs) as the count
					fmt.Printf("%s\033[33;1m⚠️  Unassigned EIPs: %d IP(s) - %s\033[0m\n",
						clearLine, actualUnassigned, strings.Join(parts, ", "))
					hasErrorMessage = true
				}
			}
		}

		// Check for CPIC errors and display warning if errors are detected or increased
		if cpicStats.Error > 0 {
			// Always display error message when errors are present (so it persists on screen)
			fmt.Printf("%s\033[31;1m⚠️  CPIC Error Detected: %d error(s) found. Please check CNCC logs in OpenShift: stern -n openshift-cloud-network-config-controller cloud-network-config-controller.\033[0m\n",
				clearLine, cpicStats.Error)
			hasErrorMessage = true
			// Reset progress tracker when errors are present (we don't want to show OVN-Kube message)
			progressTracker.iterationsWithoutProgress = 0
			progressTracker.baselineSet = false
			progressTracker.warningShown = false
		} else {
			// Check for progress in EIP assignment and CPIC status
			if !progressTracker.baselineSet {
				// Set baseline for progress tracking (use totalAssignedEIPs for consistency)
				progressTracker.baselineEIPAssigned = totalAssignedEIPs
				progressTracker.baselineCPICSuccess = cpicStats.Success
				progressTracker.baselineCPICPending = cpicStats.Pending
				for _, data := range nodeData {
					progressTracker.baselineNodeEIPs[data.Node] = data.EIPAssigned
				}
				progressTracker.baselineSet = true
				progressTracker.iterationsWithoutProgress = 0
				progressTracker.warningShown = false
			} else {
				// Check if there's been any progress
				progressMade := false

				// Check EIP assignment progress (use totalAssignedEIPs for consistency)
				if totalAssignedEIPs > progressTracker.baselineEIPAssigned {
					progressMade = true
				}

				// Check CPIC success progress
				if cpicStats.Success > progressTracker.baselineCPICSuccess {
					progressMade = true
				}

				// Check CPIC pending reduction
				if cpicStats.Pending < progressTracker.baselineCPICPending {
					progressMade = true
				}

				// Check node-level EIP assignment progress
				for _, data := range nodeData {
					if baselineEIP, exists := progressTracker.baselineNodeEIPs[data.Node]; exists {
						if data.EIPAssigned > baselineEIP {
							progressMade = true
							break
						}
					} else {
						// New node detected, count as progress
						progressMade = true
						break
					}
				}

				if progressMade {
					// Progress detected, reset counter and update baseline (use totalAssignedEIPs for consistency)
					progressTracker.iterationsWithoutProgress = 0
					progressTracker.warningShown = false
					progressTracker.baselineEIPAssigned = totalAssignedEIPs
					progressTracker.baselineCPICSuccess = cpicStats.Success
					progressTracker.baselineCPICPending = cpicStats.Pending
					for _, data := range nodeData {
						progressTracker.baselineNodeEIPs[data.Node] = data.EIPAssigned
					}
				} else {
					// No progress, increment counter
					progressTracker.iterationsWithoutProgress++

					// If 10 iterations without progress and no CPIC errors, show OVN-Kube warning (once per baseline)
					if progressTracker.iterationsWithoutProgress >= 10 && !progressTracker.warningShown {
						// Print warning as part of the overwritable output block
						fmt.Printf("%s\033[33;1m⚠️  No progress detected in 10 iterations. Please check OVN-Kube logs and restart pods in openshift-ovn-kubernetes namespace:\033[0m\n",
							clearLine)
						fmt.Printf("%s   stern -n openshift-ovn-kubernetes ovnkube-control-plane.\n", clearLine)
						fmt.Printf("%s   stern -n openshift-ovn-kubernetes ovnkube-node.\n", clearLine)
						fmt.Printf("%s   oc delete pods -n openshift-ovn-kubernetes -l app=ovnkube-control-plane\n", clearLine)
						fmt.Printf("%s   oc delete pods -n openshift-ovn-kubernetes -l app=ovnkube-node\n", clearLine)
						hasErrorMessage = true
						progressTracker.warningShown = true
					}
				}
			}
		}

		// Store current summary for next iteration (use totalAssignedEIPs for consistency)
		prevSummary.configured = eipStats.Configured
		prevSummary.successful = cpicStats.Success
		prevSummary.assigned = totalAssignedEIPs
		prevSummary.cpicError = cpicStats.Error
		prevSummary.cnccRunning = cnccStats.PodsRunning
		prevSummary.cnccReady = cnccStats.PodsReady
		prevSummary.initialized = true

		// Update count of lines printed (timestamp + nodes + 1 summary line + optional error message)
		// After printing N lines with \n, cursor is on line N+1 (blank line)
		linesPrinted = 1 + len(nodeData) + 1 // timestamp + nodes + summary
		if hasErrorMessage {
			// Add lines for error/warning messages
			if mismatchCount > 0 {
				linesPrinted += 1 // EIP/CPIC mismatch summary (1 line)
				// Add lines for detailed IP display if shown (after 10 iterations without progress)
				if progressTracker.baselineSet && progressTracker.iterationsWithoutProgress >= 10 {
					// Count how many detailed lines will be printed
					nodeMismatches := 0
					missingInEIP := 0
					for _, m := range mismatches {
						if m.MismatchType == "node_mismatch" {
							nodeMismatches++
						} else if m.MismatchType == "missing_in_eip" {
							missingInEIP++
						}
					}
					if nodeMismatches > 0 {
						linesPrinted += 1 // Header line
						displayCount := nodeMismatches
						if displayCount > 20 {
							displayCount = 20
						}
						linesPrinted += displayCount // IP lines
					}
					if missingInEIP > 0 {
						linesPrinted += 1 // Header line
						displayCount := missingInEIP
						if displayCount > 20 {
							displayCount = 20
						}
						linesPrinted += displayCount // IP lines
					}
				}
			}
			if unassignedCount > 0 {
				linesPrinted += 1 // Unassigned EIPs warning (1 line)
			}
			if cpicStats.Error > 0 {
				linesPrinted += 1 // CPIC error message (1 line)
			} else if progressTracker.iterationsWithoutProgress >= 10 && progressTracker.warningShown {
				linesPrinted += 5 // OVN-Kube warning (5 lines: header + 4 commands)
			}
		}

		// Flush stdout to ensure output is displayed immediately
		os.Stdout.Sync()

		// Log aggregated cluster-wide EIP summary (errors go to stderr, won't affect stdout)
		if err := em.LogClusterSummary(timestamp, nodeData); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating cluster summary: %v\n", err)
		}

		// Flush all buffered logs (errors go to stderr, won't affect stdout)
		if err := em.bufferedLogger.FlushAll(); err != nil {
			fmt.Fprintf(os.Stderr, "Error flushing logs: %v\n", err)
		}

		// Check if monitoring should continue
		if !em.ShouldContinueMonitoring(eipStats, cpicStats, overcommittedEIPs) {
			fmt.Printf("\n") // Add final newline
			break
		}

		time.Sleep(1 * time.Second)
	}

	log.Println("Monitoring complete - all EIPs assigned and CPIC issues resolved")
	return nil
}

// formatValue formats a value with highlighting if it changed
func formatValue(value int, changed bool, isTerminal bool) string {
	if !isTerminal || !changed {
		return fmt.Sprintf("%d", value)
	}
	// Use yellow/bright yellow for changed values
	return fmt.Sprintf("\033[33;1m%d\033[0m", value) // Yellow, bold
}

// formatValueError formats a value with red highlighting if it changed (for errors)
func formatValueError(value int, changed bool, isTerminal bool) string {
	if !isTerminal {
		return fmt.Sprintf("%d", value)
	}
	// Always highlight errors in red if they exist, or red if changed
	if value > 0 {
		if changed {
			return fmt.Sprintf("\033[31;1m%d\033[0m", value) // Red, bold (changed)
		}
		return fmt.Sprintf("\033[31m%d\033[0m", value) // Red (existing)
	}
	// If value is 0 and changed (decreased), show normally
	if changed {
		return fmt.Sprintf("\033[32;1m%d\033[0m", value) // Green, bold (error resolved)
	}
	return fmt.Sprintf("%d", value)
}

// formatNodeName formats a node name with color based on status
func formatNodeName(nodeName string, status NodeStatus, isTerminal bool) string {
	if !isTerminal {
		return nodeName
	}

	switch status {
	case NodeStatusReady:
		return fmt.Sprintf("\033[32m%s\033[0m", nodeName) // Green
	case NodeStatusSchedulingDisabled:
		return fmt.Sprintf("\033[33m%s\033[0m", nodeName) // Yellow
	case NodeStatusNotReady:
		return fmt.Sprintf("\033[31m%s\033[0m", nodeName) // Red
	default:
		return nodeName // Unknown status, no color
	}
}

// DataProcessor handles log merging
type DataProcessor struct {
	baseDir string
	logsDir string
	dataDir string
}

func NewDataProcessor(baseDir string) *DataProcessor {
	return &DataProcessor{
		baseDir: baseDir,
		logsDir: filepath.Join(baseDir, "logs"),
		dataDir: filepath.Join(baseDir, "data"),
	}
}

func (dp *DataProcessor) MergeLogs() error {
	log.Println("Starting log merge process...")

	if _, err := os.Stat(dp.logsDir); os.IsNotExist(err) {
		return &EIPToolkitError{Message: fmt.Sprintf("Logs directory %s does not exist", dp.logsDir)}
	}

	logFiles, err := filepath.Glob(filepath.Join(dp.logsDir, "*.log"))
	if err != nil {
		return err
	}

	if len(logFiles) == 0 {
		return &EIPToolkitError{Message: fmt.Sprintf("No log files found in %s", dp.logsDir)}
	}

	log.Printf("Found %d log files", len(logFiles))

	// Get unique node names
	nodeSet := make(map[string]bool)
	for _, logFile := range logFiles {
		filename := filepath.Base(logFile)
		if !strings.HasPrefix(filename, "ocp_") && !strings.HasPrefix(filename, "azure_") {
			if idx := strings.Index(filename, "_"); idx > 0 {
				nodeName := filename[:idx]
				nodeSet[nodeName] = true
			}
		}
	}

	nodes := make([]string, 0, len(nodeSet))
	for node := range nodeSet {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)

	if len(nodes) == 0 {
		log.Println("No node-specific log files found")
	}

	// Process each file type
	fileMappings := map[string]string{
		"ocp_cpic_success.log": "ocp_cpic_success.dat",
		"ocp_cpic_pending.log": "ocp_cpic_pending.dat",
		"ocp_cpic_error.log":   "ocp_cpic_error.dat",
		"ocp_eip_assigned.log": "ocp_eip_assigned.dat",
		"azure_eips.log":       "azure_eips.dat",
		"azure_lbs.log":        "azure_lbs.dat",
	}

	for logSuffix, datFilename := range fileMappings {
		dataFile := filepath.Join(dp.dataDir, datFilename)
		outFile, err := os.Create(dataFile)
		if err != nil {
			return err
		}

		for _, node := range nodes {
			logFile := filepath.Join(dp.logsDir, fmt.Sprintf("%s_%s", node, logSuffix))
			if _, err := os.Stat(logFile); err == nil {
				fmt.Fprintf(outFile, "\"%s\"\n", node)

				inFile, err := os.Open(logFile)
				if err != nil {
					outFile.Close()
					return err
				}

				buf := make([]byte, 1024)
				for {
					n, err := inFile.Read(buf)
					if n > 0 {
						outFile.Write(buf[:n])
					}
					if err != nil {
						break
					}
				}
				inFile.Close()
				fmt.Fprintf(outFile, "\n\n")
			}
		}
		outFile.Close()
	}

	log.Println("Log merge completed successfully")
	return nil
}

// PlotGenerator handles plot generation
type PlotGenerator struct {
	baseDir  string
	dataDir  string
	plotsDir string
}

func NewPlotGenerator(baseDir string) *PlotGenerator {
	return &PlotGenerator{
		baseDir:  baseDir,
		dataDir:  filepath.Join(baseDir, "data"),
		plotsDir: filepath.Join(baseDir, "plots"),
	}
}

// parseDataFile parses a .dat file and returns node data with timestamps and values
func (pg *PlotGenerator) parseDataFile(filename string) (map[string][]DataPoint, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	nodeData := make(map[string][]DataPoint)
	var currentNode string
	var points []DataPoint

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			// Empty line separates nodes
			if currentNode != "" && len(points) > 0 {
				nodeData[currentNode] = points
				points = []DataPoint{}
			}
			currentNode = ""
			continue
		}

		// Check if line is a node name (in quotes)
		if strings.HasPrefix(line, `"`) && strings.HasSuffix(line, `"`) {
			// Save previous node's data
			if currentNode != "" && len(points) > 0 {
				nodeData[currentNode] = points
			}
			// Extract node name
			currentNode = strings.Trim(line, `"`)
			points = []DataPoint{}
			continue
		}

		// Parse timestamp and value
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			timestampStr := parts[0]
			valueStr := parts[1]

			value, err := strconv.ParseFloat(valueStr, 64)
			if err != nil {
				continue // Skip invalid lines
			}

			// Try parsing timestamp in multiple formats
			var t time.Time
			var parseErr error

			// Try RFC3339 format first (e.g., "2025-11-04T17:05:42+01:00")
			t, parseErr = time.Parse(time.RFC3339, timestampStr)
			if parseErr != nil {
				// Try YYMMDD_HHMMSS format (e.g., "251104_170542")
				t, parseErr = time.Parse("060102_150405", timestampStr)
				if parseErr != nil {
					// Try RFC3339 without timezone (e.g., "2025-11-04T17:05:42Z")
					t, parseErr = time.Parse("2006-01-02T15:04:05Z", timestampStr)
					if parseErr != nil {
						continue // Skip lines with unparseable timestamps
					}
				}
			}

			points = append(points, DataPoint{
				Time:  t,
				Value: value,
			})
		}
	}

	// Save last node's data
	if currentNode != "" && len(points) > 0 {
		nodeData[currentNode] = points
	}

	return nodeData, scanner.Err()
}

type DataPoint struct {
	Time  time.Time
	Value float64
}

func (pg *PlotGenerator) GenerateAllPlots() error {
	log.Println("Starting plot generation...")

	// Ensure plots directory exists
	if err := os.MkdirAll(pg.plotsDir, 0755); err != nil {
		return err
	}

	dataFiles, err := filepath.Glob(filepath.Join(pg.dataDir, "*.dat"))
	if err != nil {
		return err
	}

	if len(dataFiles) == 0 {
		return &EIPToolkitError{Message: "No .dat files found for plotting"}
	}

	log.Printf("Found %d data files. Generating plots...", len(dataFiles))

	for _, dataFile := range dataFiles {
		baseName := filepath.Base(dataFile)
		plotName := strings.TrimSuffix(baseName, ".dat") + ".png"
		plotPath := filepath.Join(pg.plotsDir, plotName)

		if err := pg.generatePlot(dataFile, plotPath, baseName); err != nil {
			log.Printf("Warning: Failed to generate plot for %s: %v", baseName, err)
			continue
		}

		log.Printf("Generated plot: %s", plotPath)
	}

	log.Println("Plot generation complete")
	return nil
}

func (pg *PlotGenerator) generatePlot(dataFile, plotPath, title string) error {
	nodeData, err := pg.parseDataFile(dataFile)
	if err != nil {
		return err
	}

	if len(nodeData) == 0 {
		return fmt.Errorf("no data found in file")
	}

	p := plot.New()
	p.Title.Text = title
	p.X.Label.Text = "Time"
	p.Y.Label.Text = "Value"
	p.X.Tick.Marker = plot.TimeTicks{Format: "15:04:05"}
	p.Legend.Top = true

	// Color palette for different nodes
	colors := []string{"blue", "red", "green", "orange", "purple", "brown", "pink", "gray"}

	// Sort nodes for consistent ordering
	sortedNodes := make([]string, 0, len(nodeData))
	for node := range nodeData {
		if len(nodeData[node]) > 0 {
			sortedNodes = append(sortedNodes, node)
		}
	}
	sort.Strings(sortedNodes)

	colorIdx := 0
	for _, node := range sortedNodes {
		points := nodeData[node]

		// Convert to plotter.XYs
		pts := make(plotter.XYs, len(points))
		for i, point := range points {
			pts[i].X = float64(point.Time.Unix())
			pts[i].Y = point.Value
		}

		line, err := plotter.NewLine(pts)
		if err != nil {
			return err
		}

		colorName := colors[colorIdx%len(colors)]
		line.Color = getColor(colorName)
		line.Width = vg.Points(1.5)

		p.Add(line)
		p.Legend.Add(node, line)

		colorIdx++
	}

	// Save plot
	if err := p.Save(10*vg.Inch, 6*vg.Inch, plotPath); err != nil {
		return err
	}

	return nil
}

// getColor converts a color name to a color.Color
func getColor(name string) color.Color {
	switch strings.ToLower(name) {
	case "blue":
		return color.RGBA{R: 0, G: 0, B: 255, A: 255}
	case "red":
		return color.RGBA{R: 255, G: 0, B: 0, A: 255}
	case "green":
		return color.RGBA{R: 0, G: 255, B: 0, A: 255}
	case "orange":
		return color.RGBA{R: 255, G: 165, B: 0, A: 255}
	case "purple":
		return color.RGBA{R: 128, G: 0, B: 128, A: 255}
	case "brown":
		return color.RGBA{R: 165, G: 42, B: 42, A: 255}
	case "pink":
		return color.RGBA{R: 255, G: 192, B: 203, A: 255}
	case "gray":
		return color.RGBA{R: 128, G: 128, B: 128, A: 255}
	default:
		return color.RGBA{R: 0, G: 0, B: 0, A: 255}
	}
}

// Main CLI
var (
	outputDirVar string
)

func validateEnvironment() (string, string, error) {
	subscription := os.Getenv("AZ_SUBSCRIPTION")
	resourceGroup := os.Getenv("AZ_RESOURCE_GROUP")

	if subscription == "" {
		return "", "", &EIPToolkitError{Message: "AZ_SUBSCRIPTION environment variable not set"}
	}
	if resourceGroup == "" {
		return "", "", &EIPToolkitError{Message: "AZ_RESOURCE_GROUP environment variable not set"}
	}

	return subscription, resourceGroup, nil
}

func cmdMonitor() error {
	subscriptionID, resourceGroup, err := validateEnvironment()
	if err != nil {
		return err
	}

	// Check if monitoring is needed BEFORE creating directories
	ocClient := NewOpenShiftClient()
	eipStats, err := ocClient.GetEIPStats()
	if err != nil {
		return err
	}

	cpicStats, err := ocClient.GetCPICStats()
	if err != nil {
		return err
	}

	// Create a temporary monitor just for the check
	tempMonitor := &EIPMonitor{ocClient: ocClient}
	// Get overcommitted count for the check
	overcommittedEIPs, err := ocClient.CountOvercommittedEIPObjects()
	if err != nil {
		overcommittedEIPs = 0 // Default to 0 if we can't determine
	}
	if !tempMonitor.ShouldContinueMonitoring(eipStats, cpicStats, overcommittedEIPs) {
		log.Println("No monitoring needed - all EIPs properly configured")
		return nil
	}

	// Only create directories if monitoring is actually needed
	timestamp := time.Now().Format("060102_150405")
	var outputDir string
	if outputDirVar != "" {
		// Append timestamped directory to user-specified path
		outputDir = filepath.Join(outputDirVar, timestamp)
	} else {
		// Create run directory in temp directory
		tempBase := filepath.Join(os.TempDir(), "eip-toolkit")
		if err := os.MkdirAll(tempBase, 0755); err != nil {
			return fmt.Errorf("failed to create temp base directory: %w", err)
		}
		outputDir = filepath.Join(tempBase, timestamp)
	}

	monitor, err := NewEIPMonitor(outputDir, subscriptionID, resourceGroup)
	if err != nil {
		return err
	}

	log.Printf("Output directory: %s", outputDir)
	return monitor.MonitorLoop()
}

func cmdMerge(directory string) error {
	if _, err := os.Stat(directory); os.IsNotExist(err) {
		return &EIPToolkitError{Message: fmt.Sprintf("Directory %s does not exist", directory)}
	}

	processor := NewDataProcessor(directory)
	return processor.MergeLogs()
}

func cmdPlot(directory string) error {
	if _, err := os.Stat(directory); os.IsNotExist(err) {
		return &EIPToolkitError{Message: fmt.Sprintf("Directory %s does not exist", directory)}
	}

	plotter := NewPlotGenerator(directory)
	return plotter.GenerateAllPlots()
}

func cmdAll() error {
	subscriptionID, resourceGroup, err := validateEnvironment()
	if err != nil {
		return err
	}

	log.Println("🚀 Starting Complete EIP Pipeline: Monitor → Merge → Plot")

	// Phase 1: Monitor
	log.Println("📊 Phase 1: Starting EIP Monitoring...")

	// Check if monitoring is needed BEFORE creating directories
	ocClient := NewOpenShiftClient()
	eipStats, err := ocClient.GetEIPStats()
	if err != nil {
		return err
	}

	cpicStats, err := ocClient.GetCPICStats()
	if err != nil {
		return err
	}

	// Create a temporary monitor just for the check
	tempMonitor := &EIPMonitor{ocClient: ocClient}
	// Get overcommitted count for the check
	overcommittedEIPs, err := ocClient.CountOvercommittedEIPObjects()
	if err != nil {
		overcommittedEIPs = 0 // Default to 0 if we can't determine
	}
	if !tempMonitor.ShouldContinueMonitoring(eipStats, cpicStats, overcommittedEIPs) {
		log.Println("No monitoring needed - pipeline complete")
		return nil
	}

	// Only create directories if monitoring is actually needed
	timestamp := time.Now().Format("060102_150405")
	var outputDir string
	if outputDirVar != "" {
		// Append timestamped directory to user-specified path
		outputDir = filepath.Join(outputDirVar, timestamp)
	} else {
		// Create run directory in temp directory
		tempBase := filepath.Join(os.TempDir(), "eip-toolkit")
		if err := os.MkdirAll(tempBase, 0755); err != nil {
			return fmt.Errorf("failed to create temp base directory: %w", err)
		}
		outputDir = filepath.Join(tempBase, timestamp)
	}

	monitor, err := NewEIPMonitor(outputDir, subscriptionID, resourceGroup)
	if err != nil {
		return err
	}

	log.Printf("Output directory: %s", outputDir)
	if err := monitor.MonitorLoop(); err != nil {
		return err
	}
	log.Println("✅ Phase 1 Complete: Monitoring finished")

	// Phase 2: Merge
	log.Println("🔄 Phase 2: Starting Log Merge...")
	processor := NewDataProcessor(outputDir)
	if err := processor.MergeLogs(); err != nil {
		return err
	}
	log.Println("✅ Phase 2 Complete: Log merge finished")

	// Phase 3: Plot
	log.Println("📈 Phase 3: Starting Plot Generation...")
	plotter := NewPlotGenerator(outputDir)
	if err := plotter.GenerateAllPlots(); err != nil {
		return err
	}
	log.Println("✅ Phase 3 Complete: Plot generation finished")

	log.Println("🎉 PIPELINE COMPLETE! 🎉")
	log.Printf("📁 All outputs saved in: %s", outputDir)
	log.Printf("📝 Raw logs: %s/logs/*.log", outputDir)
	log.Printf("📊 Data files: %s/data/*.dat", outputDir)
	log.Printf("📈 Plots: %s/plots/*.png", outputDir)

	return nil
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "eip-toolkit",
		Short: "EIP Toolkit - Monitor, analyze, and visualize ARO EIP assignments",
	}

	var monitorCmd = &cobra.Command{
		Use:   "monitor",
		Short: "Monitor EIP and CPIC status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdMonitor()
		},
	}
	monitorCmd.Flags().StringVarP(&outputDirVar, "output-dir", "o", "", "Output base directory (timestamped subdirectory will be created; default: temp directory)")

	var mergeCmd = &cobra.Command{
		Use:   "merge [directory]",
		Short: "Merge log files into data files",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdMerge(args[0])
		},
	}

	var plotCmd = &cobra.Command{
		Use:   "plot [directory]",
		Short: "Generate plots from data files",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdPlot(args[0])
		},
	}

	var allCmd = &cobra.Command{
		Use:   "all",
		Short: "Run complete pipeline: monitor → merge → plot",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdAll()
		},
	}
	allCmd.Flags().StringVarP(&outputDirVar, "output-dir", "o", "", "Output base directory (timestamped subdirectory will be created; default: temp directory)")

	var monitorAsyncCmd = &cobra.Command{
		Use:   "monitor-async",
		Short: "Monitor EIP and CPIC status with async optimization",
		RunE: func(cmd *cobra.Command, args []string) error {
			// In Go, goroutines provide parallelization, so this is the same as monitor
			return cmdMonitor()
		},
	}
	monitorAsyncCmd.Flags().StringVarP(&outputDirVar, "output-dir", "o", "", "Output base directory (timestamped subdirectory will be created; default: temp directory)")

	var mergeOptimizedCmd = &cobra.Command{
		Use:   "merge-optimized [directory]",
		Short: "Optimized merge using pandas",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// In Go, the merge is already optimized
			return cmdMerge(args[0])
		},
	}

	var allOptimizedCmd = &cobra.Command{
		Use:   "all-optimized",
		Short: "Run complete optimized pipeline",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdAll()
		},
	}
	allOptimizedCmd.Flags().StringVarP(&outputDirVar, "output-dir", "o", "", "Output base directory (timestamped subdirectory will be created; default: temp directory)")

	rootCmd.AddCommand(monitorCmd, mergeCmd, plotCmd, allCmd, monitorAsyncCmd, mergeOptimizedCmd, allOptimizedCmd)

	if err := rootCmd.Execute(); err != nil {
		if _, ok := err.(*EIPToolkitError); ok {
			log.Printf("Error: %v", err)
		} else {
			log.Printf("Unexpected error: %v", err)
		}
		os.Exit(1)
	}
}
