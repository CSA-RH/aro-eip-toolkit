package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// runOC executes oc command and returns JSON result
func runOC(cmd []string) (map[string]interface{}, error) {
	args := append([]string{}, cmd...)
	cmdObj := exec.Command("oc", args...)
	output, err := cmdObj.Output()
	if err != nil {
		return nil, fmt.Errorf("oc command failed: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return result, nil
}

// runAZ executes az command and returns JSON result
func runAZ(cmd []string) (interface{}, error) {
	subscription := os.Getenv("AZ_SUBSCRIPTION")
	if subscription == "" {
		return nil, fmt.Errorf("AZ_SUBSCRIPTION environment variable not set")
	}

	args := append([]string{}, cmd...)
	args = append(args, "--subscription", subscription)
	cmdObj := exec.Command("az", args...)
	output, err := cmdObj.Output()
	if err != nil {
		return nil, fmt.Errorf("az command failed: %w", err)
	}

	var result interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return result, nil
}

// getEIPStats returns assigned and configured EIP counts
func getEIPStats() (int, int, error) {
	data, err := runOC([]string{"get", "eip", "--all-namespaces", "-o", "json"})
	if err != nil {
		return 0, 0, err
	}

	items, ok := data["items"].([]interface{})
	if !ok {
		return 0, 0, fmt.Errorf("invalid items format")
	}

	// Count configured EIPs: sum up the number of IPs in spec.egressIPs for each EIP resource
	// Each EIP resource can have multiple IPs configured (e.g., 2 IPs per namespace)
	configured := 0
	assigned := 0

	for _, item := range items {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		// Count IPs in spec.egressIPs
		spec, ok := itemMap["spec"].(map[string]interface{})
		if ok {
			if egressIPs, ok := spec["egressIPs"].([]interface{}); ok {
				configured += len(egressIPs)
			}
		}

		// Count assigned IPs from status.items
		status, ok := itemMap["status"].(map[string]interface{})
		if !ok {
			continue
		}

		statusItems, ok := status["items"].([]interface{})
		if ok {
			assigned += len(statusItems)
		}
	}

	return assigned, configured, nil
}

// getCPICStats returns successful CPIC count
func getCPICStats() (int, error) {
	data, err := runOC([]string{"get", "cloudprivateipconfig", "--all-namespaces", "-o", "json"})
	if err != nil {
		return 0, err
	}

	items, ok := data["items"].([]interface{})
	if !ok {
		return 0, fmt.Errorf("invalid items format")
	}

	success := 0

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
			if ok && reason == "CloudResponseSuccess" {
				success++
				break
			}
		}
	}

	return success, nil
}

// getNodes returns list of EIP-enabled nodes
func getNodes() ([]string, error) {
	cmd := exec.Command("oc", "get", "nodes", "-l", "k8s.ovn.org/egress-assignable=true", "-o", "name")
	output, err := cmd.Output()
	if err != nil {
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

	return nodes, nil
}

// getAzureNICStats returns secondary IPs and load balancer IPs for a node
func getAzureNICStats(node string) (int, int) {
	resourceGroup := os.Getenv("AZ_RESOURCE_GROUP")
	if resourceGroup == "" {
		return 0, 0
	}

	nicName := fmt.Sprintf("%s-nic", node)

	// Get IP configurations
	ipConfigsResult, err := runAZ([]string{"network", "nic", "show",
		"--resource-group", resourceGroup,
		"--name", nicName,
		"--query", "ipConfigurations[].privateIPAddress"})
	if err != nil {
		return 0, 0
	}

	ipConfigs, ok := ipConfigsResult.([]interface{})
	if !ok {
		return 0, 0
	}

	// Get load balancer associations
	lbConfigsResult, err := runAZ([]string{"network", "nic", "show",
		"--resource-group", resourceGroup,
		"--name", nicName,
		"--query", "ipConfigurations[].{pools:loadBalancerBackendAddressPools[].id}"})
	if err != nil {
		return len(ipConfigs) - 1, 0
	}

	lbConfigs, ok := lbConfigsResult.([]interface{})
	if !ok {
		return max(0, len(ipConfigs)-1), 0
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

	return secondaryIPs, secondaryLBIPs
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// monitor runs the main monitoring loop
func monitor() error {
	fmt.Println("Starting EIP monitoring...")

	nodes, err := getNodes()
	if err != nil {
		return err
	}
	fmt.Printf("Found EIP-enabled nodes: %v\n", nodes)

	for {
		timestamp := time.Now().Format("15:04:05")

		// Get global stats
		assigned, configured, err := getEIPStats()
		if err != nil {
			return err
		}

		cpicSuccess, err := getCPICStats()
		if err != nil {
			return err
		}

		// Get Azure stats for each node
		var azureStats []string
		for _, node := range nodes {
			azureEIPs, azureLBs := getAzureNICStats(node)
			azureStats = append(azureStats, fmt.Sprintf("%s:%d/%d", node, azureEIPs, azureLBs))
		}

		fmt.Printf("[%s] EIPs: %d/%d, CPIC: %d, Azure: %s\n",
			timestamp, assigned, configured, cpicSuccess, strings.Join(azureStats, ", "))

		// Check if complete
		if assigned == configured && cpicSuccess == configured {
			fmt.Println("✅ All EIPs assigned and CPIC issues resolved!")
			break
		}

		time.Sleep(1 * time.Second)
	}

	return nil
}

func main() {
	if err := monitor(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

