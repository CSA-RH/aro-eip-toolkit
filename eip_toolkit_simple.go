package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	outputDir string
	logsDir   string
	dataDir   string
	plotsDir  string
)

// EIPToolkitError represents toolkit-specific errors
type EIPToolkitError struct {
	Message string
}

func (e *EIPToolkitError) Error() string {
	return e.Message
}

// setupDirectories creates necessary output directories
func setupDirectories(baseDir string) error {
	logsDir = filepath.Join(baseDir, "logs")
	dataDir = filepath.Join(baseDir, "data")
	plotsDir = filepath.Join(baseDir, "plots")

	for _, dir := range []string{logsDir, dataDir, plotsDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

// runOCCommand executes oc command and returns JSON result
func runOCCommand(cmd []string) (map[string]interface{}, error) {
	args := append([]string{}, cmd...)
	cmdObj := exec.Command("oc", args...)
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

	return result, nil
}

// runAZCommand executes az command and returns JSON result
func runAZCommand(cmd []string) (interface{}, error) {
	subscription := os.Getenv("AZ_SUBSCRIPTION")
	if subscription == "" {
		return nil, &EIPToolkitError{Message: "AZ_SUBSCRIPTION environment variable not set"}
	}

	args := append([]string{}, cmd...)
	args = append(args, "--subscription", subscription)
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

// getEIPStats returns EIP statistics
func getEIPStats() (map[string]int, error) {
	data, err := runOCCommand([]string{"get", "eip", "-o", "json"})
	if err != nil {
		return nil, err
	}

	items, ok := data["items"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid items format")
	}

	configured := len(items)
	assigned := 0
	unassigned := 0

	for _, item := range items {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		status, ok := itemMap["status"].(map[string]interface{})
		if !ok {
			unassigned++
			continue
		}

		statusItems, ok := status["items"].([]interface{})
		if ok && len(statusItems) > 0 {
			assigned++
		} else {
			unassigned++
		}
	}

	return map[string]int{
		"configured": configured,
		"assigned":   assigned,
		"unassigned": unassigned,
	}, nil
}

// getCPICStats returns CPIC statistics
func getCPICStats() (map[string]int, error) {
	data, err := runOCCommand([]string{"get", "cloudprivateipconfig", "-o", "json"})
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

	return map[string]int{
		"success": success,
		"pending": pending,
		"error":   errorCount,
	}, nil
}

// getNodes returns list of EIP-enabled nodes
func getNodes() ([]string, error) {
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

	return nodes, nil
}

// logStats writes statistics to log files
func logStats(timestamp, statsType string, stats map[string]int) error {
	for statName, value := range stats {
		logFile := filepath.Join(logsDir, fmt.Sprintf("%s_%s.log", statsType, statName))
		f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		fmt.Fprintf(f, "%s %d\n", timestamp, value)
		f.Close()
	}
	return nil
}

// runMonitor runs the main monitoring loop
func runMonitor() error {
	if err := setupDirectories(outputDir); err != nil {
		return err
	}

	log.Println("Starting EIP monitoring...")

	nodes, err := getNodes()
	if err != nil {
		return err
	}
	log.Printf("Found EIP-enabled nodes: %v", nodes)

	for {
		timestamp := time.Now().Format(time.RFC3339)

		// Get global statistics
		eipStats, err := getEIPStats()
		if err != nil {
			return err
		}

		cpicStats, err := getCPICStats()
		if err != nil {
			return err
		}

		// Log global statistics
		if err := logStats(timestamp, "ocp_eips", eipStats); err != nil {
			return err
		}
		if err := logStats(timestamp, "ocp_cpic", cpicStats); err != nil {
			return err
		}

		// Monitor individual nodes
		for _, node := range nodes {
			// Get node-specific EIP stats
			eipData, err := runOCCommand([]string{"get", "eip", "-o", "json"})
			if err != nil {
				log.Printf("Error monitoring node %s: %v", node, err)
				continue
			}

			eipAssigned := 0
			items, ok := eipData["items"].([]interface{})
			if ok {
				for _, item := range items {
					itemMap, ok := item.(map[string]interface{})
					if !ok {
						continue
					}

					status, ok := itemMap["status"].(map[string]interface{})
					if !ok {
						continue
					}

					statusItems, ok := status["items"].([]interface{})
					if !ok {
						continue
					}

					for _, statusItem := range statusItems {
						statusItemMap, ok := statusItem.(map[string]interface{})
						if !ok {
							continue
						}

						if statusItemMap["node"] == node {
							eipAssigned++
						}
					}
				}
			}

			// Get node-specific CPIC stats
			cpicData, err := runOCCommand([]string{"get", "cloudprivateipconfig", "-o", "json"})
			if err != nil {
				log.Printf("Error monitoring node %s: %v", node, err)
				continue
			}

			cpicSuccess := 0
			items, ok = cpicData["items"].([]interface{})
			if ok {
				for _, item := range items {
					itemMap, ok := item.(map[string]interface{})
					if !ok {
						continue
					}

					spec, ok := itemMap["spec"].(map[string]interface{})
					if !ok || spec["node"] != node {
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

						if reason, ok := condMap["reason"].(string); ok && reason == "CloudResponseSuccess" {
							cpicSuccess++
							break
						}
					}
				}
			}

			// Log node statistics
			if err := logStats(timestamp, fmt.Sprintf("%s_ocp_eip", node), map[string]int{"assigned": eipAssigned}); err != nil {
				log.Printf("Error logging stats for node %s: %v", node, err)
			}
			if err := logStats(timestamp, fmt.Sprintf("%s_ocp_cpic", node), map[string]int{"success": cpicSuccess}); err != nil {
				log.Printf("Error logging stats for node %s: %v", node, err)
			}

			log.Printf("%s - EIP: %d, CPIC: %d", node, eipAssigned, cpicSuccess)
		}

		// Check if monitoring should continue
		if eipStats["assigned"] == eipStats["configured"] && cpicStats["success"] == eipStats["configured"] {
			break
		}

		time.Sleep(1 * time.Second)
	}

	log.Println("Monitoring complete - all EIPs assigned and CPIC issues resolved")
	return nil
}

// mergeLogs merges log files into data files
func runMergeLogs() error {
	if err := setupDirectories(outputDir); err != nil {
		return err
	}

	log.Println("Merging log files...")

	// Get all log files
	logFiles, err := filepath.Glob(filepath.Join(logsDir, "*.log"))
	if err != nil {
		return err
	}

	if len(logFiles) == 0 {
		return &EIPToolkitError{Message: "No log files found"}
	}

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

	// Process each file type
	fileMappings := map[string]string{
		"ocp_cpic_success.log": "ocp_cpic_success.dat",
		"ocp_cpic_pending.log": "ocp_cpic_pending.dat",
		"ocp_cpic_error.log":   "ocp_cpic_error.dat",
		"ocp_eip_assigned.log": "ocp_eip_assigned.dat",
	}

	for logSuffix, datFilename := range fileMappings {
		dataFile := filepath.Join(dataDir, datFilename)
		outFile, err := os.Create(dataFile)
		if err != nil {
			return err
		}

		for _, node := range nodes {
			logFile := filepath.Join(logsDir, fmt.Sprintf("%s_%s", node, logSuffix))
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

	log.Println("Log merge completed")
	return nil
}

// createPlots generates plots from data files (placeholder - requires external plotting tool)
func runCreatePlots() error {
	if err := setupDirectories(outputDir); err != nil {
		return err
	}

	log.Println("Creating plots...")

	dataFiles, err := filepath.Glob(filepath.Join(dataDir, "*.dat"))
	if err != nil {
		return err
	}

	if len(dataFiles) == 0 {
		return &EIPToolkitError{Message: "No .dat files found for plotting"}
	}

	log.Printf("Found %d data files. Plotting requires external tools (gnuplot, matplotlib, etc.)", len(dataFiles))
	log.Println("Plot generation completed")
	return nil
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "eip-toolkit-simple",
		Short: "EIP Toolkit - Simple Version",
	}

	var monitorCmd = &cobra.Command{
		Use:   "monitor",
		Short: "Monitor EIP and CPIC status",
		RunE: func(cmd *cobra.Command, args []string) error {
			if outputDir == "" {
				timestamp := time.Now().Format("060102_150405")
				outputDir = filepath.Join("..", "runs", timestamp)
			}
			return runMonitor()
		},
	}

	var mergeCmd = &cobra.Command{
		Use:   "merge [directory]",
		Short: "Merge log files into data files",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			outputDir = args[0]
			return runMergeLogs()
		},
	}

	var plotCmd = &cobra.Command{
		Use:   "plot [directory]",
		Short: "Generate plots from data files",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			outputDir = args[0]
			return runCreatePlots()
		},
	}

	var allCmd = &cobra.Command{
		Use:   "all",
		Short: "Run complete pipeline: monitor → merge → plot",
		RunE: func(cmd *cobra.Command, args []string) error {
			if outputDir == "" {
				timestamp := time.Now().Format("060102_150405")
				outputDir = filepath.Join("..", "runs", timestamp)
			}

			fmt.Println("🚀 Starting Complete EIP Pipeline")
			fmt.Println("📊 Phase 1: Monitoring...")
			if err := runMonitor(); err != nil {
				return err
			}
			fmt.Println("✅ Phase 1 Complete")

			fmt.Println("🔄 Phase 2: Merging logs...")
			if err := runMergeLogs(); err != nil {
				return err
			}
			fmt.Println("✅ Phase 2 Complete")

			fmt.Println("📈 Phase 3: Creating plots...")
			if err := runCreatePlots(); err != nil {
				return err
			}
			fmt.Println("✅ Phase 3 Complete")

			fmt.Println("🎉 PIPELINE COMPLETE!")
			fmt.Printf("📁 Outputs saved in: %s\n", outputDir)
			return nil
		},
	}

	rootCmd.AddCommand(monitorCmd, mergeCmd, plotCmd, allCmd)

	if err := rootCmd.Execute(); err != nil {
		if _, ok := err.(*EIPToolkitError); ok {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "Unexpected error: %v\n", err)
		}
		os.Exit(1)
	}
}
