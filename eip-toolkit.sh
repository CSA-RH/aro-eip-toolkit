#!/usr/bin/env bash

#############################################################################
# EIP Toolkit - Unified script for EIP monitoring, log merging, and plotting
# 
# Combines functionality from:
# - aro-eip.sh: EIP monitoring and data collection
# - merge-logs.sh: Log file merging and data preparation
# - plot_series.sh: Graph generation from data files
#############################################################################

# Removed strict error handling to allow for better error messages
# set -euo pipefail

# Global variables
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

#############################################################################
# UTILITY FUNCTIONS
#############################################################################

# Show usage information
show_usage() {
    cat << EOF
EIP Toolkit - Unified EIP monitoring, log merging, and plotting tool

Usage: $0 <command> [options]

Commands:
  all, -a             Run complete pipeline: monitor → merge → plot
  monitor, -m         Monitor EIP and CPIC status
  merge, -g           Merge log files into data files
  plot, -p            Generate plots from data files
  help, -h            Show this help message

Options for 'all':
  No additional options required. Uses environment variables:
    AZ_SUBSCRIPTION     Azure subscription ID
    AZ_RESOURCE_GROUP   Azure resource group name

Options for 'monitor':
  No additional options required. Uses environment variables:
    AZ_SUBSCRIPTION     Azure subscription ID
    AZ_RESOURCE_GROUP   Azure resource group name

Options for 'merge':
  <log_directory>     Directory containing log files to merge

Options for 'plot':
  <data_directory>    Directory containing .dat files to plot

Examples:
  $0 all                        # Complete pipeline: monitor → merge → plot
  $0 monitor                    # Start EIP monitoring only
  $0 merge ../runs/231021_143022/  # Merge logs from specific run
  $0 plot ../runs/231021_143022/   # Generate plots from data files
  $0 help                       # Show this help

Environment Variables:
  AZ_SUBSCRIPTION     Required for monitoring mode
  AZ_RESOURCE_GROUP   Required for monitoring mode
EOF
}

# Generate ISO-8601 timestamp
timestamp() {
    TIMESTAMP=$(gdate --iso-8601=seconds)
}

#############################################################################
# EIP MONITORING FUNCTIONS (from aro-eip.sh)
#############################################################################

# Setup global variables and configuration for monitoring
setup_monitoring_variables() {
    # Generate unique string for this run
    runid=iteration_$(LC_ALL=C tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 8 | head -n 1)o
    TEMP_DIR="../runs"
    NOW=$(date +%y%m%d_%H%M%S)

    # Azure configuration
    AZ_SUB=$AZ_SUBSCRIPTION
    AZ_RG=$AZ_RESOURCE_GROUP

    # Get EIP-enabled nodes with error checking
    echo "Checking OpenShift permissions and EIP-enabled nodes..."
    if ! oc get nodes -l k8s.ovn.org/egress-assignable=true -o name >/dev/null 2>&1; then
        echo "Error: Cannot access OpenShift nodes. Possible issues:"
        echo "  1. Insufficient permissions to list nodes at cluster scope"
        echo "  2. Not connected to the correct OpenShift cluster"
        echo "  3. EIP labels may not exist in this cluster"
        echo ""
        echo "Current user: $(oc whoami 2>/dev/null || echo 'unknown')"
        echo "Current project: $(oc project -q 2>/dev/null || echo 'unknown')"
        echo ""
        echo "Please ensure you have cluster-admin permissions or ask your admin to grant node listing permissions."
        exit 1
    fi
    
    OC_EIP_NODES=$(oc get nodes -l k8s.ovn.org/egress-assignable=true -o name | sed -e 's/node\///g')
    
    if [[ -z "$OC_EIP_NODES" ]]; then
        echo "Warning: No EIP-enabled nodes found in the cluster"
        echo "This may mean:"
        echo "  1. EIP is not configured in this cluster"
        echo "  2. Nodes don't have the k8s.ovn.org/egress-assignable=true label"
        echo "  3. You may be connected to the wrong cluster"
        exit 1
    fi
    
    echo "Found EIP-enabled nodes: $OC_EIP_NODES"
}

# Get EIP statistics from OpenShift
get_eip_stats() {
    if ! oc get eip -o json >/dev/null 2>&1; then
        echo "Error: Cannot access EIP resources. This may mean:"
        echo "  1. EIP resources don't exist in this cluster"
        echo "  2. Insufficient permissions to access EIP resources"
        echo "  3. EIP feature is not installed/configured"
        exit 1
    fi
    
    OC_EIPS_ASSIGNED=$(oc get eip -o json | jq -r '[.items[] | select(.status.items | length != 0)] | length')
    OC_EIPS_UNASSIGNED=$(oc get eip -o json | jq '[.items[] | select(.status.items | length == 0)] | length')
    OC_EIPS_CONFIGURED=$(oc get eip -o json | jq -r '[.items[] | select(.spec.egressIP | length == 0)] | length')
}

# Get CPIC (CloudPrivateIPConfig) statistics from OpenShift
get_cpic_stats() {
    if ! oc get cloudprivateipconfig -o json >/dev/null 2>&1; then
        echo "Error: Cannot access CloudPrivateIPConfig resources. This may mean:"
        echo "  1. CloudPrivateIPConfig resources don't exist in this cluster"
        echo "  2. Insufficient permissions to access CloudPrivateIPConfig resources"
        echo "  3. This feature is not available in your OpenShift version"
        exit 1
    fi
    
    OC_CPIC_SUCCESS=$(oc get cloudprivateipconfig -o json | jq -r '[.items[] | select(.status.conditions[]?.reason == "CloudResponseSuccess")] | length')
    OC_CPIC_PENDING=$(oc get cloudprivateipconfig -o json | jq -r '[.items[] | select(.status.conditions[]?.reason == "CloudResponsePending")] | length')
    OC_CPIC_ERROR=$(oc get cloudprivateipconfig -o json | jq -r '[.items[] | select(.status.conditions[]?.reason == "CloudResponseError")] | length')
}

# Check if monitoring should continue and create output directory
should_continue_monitoring() {
    get_eip_stats
    get_cpic_stats
    
    echo "Configured EIPs: $OC_EIPS_CONFIGURED"
    echo "Successful CPICs: $OC_CPIC_SUCCESS"
    echo "Assigned EIPS: ${OC_EIPS_ASSIGNED}"
    
    if [[ "${OC_EIPS_CONFIGURED}" -ne "${OC_CPIC_SUCCESS}" ]]; then
        # Create main directory and subdirectories for organized output
        mkdir -p "${TEMP_DIR}/${NOW}/logs"
        mkdir -p "${TEMP_DIR}/${NOW}/data"
        mkdir -p "${TEMP_DIR}/${NOW}/plots"
        echo "Created output directories:"
        echo "  📁 Main: ${TEMP_DIR}/${NOW}"
        echo "  📝 Logs: ${TEMP_DIR}/${NOW}/logs"
        echo "  📊 Data: ${TEMP_DIR}/${NOW}/data"
        echo "  📈 Plots: ${TEMP_DIR}/${NOW}/plots"
        return 0  # Continue monitoring
    else
        echo "Exiting because configured EIPs does not differ from successful CPICs"
        return 1  # Stop monitoring
    fi
}

# Log global statistics to files
log_global_stats() {
    echo "$TIMESTAMP $OC_EIPS_CONFIGURED" >> ${TEMP_DIR}/${NOW}/logs/ocp_eips_configured.log
    echo "$TIMESTAMP $OC_EIPS_ASSIGNED" >> ${TEMP_DIR}/${NOW}/logs/ocp_eips_assigned.log
    echo "$TIMESTAMP $OC_EIPS_UNASSIGNED" >> ${TEMP_DIR}/${NOW}/logs/ocp_eips_unassigned.log
    echo "$TIMESTAMP $OC_CPIC_SUCCESS" >> ${TEMP_DIR}/${NOW}/logs/ocp_cpic_success.log
    echo "$TIMESTAMP $OC_CPIC_PENDING" >> ${TEMP_DIR}/${NOW}/logs/ocp_cpic_pending.log
    echo "$TIMESTAMP $OC_CPIC_ERROR" >> ${TEMP_DIR}/${NOW}/logs/ocp_cpic_error.log
}

# Get statistics for a specific node
get_node_stats() {
    local AZ_NODE=$1
    
    # OpenShift CPIC stats for the node
    OC_CPIC_NODE_SUCCESS=$(oc get cloudprivateipconfig -o json | jq -r '[.items[] | select(.spec.node == '\"$AZ_NODE\"' and .status.conditions[]?.reason == "CloudResponseSuccess")] | length')
    OC_CPIC_NODE_PENDING=$(oc get cloudprivateipconfig -o json | jq -r '[.items[] | select(.spec.node == '\"$AZ_NODE\"'and .status.conditions[]?.reason == "CloudResponsePending")] | length')
    OC_CPIC_NODE_ERROR=$(oc get cloudprivateipconfig -o json | jq -r '[.items[] | select(.spec.node == '\"$AZ_NODE\"' and .status.conditions[]?.reason == "CloudResponseError")] | length')
    
    # OpenShift EIP stats for the node
    OC_EIP_NODE_ASSIGNED=$(oc get eip -o json | jq -r '[.items[].status.items[]? | select(.node == '\"$AZ_NODE\"')] | length')
    
    # Azure NIC stats for the node
    AZ_NODE_IPS=$(az network nic show --resource-group ${AZ_RG} -n $AZ_NODE-nic --query "ipConfigurations[].privateIPAddress" -o json | jq -r '[.[]] |length')
    AZ_NODE_IP_LB=$(az network nic show --resource-group ${AZ_RG} -n $AZ_NODE-nic --query "ipConfigurations[].{pools:loadBalancerBackendAddressPools[].id}" -o json | jq -r '[.[] | select(.pools != null)] | length')
    
    # Calculate secondary IPs (exclude primary NIC)
    AZ_NODE_EIPS=$(echo $AZ_NODE_IPS - 1 | bc)
    AZ_NODE_SEC_IP_LBS=$(echo $AZ_NODE_IP_LB - 1 | bc)
}

# Log node-specific statistics
log_node_stats() {
    local AZ_NODE=$1
    
    echo "$TIMESTAMP $AZ_NODE_EIPS" >> ${TEMP_DIR}/${NOW}/logs/${AZ_NODE}_azure_eips.log
    echo "$TIMESTAMP $AZ_NODE_SEC_IP_LBS" >> ${TEMP_DIR}/${NOW}/logs/${AZ_NODE}_azure_lbs.log
    echo "$TIMESTAMP $OC_CPIC_NODE_SUCCESS" >> ${TEMP_DIR}/${NOW}/logs/${AZ_NODE}_ocp_cpic_success.log
    echo "$TIMESTAMP $OC_CPIC_NODE_PENDING" >> ${TEMP_DIR}/${NOW}/logs/${AZ_NODE}_ocp_cpic_pending.log
    echo "$TIMESTAMP $OC_CPIC_NODE_ERROR" >> ${TEMP_DIR}/${NOW}/logs/${AZ_NODE}_ocp_cpic_error.log
    echo "$TIMESTAMP $OC_EIP_NODE_ASSIGNED" >> ${TEMP_DIR}/${NOW}/logs/${AZ_NODE}_ocp_eip_assigned.log
}

# Monitor all nodes for EIP and CPIC status
monitor_nodes() {
    for AZ_NODE in ${OC_EIP_NODES[@]}; do
        timestamp
        
        # Get node statistics
        get_node_stats "$AZ_NODE"
        
        # Display node statistics
        echo "${TIMESTAMP} $AZ_NODE CPIC: $OC_CPIC_NODE_SUCCESS $OC_CPIC_NODE_PENDING $OC_CPIC_NODE_ERROR"
        echo "${TIMESTAMP} $AZ_NODE EIPS: $OC_EIP_NODE_ASSIGNED"
        echo "${TIMESTAMP} $AZ_NODE Azure: $AZ_NODE_EIPS $AZ_NODE_SEC_IP_LBS"
        
        # Log node statistics
        log_node_stats "$AZ_NODE"
    done
}

# Main monitoring loop - run until all EIPs are assigned and no CPIC issues
monitor_eips() {
    # Initial stats check
    get_eip_stats
    get_cpic_stats
    
    # Run until all EIPs assigned and no issues with CPIC
    while [ "${OC_EIPS_ASSIGNED}" -ne "${OC_EIPS_CONFIGURED}" ] || [ "${OC_CPIC_SUCCESS}" -ne "${OC_EIPS_CONFIGURED}" ]; do
        timestamp
        
        # Get updated statistics
        get_eip_stats
        get_cpic_stats
        
        # Display global statistics
        echo "${TIMESTAMP} Eips: $OC_EIPS_CONFIGURED $OC_EIPS_ASSIGNED $OC_EIPS_UNASSIGNED"
        echo "${TIMESTAMP} CPIC: $OC_CPIC_SUCCESS $OC_CPIC_PENDING $OC_CPIC_ERROR"
        
        # Log global statistics
        log_global_stats
        
        # Monitor individual nodes
        monitor_nodes
        
        sleep 1 
    done
}

#############################################################################
# LOG MERGING FUNCTIONS (from merge-logs.sh)
#############################################################################

# Validate log directory input
validate_log_input() {
    local logdir=$1
    
    if [[ -z "$logdir" ]]; then
        echo "Error: Log directory not specified"
        echo "Usage: $0 merge <log_directory>"
        exit 1
    fi
    
    if [[ ! -d "$logdir" ]]; then
        echo "Error: Directory '$logdir' does not exist"
        exit 1
    fi
    
    if [[ ! -r "$logdir" ]]; then
        echo "Error: Directory '$logdir' is not readable"
        exit 1
    fi
}

# Setup merge variables and configuration
setup_merge_variables() {
    # Define the node file types to process
    NODEFILES="ocp_eip_assigned ocp_cpic_pending ocp_cpic_error ocp_cpic_success azure_lbs azure_eips"
}

# Extract node names from log directory
get_nodes() {
    local logdir=$1
    
    # Convert to absolute path to handle relative paths correctly
    LOGDIR_ABS=$(cd "$logdir" && pwd)
    
    # Look for log files in the logs/ subdirectory if it exists, otherwise in main directory
    local logs_search_dir="$logdir"
    if [[ -d "$logdir/logs" ]]; then
        logs_search_dir="$logdir/logs"
        echo "Looking for log files in: $logs_search_dir"
    else
        echo "Looking for log files in: $logs_search_dir (no logs/ subdirectory found)"
    fi
    
    # Extract node names from files, excluding system log files
    NODES=$(ls "$logs_search_dir" 2>/dev/null | egrep -v '^(ocp|azure|eips|cpic)' | cut -f1 -d _ | sort -u)
    
    if [[ -z "$NODES" ]]; then
        echo "Warning: No node log files found in directory '$logs_search_dir'"
        return 1
    fi
    
    echo "Found nodes: $NODES"
    return 0
}

# Process a single node file combination
process_node_file() {
    local node=$1
    local nodefile=$2
    local base_dir=$3
    
    # Determine source and output paths
    local logs_dir="$base_dir"
    local data_dir="$base_dir"
    
    # Use logs/ subdirectory if it exists
    if [[ -d "$base_dir/logs" ]]; then
        logs_dir="$base_dir/logs"
    fi
    
    # Use data/ subdirectory if it exists, otherwise create it
    if [[ -d "$base_dir/data" ]] || mkdir -p "$base_dir/data" 2>/dev/null; then
        data_dir="$base_dir/data"
    fi
    
    local source_file="${logs_dir}/${node}_${nodefile}.log"
    local output_file="${data_dir}/${nodefile}.dat"
    
    # Check if source log file exists
    if [[ ! -f "$source_file" ]]; then
        echo "Warning: Log file '$source_file' not found, skipping..."
        return 1
    fi
    
    # Create/append to output data file
    touch "$output_file"
    echo "\"$node\"" >> "$output_file"
    awk 1 "$source_file" >> "$output_file"
    printf '\n\n' >> "$output_file"
    
    echo "Processed: $node -> $output_file"
}

# Main log merging function
merge_logs() {
    echo "Starting log merge process in directory: $LOGDIR_ABS"
    
    # Create data subdirectory if it doesn't exist
    mkdir -p "$LOGDIR_ABS/data"
    echo "Data files will be saved to: $LOGDIR_ABS/data"
    
    # Process each node and file type combination
    for NODE in ${NODES[@]}; do 
        echo "Processing node: $NODE"
        
        for NODEFILE in ${NODEFILES[@]}; do
            process_node_file "$NODE" "$NODEFILE" "$LOGDIR_ABS"
        done
    done
    
    echo "Log merge completed successfully"
}

#############################################################################
# PLOT GENERATION FUNCTIONS (from plot_series.sh)
#############################################################################

# Validate plot input arguments
validate_plot_input() {
    local data_dir=$1
    
    if [[ -z "$data_dir" ]]; then
        echo "Error: Data directory not specified"
        echo "Usage: $0 plot <data_directory>"
        exit 1
    fi
    
    if [[ ! -d "$data_dir" ]]; then
        echo "Error: Directory '$data_dir' does not exist"
        exit 1
    fi
    
    if [[ ! -r "$data_dir" ]]; then
        echo "Error: Directory '$data_dir' is not readable"
        exit 1
    fi
}

# Find all .dat files in the directory
get_dat_files() {
    local data_dir=$1
    
    # Convert to absolute path to handle relative paths correctly
    DATA_DIR_ABS=$(cd "$data_dir" && pwd)
    
    # Look for .dat files in the data/ subdirectory if it exists, otherwise in main directory
    local dat_search_dir="$DATA_DIR_ABS"
    if [[ -d "$DATA_DIR_ABS/data" ]]; then
        dat_search_dir="$DATA_DIR_ABS/data"
        echo "Looking for .dat files in: $dat_search_dir"
    else
        echo "Looking for .dat files in: $dat_search_dir (no data/ subdirectory found)"
    fi
    
    # Find all .dat files
    DAT_FILES=($(find "$dat_search_dir" -maxdepth 1 -name "*.dat" -type f))
    
    if [[ ${#DAT_FILES[@]} -eq 0 ]]; then
        echo "Warning: No .dat files found in directory '$dat_search_dir'"
        return 1
    fi
    
    echo "Found ${#DAT_FILES[@]} .dat files to process"
    return 0
}

# Normalize filename to create a readable title
normalize_title() {
    local filename=$1
    
    # Remove path and extension
    local basename=$(basename "$filename" .dat)
    
    # Replace underscores with spaces and capitalize words
    local title=$(echo "$basename" | sed 's/_/ /g' | sed 's/\b\w/\U&/g')
    
    # Handle common abbreviations and make them more readable
    title=$(echo "$title" | sed 's/Ocp/OpenShift/g')
    title=$(echo "$title" | sed 's/Eip/EIP/g')
    title=$(echo "$title" | sed 's/Cpic/CPIC/g')
    title=$(echo "$title" | sed 's/Lbs/Load Balancers/g')
    title=$(echo "$title" | sed 's/Azure/Azure/g')
    
    echo "$title"
}

# Generate a plot for a single data file
generate_plot() {
    local input_file=$1
    local title=$2
    
    # Determine the main project directory (go up from data/ if needed)
    local data_file_dir=$(dirname "$input_file")
    local main_dir="$data_file_dir"
    
    # If we're in a data/ subdirectory, go up one level for plots
    if [[ "$(basename "$data_file_dir")" == "data" ]]; then
        main_dir=$(dirname "$data_file_dir")
    fi
    
    local plots_dir="${main_dir}/plots"
    
    # Create plots directory if it doesn't exist
    mkdir -p "$plots_dir"
    
    # Generate output filename in the plots subdirectory
    local basename=$(basename "$input_file" .dat)
    local output_file="${plots_dir}/${basename}-plot.png"
    
    echo "Generating plot for: $input_file -> $output_file"
    echo "Title: $title"
    
    gnuplot <<-EOF
		# Create a 1680x1050 image using Arial, 12pt
		set terminal pngcairo enhanced font "arial,12" fontscale 1.0 size 1680, 1050
		
		# Set output file
		set output '$output_file'
		
		# Turn key off since we will be plotting many different series
		unset key
		
		# Tell gnuplot we are plotting time data formatted like Year-month-day
		set xdata time
		set timefmt "%Y-%m-%dT%H:%M:%S"
		
		set format x "%H:%M:%S"
		set xlabel "Time"
		set ylabel "Value"
		set title "$title"
		
		# Set colors for each segment we are drawing
		set style line 1 linewidth 3 linecolor rgb "green"
		set style line 2 linewidth 3 linecolor rgb "red"
		set style line 3 linewidth 3 linecolor rgb "blue"
		set style line 4 linewidth 3 linecolor rgb "violet"
		
		# Plot the input file using the line styles defined above
		plot for [i=0:*] '$input_file' i i u 1:2 w lines ls i+1
	EOF
    
    if [[ $? -eq 0 ]]; then
        echo "Successfully generated: $output_file"
    else
        echo "Error generating plot for: $input_file"
        return 1
    fi
}

# Process all .dat files in the directory
process_all_plot_files() {
    local processed=0
    local failed=0
    
    # Determine correct plots directory (should be in main directory, not data subdirectory)
    local main_dir="$DATA_DIR_ABS"
    if [[ -d "$DATA_DIR_ABS/data" ]] && [[ ! -f "$DATA_DIR_ABS"/*.dat ]]; then
        # If we have data/ subdirectory and no .dat files in main dir, main dir is correct
        main_dir="$DATA_DIR_ABS"
    fi
    
    local plots_dir="${main_dir}/plots"
    echo "Plots will be saved to: $plots_dir"
    echo ""
    
    for dat_file in "${DAT_FILES[@]}"; do
        # Generate normalized title
        local title=$(normalize_title "$dat_file")
        
        # Generate the plot
        if generate_plot "$dat_file" "$title"; then
            ((processed++))
        else
            ((failed++))
        fi
        
        echo "---"
    done
    
    echo "Processing complete:"
    echo "  Successfully processed: $processed files"
    echo "  Failed: $failed files"
    echo "  All plots saved to: $plots_dir"
}

#############################################################################
# MAIN COMMAND HANDLERS
#############################################################################

# Handle complete pipeline: monitor → merge → plot
cmd_all() {
    echo "🚀 Starting Complete EIP Pipeline: Monitor → Merge → Plot"
    echo "=========================================================="
    
    # Check for required environment variables
    if [[ -z "${AZ_SUBSCRIPTION:-}" ]]; then
        echo "Error: AZ_SUBSCRIPTION environment variable not set"
        echo "Please set AZ_SUBSCRIPTION to your Azure subscription ID"
        exit 1
    fi
    
    if [[ -z "${AZ_RESOURCE_GROUP:-}" ]]; then
        echo "Error: AZ_RESOURCE_GROUP environment variable not set"
        echo "Please set AZ_RESOURCE_GROUP to your Azure resource group name"
        exit 1
    fi
    
    # Phase 1: Monitoring
    echo ""
    echo "📊 Phase 1: Starting EIP Monitoring..."
    echo "======================================="
    
    # Setup variables and configuration
    setup_monitoring_variables
    
    # Store the output directory for later use
    PIPELINE_OUTPUT_DIR="${TEMP_DIR}/${NOW}"
    
    # Check if monitoring should continue and create output directory
    if ! should_continue_monitoring; then
        echo "Monitoring indicates no work needed - pipeline complete"
        exit 0
    fi
    
    echo "Output directory: $PIPELINE_OUTPUT_DIR"
    echo "Starting monitoring loop..."
    
    # Start the main monitoring loop
    monitor_eips
    
    echo "✅ Phase 1 Complete: Monitoring finished"
    
    # Phase 2: Log Merging
    echo ""
    echo "🔄 Phase 2: Starting Log Merge..."
    echo "================================="
    
    # Validate the monitoring output directory exists
    if [[ ! -d "$PIPELINE_OUTPUT_DIR" ]]; then
        echo "Error: Monitoring output directory '$PIPELINE_OUTPUT_DIR' not found"
        exit 1
    fi
    
    # Setup merge variables
    setup_merge_variables
    
    # Get node names from monitoring output
    if ! get_nodes "$PIPELINE_OUTPUT_DIR"; then
        echo "Error: Could not find node data in monitoring output"
        exit 1
    fi
    
    # Merge the logs
    merge_logs
    
    echo "✅ Phase 2 Complete: Log merge finished"
    
    # Phase 3: Plot Generation
    echo ""
    echo "📈 Phase 3: Starting Plot Generation..."
    echo "======================================="
    
    # Get .dat files from the output directory
    if ! get_dat_files "$PIPELINE_OUTPUT_DIR"; then
        echo "Error: Could not find .dat files in '$PIPELINE_OUTPUT_DIR'"
        echo "This may indicate the merge phase didn't work correctly"
        exit 1
    fi
    
    # Process all files to generate plots
    process_all_plot_files
    
    echo "✅ Phase 3 Complete: Plot generation finished"
    
    # Final Summary
    echo ""
    echo "🎉 PIPELINE COMPLETE! 🎉"
    echo "======================="
    echo "📁 All outputs saved in: $PIPELINE_OUTPUT_DIR"
    echo "📝 Raw logs: $PIPELINE_OUTPUT_DIR/logs/*.log"
    echo "📊 Data files: $PIPELINE_OUTPUT_DIR/data/*.dat"
    echo "📈 Plots: $PIPELINE_OUTPUT_DIR/plots/*.png"
    echo ""
    echo "Directory Structure:"
    echo "  $PIPELINE_OUTPUT_DIR/"
    echo "  ├── logs/     # Raw monitoring data"
    echo "  ├── data/     # Processed data files"  
    echo "  └── plots/    # Generated visualizations"
    echo ""
    echo "Your EIP monitoring, analysis, and visualization pipeline is complete!"
}

# Handle monitor command
cmd_monitor() {
    echo "Starting EIP monitoring..."
    
    # Check for required environment variables
    if [[ -z "${AZ_SUBSCRIPTION:-}" ]]; then
        echo "Error: AZ_SUBSCRIPTION environment variable not set"
        echo "Please set AZ_SUBSCRIPTION to your Azure subscription ID"
        exit 1
    fi
    
    if [[ -z "${AZ_RESOURCE_GROUP:-}" ]]; then
        echo "Error: AZ_RESOURCE_GROUP environment variable not set"
        echo "Please set AZ_RESOURCE_GROUP to your Azure resource group name"
        exit 1
    fi
    
    # Setup variables and configuration
    setup_monitoring_variables
    
    # Check if monitoring should continue and create output directory
    if ! should_continue_monitoring; then
        exit 0
    fi
    
    echo "Starting monitoring loop..."
    
    # Start the main monitoring loop
    monitor_eips
    
    echo "Monitoring complete - all EIPs assigned and CPIC issues resolved"
}

# Handle merge command
cmd_merge() {
    local logdir=$1
    
    echo "Starting log merge..."
    
    # Validate input
    validate_log_input "$logdir"
    
    # Setup variables
    setup_merge_variables
    
    # Get node names from directory
    if ! get_nodes "$logdir"; then
        exit 1
    fi
    
    # Merge the logs
    merge_logs
    
    echo "Log merge completed successfully"
}

# Handle plot command
cmd_plot() {
    local data_dir=$1
    
    echo "Starting batch plot generation..."
    
    # Validate input
    validate_plot_input "$data_dir"
    
    # Get .dat files from directory
    if ! get_dat_files "$data_dir"; then
        exit 1
    fi
    
    # Process all files
    process_all_plot_files
    
    echo "Plot generation completed successfully"
}

#############################################################################
# MAIN FUNCTION AND ARGUMENT PARSING
#############################################################################

main() {
    # Check if any arguments provided
    if [[ $# -eq 0 ]]; then
        show_usage
        exit 1
    fi
    
    # Parse command
    case "$1" in
        all|-a)
            cmd_all
            ;;
        monitor|-m)
            cmd_monitor
            ;;
        merge|-g)
            if [[ $# -lt 2 ]]; then
                echo "Error: merge command requires a log directory argument"
                echo "Usage: $0 merge <log_directory>"
                exit 1
            fi
            cmd_merge "$2"
            ;;
        plot|-p)
            if [[ $# -lt 2 ]]; then
                echo "Error: plot command requires a data directory argument"
                echo "Usage: $0 plot <data_directory>"
                exit 1
            fi
            cmd_plot "$2"
            ;;
        help|-h|--help)
            show_usage
            exit 0
            ;;
        *)
            echo "Error: Unknown command '$1'"
            echo
            show_usage
            exit 1
            ;;
    esac
}

# Execute main function with all arguments
main "$@"
