#!/usr/bin/env python3
"""
EIP Monitor - Ultra Simple Version
Monitor Azure Red Hat OpenShift Egress IP assignments.
"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime


def run_oc(cmd):
    """Run oc command and return JSON."""
    result = subprocess.run(['oc'] + cmd, capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def run_az(cmd):
    """Run az command and return JSON."""
    subscription = os.getenv('AZ_SUBSCRIPTION')
    if not subscription:
        raise Exception("AZ_SUBSCRIPTION environment variable not set")
    
    result = subprocess.run(['az'] + cmd + ['--subscription', subscription], 
                          capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def get_eip_stats():
    """Get EIP statistics."""
    data = run_oc(['get', 'eip', '-o', 'json'])
    assigned = len([item for item in data['items'] if item.get('status', {}).get('items', [])])
    configured = len(data['items'])
    return assigned, configured


def get_cpic_stats():
    """Get CPIC statistics."""
    data = run_oc(['get', 'cloudprivateipconfig', '-o', 'json'])
    success = len([item for item in data['items'] 
                  for condition in item.get('status', {}).get('conditions', [])
                  if condition.get('reason') == 'CloudResponseSuccess'])
    return success


def get_nodes():
    """Get EIP-enabled nodes."""
    result = subprocess.run(['oc', 'get', 'nodes', '-l', 'k8s.ovn.org/egress-assignable=true', '-o', 'name'],
                          capture_output=True, text=True, check=True)
    return [line.replace('node/', '') for line in result.stdout.strip().split('\n') if line]


def get_azure_nic_stats(node):
    """Get Azure NIC statistics for a node."""
    try:
        nic_name = f"{node}-nic"
        resource_group = os.getenv('AZ_RESOURCE_GROUP')
        if not resource_group:
            return 0, 0
        
        # Get IP configurations
        ip_configs = run_az(['network', 'nic', 'show', '--resource-group', resource_group, 
                           '--name', nic_name, '--query', 'ipConfigurations[].privateIPAddress'])
        
        # Get load balancer associations
        lb_configs = run_az(['network', 'nic', 'show', '--resource-group', resource_group,
                           '--name', nic_name, '--query', 'ipConfigurations[].{pools:loadBalancerBackendAddressPools[].id}'])
        
        total_ips = len(ip_configs) if ip_configs else 0
        lb_associated = len([cfg for cfg in lb_configs if cfg.get('pools')]) if lb_configs else 0
        
        # Subtract primary IP
        secondary_ips = max(0, total_ips - 1)
        secondary_lb_ips = max(0, lb_associated - 1)
        
        return secondary_ips, secondary_lb_ips
    except:
        return 0, 0


def monitor():
    """Main monitoring loop."""
    print("Starting EIP monitoring...")
    
    nodes = get_nodes()
    print(f"Found EIP-enabled nodes: {nodes}")
    
    while True:
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        # Get global stats
        assigned, configured = get_eip_stats()
        cpic_success = get_cpic_stats()
        
        # Get Azure stats for each node
        azure_stats = []
        for node in nodes:
            azure_eips, azure_lbs = get_azure_nic_stats(node)
            azure_stats.append(f"{node}:{azure_eips}/{azure_lbs}")
        
        print(f"[{timestamp}] EIPs: {assigned}/{configured}, CPIC: {cpic_success}, Azure: {', '.join(azure_stats)}")
        
        # Check if complete
        if assigned == configured and cpic_success == configured:
            print("✅ All EIPs assigned and CPIC issues resolved!")
            break
        
        time.sleep(1)


if __name__ == '__main__':
    try:
        monitor()
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
