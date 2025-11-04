#!/usr/bin/env python3
"""
EIP Toolkit - Simple Version
Monitor Azure Red Hat OpenShift Egress IP assignments and CPIC status.
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


class EIPToolkitError(Exception):
    """Custom exception for EIP Toolkit errors."""
    pass


class EIPMonitor:
    """Simple EIP monitoring class."""
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.logs_dir = output_dir / 'logs'
        self.data_dir = output_dir / 'data'
        self.plots_dir = output_dir / 'plots'
        
        for directory in [self.logs_dir, self.data_dir, self.plots_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
    
    def run_oc_command(self, cmd):
        """Run oc command and return JSON result."""
        try:
            result = subprocess.run(['oc'] + cmd, capture_output=True, text=True, check=True)
            return json.loads(result.stdout)
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            raise EIPToolkitError(f"OpenShift command failed: {e}")
    
    def run_az_command(self, cmd):
        """Run az command and return JSON result."""
        try:
            subscription = os.getenv('AZ_SUBSCRIPTION')
            if not subscription:
                raise EIPToolkitError("AZ_SUBSCRIPTION environment variable not set")
            
            result = subprocess.run(['az'] + cmd + ['--subscription', subscription], 
                                  capture_output=True, text=True, check=True)
            return json.loads(result.stdout)
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            raise EIPToolkitError(f"Azure command failed: {e}")
    
    def get_eip_stats(self):
        """Get EIP statistics."""
        data = self.run_oc_command(['get', 'eip', '-o', 'json'])
        assigned = len([item for item in data['items'] if item.get('status', {}).get('items', [])])
        unassigned = len([item for item in data['items'] if not item.get('status', {}).get('items', [])])
        configured = len(data['items'])
        return {'configured': configured, 'assigned': assigned, 'unassigned': unassigned}
    
    def get_cpic_stats(self):
        """Get CPIC statistics."""
        data = self.run_oc_command(['get', 'cloudprivateipconfig', '-o', 'json'])
        success = len([item for item in data['items'] 
                      for condition in item.get('status', {}).get('conditions', [])
                      if condition.get('reason') == 'CloudResponseSuccess'])
        pending = len([item for item in data['items'] 
                      for condition in item.get('status', {}).get('conditions', [])
                      if condition.get('reason') == 'CloudResponsePending'])
        error = len([item for item in data['items'] 
                    for condition in item.get('status', {}).get('conditions', [])
                    if condition.get('reason') == 'CloudResponseError'])
        return {'success': success, 'pending': pending, 'error': error}
    
    def get_nodes(self):
        """Get EIP-enabled nodes."""
        try:
            result = subprocess.run(['oc', 'get', 'nodes', '-l', 'k8s.ovn.org/egress-assignable=true', '-o', 'name'],
                                  capture_output=True, text=True, check=True)
            return [line.replace('node/', '') for line in result.stdout.strip().split('\n') if line]
        except subprocess.CalledProcessError as e:
            raise EIPToolkitError(f"Cannot access OpenShift nodes: {e.stderr}")
    
    def log_stats(self, timestamp, stats_type, **kwargs):
        """Log statistics to files."""
        for stat_name, value in kwargs.items():
            log_file = self.logs_dir / f"{stats_type}_{stat_name}.log"
            with open(log_file, 'a') as f:
                f.write(f"{timestamp} {value}\n")
    
    def monitor(self):
        """Main monitoring loop."""
        self.logger.info("Starting EIP monitoring...")
        
        nodes = self.get_nodes()
        self.logger.info(f"Found EIP-enabled nodes: {nodes}")
        
        while True:
            timestamp = datetime.now().isoformat()
            
            # Get global statistics
            eip_stats = self.get_eip_stats()
            cpic_stats = self.get_cpic_stats()
            
            # Log global statistics
            self.log_stats(timestamp, 'ocp_eips', **eip_stats)
            self.log_stats(timestamp, 'ocp_cpic', **cpic_stats)
            
            # Monitor individual nodes
            for node in nodes:
                try:
                    # Get node-specific EIP stats
                    eip_data = self.run_oc_command(['get', 'eip', '-o', 'json'])
                    eip_assigned = len([item for item in eip_data['items']
                                      for status_item in item.get('status', {}).get('items', [])
                                      if status_item.get('node') == node])
                    
                    # Get node-specific CPIC stats
                    cpic_data = self.run_oc_command(['get', 'cloudprivateipconfig', '-o', 'json'])
                    cpic_success = len([item for item in cpic_data['items']
                                      if (item.get('spec', {}).get('node') == node and
                                          any(c.get('reason') == 'CloudResponseSuccess'
                                              for c in item.get('status', {}).get('conditions', [])))])
                    
                    # Log node statistics
                    self.log_stats(timestamp, f'{node}_ocp_eip', assigned=eip_assigned)
                    self.log_stats(timestamp, f'{node}_ocp_cpic', success=cpic_success)
                    
                    self.logger.info(f"{node} - EIP: {eip_assigned}, CPIC: {cpic_success}")
                    
                except Exception as e:
                    self.logger.error(f"Error monitoring node {node}: {e}")
            
            # Check if monitoring should continue
            if (eip_stats['assigned'] == eip_stats['configured'] and 
                cpic_stats['success'] == eip_stats['configured']):
                break
            
            time.sleep(1)
        
        self.logger.info("Monitoring complete - all EIPs assigned and CPIC issues resolved")
    
    def merge_logs(self):
        """Merge log files into data files."""
        self.logger.info("Merging log files...")
        
        # Get all log files
        log_files = list(self.logs_dir.glob('*.log'))
        if not log_files:
            raise EIPToolkitError("No log files found")
        
        # Get unique node names
        nodes = set()
        for log_file in log_files:
            filename = log_file.name
            if not filename.startswith(('ocp_', 'azure_')) and '_' in filename:
                node_name = filename.split('_')[0]
                nodes.add(node_name)
        
        # Process each file type
        file_mappings = {
            'ocp_cpic_success.log': 'ocp_cpic_success.dat',
            'ocp_cpic_pending.log': 'ocp_cpic_pending.dat', 
            'ocp_cpic_error.log': 'ocp_cpic_error.dat',
            'ocp_eip_assigned.log': 'ocp_eip_assigned.dat'
        }
        
        for log_suffix, dat_filename in file_mappings.items():
            data_file = self.data_dir / dat_filename
            
            with open(data_file, 'w') as outfile:
                for node in sorted(nodes):
                    log_file = self.logs_dir / f"{node}_{log_suffix}"
                    if log_file.exists():
                        outfile.write(f'"{node}"\n')
                        with open(log_file, 'r') as infile:
                            outfile.write(infile.read())
                        outfile.write('\n\n')
        
        self.logger.info("Log merge completed")
    
    def create_plots(self):
        """Generate plots from data files."""
        self.logger.info("Creating plots...")
        
        data_files = list(self.data_dir.glob('*.dat'))
        if not data_files:
            raise EIPToolkitError("No .dat files found for plotting")
        
        for data_file in data_files:
            try:
                # Read the data file
                with open(data_file, 'r') as f:
                    content = f.read()
                
                # Parse data sections
                sections = content.split('\n\n')
                
                plt.figure(figsize=(12, 8))
                colors = ['green', 'red', 'blue', 'violet', 'orange', 'brown']
                
                for i, section in enumerate(sections):
                    if not section.strip():
                        continue
                    
                    lines = section.strip().split('\n')
                    if not lines:
                        continue
                    
                    node_name = lines[0].strip('"')
                    data_lines = lines[1:]
                    
                    timestamps = []
                    values = []
                    
                    for line in data_lines:
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 2:
                                try:
                                    timestamp = pd.to_datetime(parts[0])
                                    value = float(parts[1])
                                    timestamps.append(timestamp)
                                    values.append(value)
                                except (ValueError, pd.errors.ParserError):
                                    continue
                    
                    if timestamps and values:
                        color = colors[i % len(colors)]
                        plt.plot(timestamps, values, label=node_name, 
                                linewidth=2, color=color, marker='o', markersize=4)
                
                # Format plot
                title = data_file.stem.replace('_', ' ').title()
                plt.title(title, fontsize=14, fontweight='bold')
                plt.xlabel('Time', fontsize=12)
                plt.ylabel('Value', fontsize=12)
                plt.legend()
                plt.grid(True, alpha=0.3)
                plt.xticks(rotation=45)
                plt.tight_layout()
                
                # Save plot
                plot_file = self.plots_dir / f"{data_file.stem}.png"
                plt.savefig(plot_file, dpi=150, bbox_inches='tight')
                plt.close()
                
                self.logger.info(f"Generated plot: {plot_file}")
                
            except Exception as e:
                self.logger.error(f"Error creating plot for {data_file}: {e}")
        
        self.logger.info("Plot generation completed")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='EIP Toolkit - Simple Version')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Monitor command
    subparsers.add_parser('monitor', help='Monitor EIP and CPIC status')
    
    # Merge command
    merge_parser = subparsers.add_parser('merge', help='Merge log files into data files')
    merge_parser.add_argument('directory', help='Directory containing log files')
    
    # Plot command
    plot_parser = subparsers.add_parser('plot', help='Generate plots from data files')
    plot_parser.add_argument('directory', help='Directory containing data files')
    
    # All command
    subparsers.add_parser('all', help='Run complete pipeline: monitor → merge → plot')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    try:
        if args.command == 'monitor':
            timestamp = datetime.now().strftime('%y%m%d_%H%M%S')
            output_dir = Path('../runs') / timestamp
            monitor = EIPMonitor(output_dir)
            monitor.monitor()
            
        elif args.command == 'merge':
            base_dir = Path(args.directory)
            if not base_dir.exists():
                raise EIPToolkitError(f"Directory {base_dir} does not exist")
            monitor = EIPMonitor(base_dir)
            monitor.merge_logs()
            
        elif args.command == 'plot':
            base_dir = Path(args.directory)
            if not base_dir.exists():
                raise EIPToolkitError(f"Directory {base_dir} does not exist")
            monitor = EIPMonitor(base_dir)
            monitor.create_plots()
            
        elif args.command == 'all':
            timestamp = datetime.now().strftime('%y%m%d_%H%M%S')
            output_dir = Path('../runs') / timestamp
            monitor = EIPMonitor(output_dir)
            
            print("🚀 Starting Complete EIP Pipeline")
            print("📊 Phase 1: Monitoring...")
            monitor.monitor()
            print("✅ Phase 1 Complete")
            
            print("🔄 Phase 2: Merging logs...")
            monitor.merge_logs()
            print("✅ Phase 2 Complete")
            
            print("📈 Phase 3: Creating plots...")
            monitor.create_plots()
            print("✅ Phase 3 Complete")
            
            print("🎉 PIPELINE COMPLETE!")
            print(f"📁 Outputs saved in: {output_dir}")
        
        return 0
        
    except EIPToolkitError as e:
        print(f"Error: {e}")
        return 1
    except KeyboardInterrupt:
        print("Interrupted by user")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())

