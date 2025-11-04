#!/usr/bin/env python3
"""
EIP Toolkit - Python Implementation

A unified tool for monitoring, analyzing, and visualizing Azure Red Hat OpenShift (ARO) 
Egress IP (EIP) assignments and CloudPrivateIPConfig (CPIC) status.

Author: EIP Monitoring Team
Version: 2.0.0 (Python)
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from collections import defaultdict
import weakref

import aiofiles

import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import pandas as pd
from dataclasses import dataclass


@dataclass
class EIPStats:
    """Container for EIP statistics."""
    configured: int
    assigned: int
    unassigned: int


@dataclass
class CPICStats:
    """Container for CPIC statistics."""
    success: int
    pending: int
    error: int


@dataclass
class NodeStats:
    """Container for node-specific statistics."""
    cpic_success: int
    cpic_pending: int
    cpic_error: int
    eip_assigned: int
    azure_eips: int
    azure_lbs: int


class EIPToolkitError(Exception):
    """Custom exception for EIP Toolkit errors."""
    pass


class SmartCache:
    """Advanced caching system with intelligent invalidation."""
    
    def __init__(self, default_ttl: int = 5, max_size: int = 1000):
        self.default_ttl = default_ttl
        self.max_size = max_size
        self._cache = {}
        self._access_times = {}
        self._dependencies = defaultdict(set)  # key -> set of dependent keys
        
    def get(self, key: str) -> Optional[any]:
        """Get cached value if valid."""
        if key not in self._cache:
            return None
            
        now = time.time()
        entry = self._cache[key]
        
        # Check TTL
        if now - entry['timestamp'] > entry['ttl']:
            self._invalidate_key(key)
            return None
            
        # Update access time for LRU
        self._access_times[key] = now
        return entry['data']
    
    def set(self, key: str, data: any, ttl: Optional[int] = None, 
            dependencies: Optional[List[str]] = None):
        """Set cached value with dependencies."""
        if len(self._cache) >= self.max_size:
            self._evict_lru()
            
        now = time.time()
        self._cache[key] = {
            'data': data,
            'timestamp': now,
            'ttl': ttl or self.default_ttl
        }
        self._access_times[key] = now
        
        # Set up dependencies
        if dependencies:
            for dep in dependencies:
                self._dependencies[dep].add(key)
    
    def invalidate(self, key: str):
        """Invalidate a key and all its dependents."""
        self._invalidate_key(key)
        
        # Invalidate all dependent keys
        for dependent in list(self._dependencies.get(key, set())):
            self._invalidate_key(dependent)
    
    def _invalidate_key(self, key: str):
        """Remove key from cache."""
        if key in self._cache:
            del self._cache[key]
        if key in self._access_times:
            del self._access_times[key]
        if key in self._dependencies:
            del self._dependencies[key]
    
    def _evict_lru(self):
        """Evict least recently used entry."""
        if not self._access_times:
            return
            
        lru_key = min(self._access_times.keys(), 
                     key=lambda k: self._access_times[k])
        self._invalidate_key(lru_key)
    
    def clear(self):
        """Clear all cache."""
        self._cache.clear()
        self._access_times.clear()
        self._dependencies.clear()


class AsyncBufferedLogger:
    """Async buffered logger with better performance."""
    
    def __init__(self, logs_dir: Path, buffer_size: int = 1000):
        self.logs_dir = logs_dir
        self.buffers = defaultdict(list)
        self.buffer_size = buffer_size
        self._lock = asyncio.Lock()
    
    async def log_stats(self, timestamp: str, stats_type: str, **kwargs):
        """Async buffer statistics."""
        async with self._lock:
            for stat_name, value in kwargs.items():
                key = f"{stats_type}_{stat_name}"
                self.buffers[key].append(f"{timestamp} {value}\n")
                
                if len(self.buffers[key]) >= self.buffer_size:
                    await self._flush_buffer_async(key)
    
    async def _flush_buffer_async(self, key: str):
        """Async flush buffer to file."""
        if key not in self.buffers or not self.buffers[key]:
            return
        
        log_file = self.logs_dir / f"{key}.log"
        lines = self.buffers[key].copy()
        self.buffers[key].clear()
        
        async with aiofiles.open(log_file, 'a') as f:
            await f.writelines(lines)
    
    async def flush_all(self):
        """Async flush all buffers."""
        async with self._lock:
            tasks = []
            for key in list(self.buffers.keys()):
                if self.buffers[key]:
                    tasks.append(self._flush_buffer_async(key))
            
            if tasks:
                await asyncio.gather(*tasks)


class BufferedLogger:
    """Buffered logger to reduce file I/O operations."""
    
    def __init__(self, logs_dir: Path):
        self.logs_dir = logs_dir
        self.buffers = {}
        self.buffer_size = 100  # Flush after 100 entries
    
    def log_stats(self, timestamp: str, stats_type: str, **kwargs):
        """Buffer statistics instead of immediate file I/O."""
        for stat_name, value in kwargs.items():
            key = f"{stats_type}_{stat_name}"
            if key not in self.buffers:
                self.buffers[key] = []
            
            self.buffers[key].append(f"{timestamp} {value}\n")
            
            # Flush if buffer is full
            if len(self.buffers[key]) >= self.buffer_size:
                self._flush_buffer(key)
    
    def _flush_buffer(self, key: str):
        """Flush a specific buffer to file."""
        if key not in self.buffers or not self.buffers[key]:
            return
        
        log_file = self.logs_dir / f"{key}.log"
        with open(log_file, 'a') as f:
            f.writelines(self.buffers[key])
        self.buffers[key] = []
    
    def flush_all(self):
        """Flush all buffers to files."""
        for key in list(self.buffers.keys()):
            self._flush_buffer(key)
    
    def log_cluster_summary(self, timestamp: str, node_eip_data: List[Dict], 
                           total_assigned_eips: int, total_azure_eips: int):
        """Log cluster summary with buffering."""
        summary_file = self.logs_dir / 'cluster_eip_details.log'
        
        # Write to buffer first
        lines = [f"{timestamp} CLUSTER_SUMMARY\n"]
        for node_data in node_eip_data:
            lines.append(f"{timestamp} {node_data['node']} {node_data['eip_assigned']} {node_data['azure_eips']}\n")
        lines.append(f"{timestamp} TOTAL {total_assigned_eips} {total_azure_eips}\n")
        lines.append("\n")
        
        with open(summary_file, 'a') as f:
            f.writelines(lines)


class OpenShiftClient:
    """Wrapper for OpenShift CLI operations with smart caching."""
    
    def __init__(self, cache_ttl: int = 5):
        self.cache_ttl = cache_ttl
        self._cache = SmartCache(default_ttl=cache_ttl)
    
    def run_command(self, cmd: List[str]) -> Dict:
        """Execute oc command and return JSON result with smart caching."""
        cache_key = ' '.join(cmd)
        
        # Check cache first
        cached_data = self._cache.get(cache_key)
        if cached_data is not None:
            return cached_data
        
        try:
            result = subprocess.run(
                ['oc'] + cmd,
                capture_output=True,
                text=True,
                check=True
            )
            data = json.loads(result.stdout)
            
            # Cache with dependencies
            dependencies = []
            if 'get eip' in cache_key:
                dependencies.append('eip_stats')
            elif 'get cloudprivateipconfig' in cache_key:
                dependencies.append('cpic_stats')
            
            self._cache.set(cache_key, data, dependencies=dependencies)
            return data
        except subprocess.CalledProcessError as e:
            raise EIPToolkitError(f"OpenShift command failed: {e.stderr}")
        except json.JSONDecodeError as e:
            raise EIPToolkitError(f"Failed to parse OpenShift response: {e}")
    
    def get_eip_enabled_nodes(self) -> List[str]:
        """Get list of EIP-enabled nodes."""
        try:
            result = subprocess.run(
                ['oc', 'get', 'nodes', '-l', 'k8s.ovn.org/egress-assignable=true', '-o', 'name'],
                capture_output=True,
                text=True,
                check=True
            )
            nodes = [line.replace('node/', '') for line in result.stdout.strip().split('\n') if line]
            if not nodes:
                raise EIPToolkitError("No EIP-enabled nodes found")
            return nodes
        except subprocess.CalledProcessError as e:
            raise EIPToolkitError(f"Cannot access OpenShift nodes: {e.stderr}")
    
    def get_eip_stats(self) -> EIPStats:
        """Get EIP statistics from OpenShift."""
        data = self.run_command(['get', 'eip', '-o', 'json'])
        
        assigned = len([item for item in data['items'] 
                       if item.get('status', {}).get('items', [])])
        unassigned = len([item for item in data['items'] 
                         if not item.get('status', {}).get('items', [])])
        configured = len([item for item in data['items'] 
                         if not item.get('spec', {}).get('egressIP', [])])
        
        return EIPStats(configured=configured, assigned=assigned, unassigned=unassigned)
    
    def get_cpic_stats(self) -> CPICStats:
        """Get CPIC statistics from OpenShift."""
        data = self.run_command(['get', 'cloudprivateipconfig', '-o', 'json'])
        
        success = len([item for item in data['items']
                      for condition in item.get('status', {}).get('conditions', [])
                      if condition.get('reason') == 'CloudResponseSuccess'])
        pending = len([item for item in data['items']
                      for condition in item.get('status', {}).get('conditions', [])
                      if condition.get('reason') == 'CloudResponsePending'])
        error = len([item for item in data['items']
                    for condition in item.get('status', {}).get('conditions', [])
                    if condition.get('reason') == 'CloudResponseError'])
        
        return CPICStats(success=success, pending=pending, error=error)
    
    def get_node_stats(self, node_name: str) -> NodeStats:
        """Get statistics for a specific node."""
        # CPIC stats for the node
        cpic_data = self.run_command(['get', 'cloudprivateipconfig', '-o', 'json'])
        cpic_success = len([item for item in cpic_data['items']
                           if (item.get('spec', {}).get('node') == node_name and
                               any(c.get('reason') == 'CloudResponseSuccess'
                                   for c in item.get('status', {}).get('conditions', [])))])
        cpic_pending = len([item for item in cpic_data['items']
                           if (item.get('spec', {}).get('node') == node_name and
                               any(c.get('reason') == 'CloudResponsePending'
                                   for c in item.get('status', {}).get('conditions', [])))])
        cpic_error = len([item for item in cpic_data['items']
                         if (item.get('spec', {}).get('node') == node_name and
                             any(c.get('reason') == 'CloudResponseError'
                                 for c in item.get('status', {}).get('conditions', [])))])
        
        # EIP stats for the node
        eip_data = self.run_command(['get', 'eip', '-o', 'json'])
        eip_assigned = len([item for item in eip_data['items']
                           for status_item in item.get('status', {}).get('items', [])
                           if status_item.get('node') == node_name])
        
        return NodeStats(
            cpic_success=cpic_success,
            cpic_pending=cpic_pending,
            cpic_error=cpic_error,
            eip_assigned=eip_assigned,
            azure_eips=0,  # Will be filled by Azure client
            azure_lbs=0    # Will be filled by Azure client
        )


class AzureClient:
    """Wrapper for Azure CLI operations."""
    
    def __init__(self, subscription_id: str, resource_group: str):
        self.subscription_id = subscription_id
        self.resource_group = resource_group
    
    def run_command(self, cmd: List[str]) -> Dict:
        """Execute az command and return JSON result."""
        try:
            result = subprocess.run(
                ['az'] + cmd + ['--subscription', self.subscription_id],
                capture_output=True,
                text=True,
                check=True
            )
            return json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            raise EIPToolkitError(f"Azure command failed: {e.stderr}")
        except json.JSONDecodeError as e:
            raise EIPToolkitError(f"Failed to parse Azure response: {e}")
    
    def get_node_nic_stats(self, node_name: str) -> Tuple[int, int]:
        """Get NIC statistics for a node."""
        nic_name = f"{node_name}-nic"
        
        # Get IP configurations
        ip_configs = self.run_command([
            'network', 'nic', 'show',
            '--resource-group', self.resource_group,
            '--name', nic_name,
            '--query', 'ipConfigurations[].privateIPAddress'
        ])
        
        # Get load balancer associations
        lb_configs = self.run_command([
            'network', 'nic', 'show',
            '--resource-group', self.resource_group,
            '--name', nic_name,
            '--query', 'ipConfigurations[].{pools:loadBalancerBackendAddressPools[].id}'
        ])
        
        total_ips = len(ip_configs) if ip_configs else 0
        lb_associated = len([cfg for cfg in lb_configs if cfg.get('pools')]) if lb_configs else 0
        
        # Subtract primary IP
        secondary_ips = max(0, total_ips - 1)
        secondary_lb_ips = max(0, lb_associated - 1)
        
        return secondary_ips, secondary_lb_ips


class EIPMonitor:
    """Main EIP monitoring class."""
    
    def __init__(self, output_dir: Path, subscription_id: str, resource_group: str):
        self.output_dir = output_dir
        self.oc_client = OpenShiftClient()
        self.az_client = AzureClient(subscription_id, resource_group)
        
        # Create output directories
        self.logs_dir = output_dir / 'logs'
        self.data_dir = output_dir / 'data'
        self.plots_dir = output_dir / 'plots'
        
        for directory in [self.logs_dir, self.data_dir, self.plots_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Use buffered logger for better performance
        self.buffered_logger = BufferedLogger(self.logs_dir)
    
    def should_continue_monitoring(self, eip_stats: EIPStats, cpic_stats: CPICStats) -> bool:
        """Check if monitoring should continue using provided stats."""
        self.logger.info(f"Configured EIPs: {eip_stats.configured}")
        self.logger.info(f"Successful CPICs: {cpic_stats.success}")
        self.logger.info(f"Assigned EIPs: {eip_stats.assigned}")
        
        return (eip_stats.assigned != eip_stats.configured or 
                cpic_stats.success != eip_stats.configured)
    
    def log_stats(self, timestamp: str, stats_type: str, **kwargs):
        """Log statistics to files."""
        for stat_name, value in kwargs.items():
            log_file = self.logs_dir / f"{stats_type}_{stat_name}.log"
            with open(log_file, 'a') as f:
                f.write(f"{timestamp} {value}\n")
    
    def collect_single_node_data(self, node: str, timestamp: str) -> Optional[Dict]:
        """Collect data for a single node."""
        try:
            node_stats = self.oc_client.get_node_stats(node)
            azure_eips, azure_lbs = self.az_client.get_node_nic_stats(node)
            node_stats.azure_eips = azure_eips
            node_stats.azure_lbs = azure_lbs
            
            # Log node statistics using buffered logger
            self.buffered_logger.log_stats(timestamp, f'{node}_ocp_cpic',
                                          success=node_stats.cpic_success,
                                          pending=node_stats.cpic_pending,
                                          error=node_stats.cpic_error)
            
            self.buffered_logger.log_stats(timestamp, f'{node}_ocp_eip',
                                          assigned=node_stats.eip_assigned)
            
            self.buffered_logger.log_stats(timestamp, f'{node}_azure',
                                          eips=node_stats.azure_eips,
                                          lbs=node_stats.azure_lbs)
            
            self.logger.info(f"{node} - CPIC: {node_stats.cpic_success}/{node_stats.cpic_pending}/{node_stats.cpic_error}, "
                           f"EIP: {node_stats.eip_assigned}, Azure: {node_stats.azure_eips}/{node_stats.azure_lbs}")
            
            return {
                'node': node,
                'eip_assigned': node_stats.eip_assigned,
                'azure_eips': azure_eips
            }
            
        except Exception as e:
            self.logger.error(f"Error monitoring node {node}: {e}")
            return None

    def collect_node_data_parallel(self, nodes: List[str], timestamp: str) -> List[Dict]:
        """Collect data from all nodes in parallel."""
        node_eip_data = []
        
        with ThreadPoolExecutor(max_workers=min(len(nodes), 10)) as executor:
            # Submit all tasks
            future_to_node = {
                executor.submit(self.collect_single_node_data, node, timestamp): node 
                for node in nodes
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_node):
                node = future_to_node[future]
                try:
                    result = future.result()
                    if result:
                        node_eip_data.append(result)
                except Exception as e:
                    self.logger.error(f"Error processing node {node}: {e}")
        
        return node_eip_data

    def log_cluster_summary(self, timestamp: str, node_eip_data: List[Dict]):
        """Log aggregated cluster-wide EIP summary."""
        try:
            total_assigned_eips = sum(data['eip_assigned'] for data in node_eip_data)
            total_azure_eips = sum(data['azure_eips'] for data in node_eip_data)
            node_count = len(node_eip_data)
            
            # Log cluster totals using buffered logger
            self.buffered_logger.log_stats(timestamp, 'cluster_summary',
                                          total_assigned_eips=total_assigned_eips,
                                          total_azure_eips=total_azure_eips,
                                          node_count=node_count,
                                          avg_eips_per_node=round(total_assigned_eips / max(node_count, 1), 2))
            
            # Log detailed summary
            self.buffered_logger.log_cluster_summary(timestamp, node_eip_data, 
                                                   total_assigned_eips, total_azure_eips)
            
        except Exception as e:
            self.logger.error(f"Error creating cluster summary: {e}")
    
    def monitor_loop(self):
        """Main monitoring loop with optimizations."""
        self.logger.info("Starting EIP monitoring loop...")
        
        nodes = self.oc_client.get_eip_enabled_nodes()
        self.logger.info(f"Found EIP-enabled nodes: {nodes}")
        
        while True:
            timestamp = datetime.now().isoformat()
            
            # Get global statistics once per iteration
            eip_stats = self.oc_client.get_eip_stats()
            cpic_stats = self.oc_client.get_cpic_stats()
            
            # Log global statistics using buffered logger
            self.buffered_logger.log_stats(timestamp, 'ocp_eips',
                                          configured=eip_stats.configured,
                                          assigned=eip_stats.assigned,
                                          unassigned=eip_stats.unassigned)
            
            self.buffered_logger.log_stats(timestamp, 'ocp_cpic',
                                          success=cpic_stats.success,
                                          pending=cpic_stats.pending,
                                          error=cpic_stats.error)
            
            # Collect node data in parallel
            node_eip_data = self.collect_node_data_parallel(nodes, timestamp)
            
            # Log aggregated cluster-wide EIP summary
            self.log_cluster_summary(timestamp, node_eip_data)
            
            # Flush all buffered logs
            self.buffered_logger.flush_all()
            
            # Check if monitoring should continue
            if not self.should_continue_monitoring(eip_stats, cpic_stats):
                break
            
            time.sleep(1)
        
        self.logger.info("Monitoring complete - all EIPs assigned and CPIC issues resolved")
    
    async def monitor_loop_async(self):
        """Async monitoring loop with maximum performance."""
        self.logger.info("Starting async EIP monitoring loop...")
        
        nodes = self.oc_client.get_eip_enabled_nodes()
        self.logger.info(f"Found EIP-enabled nodes: {nodes}")
        
        # Use async buffered logger
        async_logger = AsyncBufferedLogger(self.logs_dir)
        
        while True:
            timestamp = datetime.now().isoformat()
            
            # Get global statistics once per iteration
            eip_stats = self.oc_client.get_eip_stats()
            cpic_stats = self.oc_client.get_cpic_stats()
            
            # Log global statistics using async buffered logger
            await async_logger.log_stats(timestamp, 'ocp_eips',
                                        configured=eip_stats.configured,
                                        assigned=eip_stats.assigned,
                                        unassigned=eip_stats.unassigned)
            
            await async_logger.log_stats(timestamp, 'ocp_cpic',
                                        success=cpic_stats.success,
                                        pending=cpic_stats.pending,
                                        error=cpic_stats.error)
            
            # Collect node data in parallel with async operations
            node_eip_data = await self.collect_node_data_async(nodes, timestamp, async_logger)
            
            # Log aggregated cluster-wide EIP summary
            await self.log_cluster_summary_async(timestamp, node_eip_data, async_logger)
            
            # Flush all buffered logs
            await async_logger.flush_all()
            
            # Check if monitoring should continue
            if not self.should_continue_monitoring(eip_stats, cpic_stats):
                break
            
            await asyncio.sleep(1)
        
        self.logger.info("Async monitoring complete - all EIPs assigned and CPIC issues resolved")
    
    async def collect_single_node_data_async(self, node: str, timestamp: str, 
                                           async_logger: AsyncBufferedLogger) -> Optional[Dict]:
        """Async collect data for a single node."""
        try:
            # Run blocking operations in thread pool
            loop = asyncio.get_event_loop()
            node_stats = await loop.run_in_executor(None, self.oc_client.get_node_stats, node)
            azure_eips, azure_lbs = await loop.run_in_executor(
                None, self.az_client.get_node_nic_stats, node)
            
            node_stats.azure_eips = azure_eips
            node_stats.azure_lbs = azure_lbs
            
            # Log node statistics using async buffered logger
            await async_logger.log_stats(timestamp, f'{node}_ocp_cpic',
                                        success=node_stats.cpic_success,
                                        pending=node_stats.cpic_pending,
                                        error=node_stats.cpic_error)
            
            await async_logger.log_stats(timestamp, f'{node}_ocp_eip',
                                        assigned=node_stats.eip_assigned)
            
            await async_logger.log_stats(timestamp, f'{node}_azure',
                                        eips=node_stats.azure_eips,
                                        lbs=node_stats.azure_lbs)
            
            self.logger.info(f"{node} - CPIC: {node_stats.cpic_success}/{node_stats.cpic_pending}/{node_stats.cpic_error}, "
                           f"EIP: {node_stats.eip_assigned}, Azure: {node_stats.azure_eips}/{node_stats.azure_lbs}")
            
            return {
                'node': node,
                'eip_assigned': node_stats.eip_assigned,
                'azure_eips': azure_eips
            }
            
        except Exception as e:
            self.logger.error(f"Error monitoring node {node}: {e}")
            return None

    async def collect_node_data_async(self, nodes: List[str], timestamp: str, 
                                    async_logger: AsyncBufferedLogger) -> List[Dict]:
        """Async collect data from all nodes in parallel."""
        # Create tasks for all nodes
        tasks = [
            self.collect_single_node_data_async(node, timestamp, async_logger)
            for node in nodes
        ]
        
        # Wait for all tasks to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and None results
        node_eip_data = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self.logger.error(f"Error processing node {nodes[i]}: {result}")
            elif result is not None:
                node_eip_data.append(result)
        
        return node_eip_data

    async def log_cluster_summary_async(self, timestamp: str, node_eip_data: List[Dict], 
                                       async_logger: AsyncBufferedLogger):
        """Async log aggregated cluster-wide EIP summary."""
        try:
            total_assigned_eips = sum(data['eip_assigned'] for data in node_eip_data)
            total_azure_eips = sum(data['azure_eips'] for data in node_eip_data)
            node_count = len(node_eip_data)
            
            # Log cluster totals using async buffered logger
            await async_logger.log_stats(timestamp, 'cluster_summary',
                                        total_assigned_eips=total_assigned_eips,
                                        total_azure_eips=total_azure_eips,
                                        node_count=node_count,
                                        avg_eips_per_node=round(total_assigned_eips / max(node_count, 1), 2))
            
            # Log detailed summary
            summary_file = self.logs_dir / 'cluster_eip_details.log'
            lines = [f"{timestamp} CLUSTER_SUMMARY\n"]
            for node_data in node_eip_data:
                lines.append(f"{timestamp} {node_data['node']} {node_data['eip_assigned']} {node_data['azure_eips']}\n")
            lines.append(f"{timestamp} TOTAL {total_assigned_eips} {total_azure_eips}\n")
            lines.append("\n")
            
            async with aiofiles.open(summary_file, 'a') as f:
                await f.writelines(lines)
            
        except Exception as e:
            self.logger.error(f"Error creating cluster summary: {e}")


class OptimizedDataProcessor:
    """Optimized data processor using pandas for better performance."""
    
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.logs_dir = base_dir / 'logs'
        self.data_dir = base_dir / 'data'
        self.data_dir.mkdir(exist_ok=True)
    
    def merge_logs_optimized(self):
        """Optimized log merging using pandas."""
        logging.info("Starting optimized log merge process...")
        
        if not self.logs_dir.exists():
            raise EIPToolkitError(f"Logs directory {self.logs_dir} does not exist")
        
        log_files = list(self.logs_dir.glob('*.log'))
        if not log_files:
            raise EIPToolkitError(f"No log files found in {self.logs_dir}")
        
        # Get unique node names
        nodes = set()
        for log_file in log_files:
            filename = log_file.name
            if not filename.startswith(('ocp_', 'azure_')) and '_' in filename:
                node_name = filename.split('_')[0]
                nodes.add(node_name)
        
        logging.info(f"Found nodes: {sorted(nodes) if nodes else 'None (global files only)'}")
        
        # Process files in parallel using pandas
        file_mappings = {
            'ocp_cpic_success.log': 'ocp_cpic_success.dat',
            'ocp_cpic_pending.log': 'ocp_cpic_pending.dat', 
            'ocp_cpic_error.log': 'ocp_cpic_error.dat',
            'ocp_eip_assigned.log': 'ocp_eip_assigned.dat',
            'azure_eips.log': 'azure_eips.dat',
            'azure_lbs.log': 'azure_lbs.dat'
        }
        
        # Process each file type with pandas
        for log_suffix, dat_filename in file_mappings.items():
            data_file = self.data_dir / dat_filename
            
            # Collect all data for this file type
            all_data = []
            
            # Process node-specific files
            for node in sorted(nodes):
                log_file = self.logs_dir / f"{node}_{log_suffix}"
                if log_file.exists():
                    try:
                        df = pd.read_csv(log_file, sep=' ', names=['timestamp', 'value'], 
                                       parse_dates=['timestamp'], engine='c')
                        df['node'] = node
                        all_data.append(df)
                        logging.info(f"Processed: {log_file.name} -> {dat_filename}")
                    except Exception as e:
                        logging.warning(f"Error processing {log_file}: {e}")
            
            # Process global files if no node files
            if not nodes:
                global_log_file = self.logs_dir / log_suffix
                if global_log_file.exists():
                    try:
                        df = pd.read_csv(global_log_file, sep=' ', names=['timestamp', 'value'],
                                       parse_dates=['timestamp'], engine='c')
                        df['node'] = 'global'
                        all_data.append(df)
                        logging.info(f"Processed global: {global_log_file.name} -> {dat_filename}")
                    except Exception as e:
                        logging.warning(f"Error processing {global_log_file}: {e}")
            
            # Combine and save
            if all_data:
                combined_df = pd.concat(all_data, ignore_index=True)
                # Sort by timestamp for better plotting
                combined_df = combined_df.sort_values(['node', 'timestamp'])
                
                # Save in optimized format
                combined_df.to_csv(data_file, index=False, compression='gzip')
                logging.info(f"Saved optimized data: {dat_filename}")
        
        logging.info("Optimized log merge completed successfully")


class DataProcessor:
    """Process log files into data files for plotting."""
    
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.logs_dir = base_dir / 'logs'
        self.data_dir = base_dir / 'data'
        self.data_dir.mkdir(exist_ok=True)
    
    def merge_logs(self):
        """Merge log files into data files."""
        logging.info("Starting log merge process...")
        
        # Check if logs directory exists and has files
        if not self.logs_dir.exists():
            raise EIPToolkitError(f"Logs directory {self.logs_dir} does not exist")
        
        log_files = list(self.logs_dir.glob('*.log'))
        if not log_files:
            raise EIPToolkitError(f"No log files found in {self.logs_dir}")
        
        logging.info(f"Found {len(log_files)} log files")
        
        # Get unique node names by looking for node-prefixed files
        nodes = set()
        for log_file in log_files:
            filename = log_file.name
            # Look for files that start with a node name (not ocp_, azure_ etc.)
            if not filename.startswith(('ocp_', 'azure_')) and '_' in filename:
                node_name = filename.split('_')[0]
                nodes.add(node_name)
        
        if not nodes:
            logging.warning("No node-specific log files found")
            # Still process global files
            nodes = set()
        
        logging.info(f"Found nodes: {sorted(nodes) if nodes else 'None (global files only)'}")
        
        # Define file type mappings (log suffix -> output file)
        file_mappings = {
            'ocp_cpic_success.log': 'ocp_cpic_success.dat',
            'ocp_cpic_pending.log': 'ocp_cpic_pending.dat', 
            'ocp_cpic_error.log': 'ocp_cpic_error.dat',
            'ocp_eip_assigned.log': 'ocp_eip_assigned.dat',
            'azure_eips.log': 'azure_eips.dat',
            'azure_lbs.log': 'azure_lbs.dat'
        }
        
        # Define cluster summary mappings
        cluster_summary_mappings = {
            'cluster_summary_total_assigned_eips.log': 'cluster_total_assigned_eips.dat',
            'cluster_summary_total_azure_eips.log': 'cluster_total_azure_eips.dat',
            'cluster_summary_node_count.log': 'cluster_node_count.dat',
            'cluster_summary_avg_eips_per_node.log': 'cluster_avg_eips_per_node.dat'
        }
        
        # Process each file type
        for log_suffix, dat_filename in file_mappings.items():
            data_file = self.data_dir / dat_filename
            
            with open(data_file, 'w') as outfile:
                # Process node-specific files
                for node in sorted(nodes):
                    log_file = self.logs_dir / f"{node}_{log_suffix}"
                    if log_file.exists():
                        outfile.write(f'"{node}"\n')
                        with open(log_file, 'r') as infile:
                            outfile.write(infile.read())
                        outfile.write('\n\n')
                        logging.info(f"Processed: {log_file.name} -> {dat_filename}")
                
                # If no node files were found, look for global files
                if not nodes:
                    global_log_file = self.logs_dir / log_suffix
                    if global_log_file.exists():
                        outfile.write('"global"\n')
                        with open(global_log_file, 'r') as infile:
                            outfile.write(infile.read())
                        outfile.write('\n\n')
                        logging.info(f"Processed global: {global_log_file.name} -> {dat_filename}")
        
        # Process cluster summary files
        for log_suffix, dat_filename in cluster_summary_mappings.items():
            cluster_log_file = self.logs_dir / log_suffix
            if cluster_log_file.exists():
                data_file = self.data_dir / dat_filename
                with open(data_file, 'w') as outfile:
                    outfile.write('"cluster"\n')
                    with open(cluster_log_file, 'r') as infile:
                        outfile.write(infile.read())
                    outfile.write('\n\n')
                    logging.info(f"Processed cluster: {cluster_log_file.name} -> {dat_filename}")
        
        # Process the detailed cluster EIP summary file
        cluster_details_file = self.logs_dir / 'cluster_eip_details.log'
        if cluster_details_file.exists():
            self.process_cluster_details(cluster_details_file)
        
        logging.info("Log merge completed successfully")
    
    def process_cluster_details(self, details_file: Path):
        """Process the cluster EIP details file into multiple data files."""
        logging.info("Processing cluster EIP details...")
        
        # Create data files for different views of the cluster data
        eip_by_node_file = self.data_dir / 'cluster_eips_by_node.dat'
        azure_by_node_file = self.data_dir / 'cluster_azure_by_node.dat'
        combined_summary_file = self.data_dir / 'cluster_combined_summary.dat'
        
        try:
            with open(details_file, 'r') as infile:
                content = infile.read()
            
            # Parse the content by timestamp blocks
            blocks = content.split('\n\n')
            
            with open(eip_by_node_file, 'w') as eip_out, \
                 open(azure_by_node_file, 'w') as azure_out, \
                 open(combined_summary_file, 'w') as combined_out:
                
                for block in blocks:
                    if not block.strip():
                        continue
                    
                    lines = block.strip().split('\n')
                    if not lines:
                        continue
                    
                    # Find the header line and extract timestamp
                    header_line = None
                    node_lines = []
                    total_line = None
                    
                    for line in lines:
                        if 'CLUSTER_SUMMARY' in line:
                            header_line = line
                            timestamp = line.split()[0]
                        elif 'TOTAL' in line:
                            total_line = line
                        elif line.strip() and 'CLUSTER_SUMMARY' not in line:
                            node_lines.append(line)
                    
                    if not header_line or not node_lines:
                        continue
                    
                    # Process node data for EIP assignments
                    eip_out.write(f'"{timestamp}"\n')
                    azure_out.write(f'"{timestamp}"\n')
                    combined_out.write(f'"{timestamp}"\n')
                    
                    for line in node_lines:
                        parts = line.split()
                        if len(parts) >= 4:
                            node_name = parts[1]
                            eip_assigned = parts[2]
                            azure_eips = parts[3]
                            
                            eip_out.write(f"{timestamp} {node_name}:{eip_assigned}\n")
                            azure_out.write(f"{timestamp} {node_name}:{azure_eips}\n")
                            combined_out.write(f"{timestamp} {node_name}_EIP:{eip_assigned} {node_name}_Azure:{azure_eips}\n")
                    
                    # Add total line if available
                    if total_line:
                        parts = total_line.split()
                        if len(parts) >= 4:
                            total_eip = parts[2]
                            total_azure = parts[3]
                            eip_out.write(f"{timestamp} TOTAL:{total_eip}\n")
                            azure_out.write(f"{timestamp} TOTAL:{total_azure}\n")
                            combined_out.write(f"{timestamp} TOTAL_EIP:{total_eip} TOTAL_Azure:{total_azure}\n")
                    
                    eip_out.write('\n')
                    azure_out.write('\n')
                    combined_out.write('\n')
            
            logging.info("Processed cluster details into:")
            logging.info(f"  - {eip_by_node_file.name}: EIP assignments by node")
            logging.info(f"  - {azure_by_node_file.name}: Azure IPs by node")  
            logging.info(f"  - {combined_summary_file.name}: Combined cluster summary")
            
        except Exception as e:
            logging.error(f"Error processing cluster details: {e}")


class PlotGenerator:
    """Generate plots from data files."""
    
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.data_dir = base_dir / 'data'
        self.plots_dir = base_dir / 'plots'
        self.plots_dir.mkdir(exist_ok=True)
    
    def normalize_title(self, filename: str) -> str:
        """Convert filename to readable title."""
        title = filename.replace('_', ' ').title()
        
        # Handle common abbreviations
        replacements = {
            'Ocp': 'OpenShift',
            'Eip': 'EIP',
            'Cpic': 'CPIC',
            'Lbs': 'Load Balancers'
        }
        
        for old, new in replacements.items():
            title = title.replace(old, new)
        
        return title
    
    def create_plot(self, data_file: Path):
        """Create a time-series plot from data file."""
        try:
            # Read the data file
            with open(data_file, 'r') as f:
                content = f.read()
            
            # Parse data sections (separated by node names in quotes)
            sections = content.split('\n\n')
            
            plt.figure(figsize=(16, 10))
            colors = ['green', 'red', 'blue', 'violet', 'orange', 'brown']
            
            for i, section in enumerate(sections):
                if not section.strip():
                    continue
                
                lines = section.strip().split('\n')
                if not lines:
                    continue
                
                # First line should be node name in quotes
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
            title = self.normalize_title(data_file.stem)
            plt.title(title, fontsize=16, fontweight='bold')
            plt.xlabel('Time', fontsize=12)
            plt.ylabel('Value', fontsize=12)
            plt.legend()
            plt.grid(True, alpha=0.3)
            
            # Format x-axis
            plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
            plt.gca().xaxis.set_major_locator(mdates.MinuteLocator(interval=10))
            plt.xticks(rotation=45)
            
            plt.tight_layout()
            
            # Save plot
            plot_file = self.plots_dir / f"{data_file.stem}-plot.png"
            plt.savefig(plot_file, dpi=150, bbox_inches='tight')
            plt.close()
            
            logging.info(f"Generated plot: {plot_file}")
            return True
            
        except Exception as e:
            logging.error(f"Error creating plot for {data_file}: {e}")
            return False
    
    def generate_all_plots(self):
        """Generate plots for all data files."""
        logging.info("Starting plot generation...")
        
        data_files = list(self.data_dir.glob('*.dat'))
        if not data_files:
            raise EIPToolkitError("No .dat files found for plotting")
        
        success_count = 0
        for data_file in data_files:
            if self.create_plot(data_file):
                success_count += 1
        
        logging.info(f"Plot generation complete: {success_count}/{len(data_files)} successful")


class EIPToolkit:
    """Main EIP Toolkit application."""
    
    def __init__(self):
        self.setup_logging()
    
    def setup_logging(self):
        """Setup logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def validate_environment(self):
        """Validate required environment variables."""
        subscription = os.getenv('AZ_SUBSCRIPTION')
        resource_group = os.getenv('AZ_RESOURCE_GROUP')
        
        if not subscription:
            raise EIPToolkitError("AZ_SUBSCRIPTION environment variable not set")
        if not resource_group:
            raise EIPToolkitError("AZ_RESOURCE_GROUP environment variable not set")
        
        return subscription, resource_group
    
    def cmd_monitor(self, args):
        """Handle monitor command."""
        subscription_id, resource_group = self.validate_environment()
        
        # Create timestamped output directory
        timestamp = datetime.now().strftime('%y%m%d_%H%M%S')
        output_dir = Path('../runs') / timestamp
        
        monitor = EIPMonitor(output_dir, subscription_id, resource_group)
        
        # Check if monitoring is needed
        eip_stats = monitor.oc_client.get_eip_stats()
        cpic_stats = monitor.oc_client.get_cpic_stats()
        
        if not monitor.should_continue_monitoring(eip_stats, cpic_stats):
            self.logger.info("No monitoring needed - all EIPs properly configured")
            return
        
        monitor.monitor_loop()
    
    def cmd_merge(self, args):
        """Handle merge command."""
        base_dir = Path(args.directory)
        if not base_dir.exists():
            raise EIPToolkitError(f"Directory {base_dir} does not exist")
        
        processor = DataProcessor(base_dir)
        processor.merge_logs()
    
    def cmd_plot(self, args):
        """Handle plot command."""
        base_dir = Path(args.directory)
        if not base_dir.exists():
            raise EIPToolkitError(f"Directory {base_dir} does not exist")
        
        plotter = PlotGenerator(base_dir)
        plotter.generate_all_plots()
    
    def cmd_all(self, args):
        """Handle complete pipeline command."""
        subscription_id, resource_group = self.validate_environment()
        
        self.logger.info("🚀 Starting Complete EIP Pipeline: Monitor → Merge → Plot")
        
        # Phase 1: Monitor
        self.logger.info("📊 Phase 1: Starting EIP Monitoring...")
        timestamp = datetime.now().strftime('%y%m%d_%H%M%S')
        output_dir = Path('../runs') / timestamp
        
        monitor = EIPMonitor(output_dir, subscription_id, resource_group)
        
        # Check if monitoring is needed
        eip_stats = monitor.oc_client.get_eip_stats()
        cpic_stats = monitor.oc_client.get_cpic_stats()
        
        if not monitor.should_continue_monitoring(eip_stats, cpic_stats):
            self.logger.info("No monitoring needed - pipeline complete")
            return
        
        monitor.monitor_loop()
        self.logger.info("✅ Phase 1 Complete: Monitoring finished")
        
        # Phase 2: Merge
        self.logger.info("🔄 Phase 2: Starting Log Merge...")
        processor = DataProcessor(output_dir)
        processor.merge_logs()
        self.logger.info("✅ Phase 2 Complete: Log merge finished")
        
        # Phase 3: Plot
        self.logger.info("📈 Phase 3: Starting Plot Generation...")
        plotter = PlotGenerator(output_dir)
        plotter.generate_all_plots()
        self.logger.info("✅ Phase 3 Complete: Plot generation finished")
        
        # Final summary
        self.logger.info("🎉 PIPELINE COMPLETE! 🎉")
        self.logger.info(f"📁 All outputs saved in: {output_dir}")
        self.logger.info(f"📝 Raw logs: {output_dir}/logs/*.log")
        self.logger.info(f"📊 Data files: {output_dir}/data/*.dat")
        self.logger.info(f"📈 Plots: {output_dir}/plots/*.png")
    
    def cmd_monitor_async(self, args):
        """Handle async monitor command."""
        subscription_id, resource_group = self.validate_environment()
        
        # Create timestamped output directory
        timestamp = datetime.now().strftime('%y%m%d_%H%M%S')
        output_dir = Path('../runs') / timestamp
        
        monitor = EIPMonitor(output_dir, subscription_id, resource_group)
        
        # Check if monitoring is needed
        eip_stats = monitor.oc_client.get_eip_stats()
        cpic_stats = monitor.oc_client.get_cpic_stats()
        
        if not monitor.should_continue_monitoring(eip_stats, cpic_stats):
            self.logger.info("No monitoring needed - all EIPs properly configured")
            return
        
        # Run async monitoring
        asyncio.run(monitor.monitor_loop_async())
    
    def cmd_merge_optimized(self, args):
        """Handle optimized merge command."""
        base_dir = Path(args.directory)
        if not base_dir.exists():
            raise EIPToolkitError(f"Directory {base_dir} does not exist")
        
        processor = OptimizedDataProcessor(base_dir)
        processor.merge_logs_optimized()
    
    def cmd_all_optimized(self, args):
        """Handle complete optimized pipeline command."""
        subscription_id, resource_group = self.validate_environment()
        
        self.logger.info("🚀 Starting OPTIMIZED EIP Pipeline: Monitor → Merge → Plot")
        
        # Phase 1: Async Monitor
        self.logger.info("📊 Phase 1: Starting Async EIP Monitoring...")
        timestamp = datetime.now().strftime('%y%m%d_%H%M%S')
        output_dir = Path('../runs') / timestamp
        
        monitor = EIPMonitor(output_dir, subscription_id, resource_group)
        
        # Check if monitoring is needed
        eip_stats = monitor.oc_client.get_eip_stats()
        cpic_stats = monitor.oc_client.get_cpic_stats()
        
        if not monitor.should_continue_monitoring(eip_stats, cpic_stats):
            self.logger.info("No monitoring needed - pipeline complete")
            return
        
        # Run async monitoring
        asyncio.run(monitor.monitor_loop_async())
        self.logger.info("✅ Phase 1 Complete: Async monitoring finished")
        
        # Phase 2: Optimized Merge
        self.logger.info("🔄 Phase 2: Starting Optimized Log Merge...")
        processor = OptimizedDataProcessor(output_dir)
        processor.merge_logs_optimized()
        self.logger.info("✅ Phase 2 Complete: Optimized log merge finished")
        
        # Phase 3: Plot
        self.logger.info("📈 Phase 3: Starting Plot Generation...")
        plotter = PlotGenerator(output_dir)
        plotter.generate_all_plots()
        self.logger.info("✅ Phase 3 Complete: Plot generation finished")
        
        # Final summary
        self.logger.info("🎉 OPTIMIZED PIPELINE COMPLETE! 🎉")
        self.logger.info(f"📁 All outputs saved in: {output_dir}")
        self.logger.info(f"📝 Raw logs: {output_dir}/logs/*.log")
        self.logger.info(f"📊 Data files: {output_dir}/data/*.dat")
        self.logger.info(f"📈 Plots: {output_dir}/plots/*.png")
    
    def main(self):
        """Main entry point."""
        parser = argparse.ArgumentParser(
            description='EIP Toolkit - Monitor, analyze, and visualize ARO EIP assignments',
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        
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
        
        # Async monitor command
        subparsers.add_parser('monitor-async', help='Monitor EIP and CPIC status with async optimization')
        
        # Optimized merge command
        merge_opt_parser = subparsers.add_parser('merge-optimized', help='Optimized merge using pandas')
        merge_opt_parser.add_argument('directory', help='Directory containing log files')
        
        # All optimized command
        subparsers.add_parser('all-optimized', help='Run complete optimized pipeline')
        
        args = parser.parse_args()
        
        if not args.command:
            parser.print_help()
            return 1
        
        try:
            if args.command == 'monitor':
                self.cmd_monitor(args)
            elif args.command == 'monitor-async':
                self.cmd_monitor_async(args)
            elif args.command == 'merge':
                self.cmd_merge(args)
            elif args.command == 'merge-optimized':
                self.cmd_merge_optimized(args)
            elif args.command == 'plot':
                self.cmd_plot(args)
            elif args.command == 'all':
                self.cmd_all(args)
            elif args.command == 'all-optimized':
                self.cmd_all_optimized(args)
            
            return 0
            
        except EIPToolkitError as e:
            self.logger.error(f"Error: {e}")
            return 1
        except KeyboardInterrupt:
            self.logger.info("Interrupted by user")
            return 1
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
            return 1


if __name__ == '__main__':
    toolkit = EIPToolkit()
    sys.exit(toolkit.main())
