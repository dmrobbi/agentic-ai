#!/usr/bin/env python3
"""
KaliAgent v3 - Production Monitoring & Performance
===================================================

Resource monitoring, performance optimization, and alerting.

Tasks: 5.1.1, 5.1.2, 5.1.3
Status: IMPLEMENTED
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

# Try to import psutil
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logging.debug("psutil not available - using mock mode")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class AlertLevel(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class ResourceType(Enum):
    """Resource types to monitor."""
    CPU = "cpu"
    MEMORY = "memory"
    DISK = "disk"
    NETWORK = "network"
    PROCESSES = "processes"


@dataclass
class ResourceMetric:
    """Single resource metric."""
    resource: ResourceType
    value: float
    unit: str
    timestamp: datetime
    threshold_warning: float
    threshold_critical: float
    
    def to_dict(self) -> Dict:
        return {
            'resource': self.resource.value,
            'value': self.value,
            'unit': self.unit,
            'timestamp': self.timestamp.isoformat(),
            'threshold_warning': self.threshold_warning,
            'threshold_critical': self.threshold_critical
        }


@dataclass
class Alert:
    """System alert."""
    id: str
    level: AlertLevel
    resource: ResourceType
    message: str
    value: float
    threshold: float
    timestamp: datetime
    acknowledged: bool = False
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'level': self.level.value,
            'resource': self.resource.value,
            'message': self.message,
            'value': self.value,
            'threshold': self.threshold,
            'timestamp': self.timestamp.isoformat(),
            'acknowledged': self.acknowledged
        }


@dataclass
class SystemHealth:
    """Overall system health status."""
    status: str  # healthy, degraded, critical
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_rx_mb: float
    network_tx_mb: float
    active_processes: int
    alerts_count: int
    last_check: datetime


class SystemMonitor:
    """
    System resource monitoring.
    
    Provides:
    - Real-time resource monitoring
    - Threshold-based alerting
    - Performance metrics collection
    - Health status reporting
    """
    
    def __init__(self, config_dir: Optional[Path] = None):
        """Initialize system monitor."""
        self.config_dir = config_dir or Path.home() / 'kali_agent_v3' / 'production'
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Thresholds
        self.thresholds = {
            ResourceType.CPU: {'warning': 70.0, 'critical': 90.0},
            ResourceType.MEMORY: {'warning': 75.0, 'critical': 90.0},
            ResourceType.DISK: {'warning': 80.0, 'critical': 95.0},
            ResourceType.NETWORK: {'warning': 80.0, 'critical': 95.0},
            ResourceType.PROCESSES: {'warning': 200, 'critical': 500}
        }
        
        # Metrics history
        self.metrics_history: List[ResourceMetric] = []
        self.alerts: List[Alert] = []
        self.alert_counter = 0
        
        # Load config
        self._load_config()
        
        logger.info(f"System monitor initialized (config: {self.config_dir})")
    
    def _load_config(self):
        """Load monitoring configuration."""
        config_file = self.config_dir / 'monitoring_config.json'
        
        if config_file.exists():
            with open(config_file, 'r') as f:
                config = json.load(f)
            
            # Load thresholds
            for resource_str, thresholds in config.get('thresholds', {}).items():
                resource = ResourceType(resource_str)
                self.thresholds[resource] = thresholds
            
            logger.info("Monitoring configuration loaded")
    
    def _save_config(self):
        """Save monitoring configuration."""
        config = {
            'thresholds': {
                r.value: t for r, t in self.thresholds.items()
            },
            'last_updated': datetime.now().isoformat()
        }
        
        config_file = self.config_dir / 'monitoring_config.json'
        
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
    
    # =====================================================================
    # Task 5.1.1: Performance Optimization
    # =====================================================================
    
    def get_cpu_usage(self) -> float:
        """Get current CPU usage percentage."""
        if not PSUTIL_AVAILABLE:
            return 25.0  # Mock value
        return psutil.cpu_percent(interval=1)
    
    def get_memory_usage(self) -> Dict:
        """Get memory usage statistics."""
        if not PSUTIL_AVAILABLE:
            return {
                'total_mb': 8192,
                'available_mb': 4096,
                'used_mb': 4096,
                'percent': 50.0,
                'swap_total_mb': 2048,
                'swap_used_mb': 512,
                'swap_percent': 25.0
            }
        mem = psutil.virtual_memory()
        
        return {
            'total_mb': mem.total / (1024 * 1024),
            'available_mb': mem.available / (1024 * 1024),
            'used_mb': mem.used / (1024 * 1024),
            'percent': mem.percent,
            'swap_total_mb': psutil.swap_memory().total / (1024 * 1024),
            'swap_used_mb': psutil.swap_memory().used / (1024 * 1024),
            'swap_percent': psutil.swap_memory().percent
        }
    
    def get_disk_usage(self, path: str = '/') -> Dict:
        """Get disk usage statistics."""
        if not PSUTIL_AVAILABLE:
            return {
                'total_gb': 500,
                'used_gb': 200,
                'free_gb': 300,
                'percent': 40.0
            }
        disk = psutil.disk_usage(path)
        
        return {
            'total_gb': disk.total / (1024 * 1024 * 1024),
            'used_gb': disk.used / (1024 * 1024 * 1024),
            'free_gb': disk.free / (1024 * 1024 * 1024),
            'percent': disk.percent
        }
    
    def get_network_io(self) -> Dict:
        """Get network I/O statistics."""
        if not PSUTIL_AVAILABLE:
            return {
                'bytes_sent': 1024000,
                'bytes_recv': 2048000,
                'packets_sent': 1000,
                'packets_recv': 2000,
                'errors_in': 0,
                'errors_out': 0,
                'drops_in': 0,
                'drops_out': 0
            }
        net = psutil.net_io_counters()
        
        return {
            'bytes_sent': net.bytes_sent,
            'bytes_recv': net.bytes_recv,
            'packets_sent': net.packets_sent,
            'packets_recv': net.packets_recv,
            'errors_in': net.errin,
            'errors_out': net.errout,
            'drops_in': net.dropin,
            'drops_out': net.dropout
        }
    
    def get_process_count(self) -> int:
        """Get number of running processes."""
        if not PSUTIL_AVAILABLE:
            return 150  # Mock value
        return len(psutil.pids())
    
    def get_top_processes(self, limit: int = 10) -> List[Dict]:
        """Get top processes by CPU usage."""
        if not PSUTIL_AVAILABLE:
            return [
                {'pid': 1, 'name': 'init', 'cpu_percent': 0.1, 'memory_percent': 0.5},
                {'pid': 1234, 'name': 'python3', 'cpu_percent': 5.0, 'memory_percent': 2.0}
            ]
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'cpu_percent': proc.info['cpu_percent'] or 0,
                    'memory_percent': proc.info['memory_percent'] or 0
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Sort by CPU usage
        processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
        
        return processes[:limit]
    
    # =====================================================================
    # Task 5.1.2: Resource Monitoring
    # =====================================================================
    
    def check_resources(self) -> List[ResourceMetric]:
        """
        Check all monitored resources.
        
        Returns:
            List of ResourceMetric objects
        """
        logger.debug("Checking system resources...")
        
        metrics = []
        now = datetime.now()
        
        # CPU
        cpu_usage = self.get_cpu_usage()
        metrics.append(ResourceMetric(
            resource=ResourceType.CPU,
            value=cpu_usage,
            unit='percent',
            timestamp=now,
            threshold_warning=self.thresholds[ResourceType.CPU]['warning'],
            threshold_critical=self.thresholds[ResourceType.CPU]['critical']
        ))
        
        # Memory
        mem_usage = self.get_memory_usage()
        metrics.append(ResourceMetric(
            resource=ResourceType.MEMORY,
            value=mem_usage['percent'],
            unit='percent',
            timestamp=now,
            threshold_warning=self.thresholds[ResourceType.MEMORY]['warning'],
            threshold_critical=self.thresholds[ResourceType.MEMORY]['critical']
        ))
        
        # Disk
        disk_usage = self.get_disk_usage()
        metrics.append(ResourceMetric(
            resource=ResourceType.DISK,
            value=disk_usage['percent'],
            unit='percent',
            timestamp=now,
            threshold_warning=self.thresholds[ResourceType.DISK]['warning'],
            threshold_critical=self.thresholds[ResourceType.DISK]['critical']
        ))
        
        # Processes
        proc_count = self.get_process_count()
        metrics.append(ResourceMetric(
            resource=ResourceType.PROCESSES,
            value=proc_count,
            unit='count',
            timestamp=now,
            threshold_warning=self.thresholds[ResourceType.PROCESSES]['warning'],
            threshold_critical=self.thresholds[ResourceType.PROCESSES]['critical']
        ))
        
        # Store in history
        self.metrics_history.extend(metrics)
        
        # Keep last 1000 metrics
        if len(self.metrics_history) > 1000:
            self.metrics_history = self.metrics_history[-1000:]
        
        # Check thresholds and generate alerts
        self._check_thresholds(metrics)
        
        return metrics
    
    def _check_thresholds(self, metrics: List[ResourceMetric]):
        """Check metrics against thresholds and generate alerts."""
        for metric in metrics:
            if metric.value >= metric.threshold_critical:
                self._create_alert(
                    level=AlertLevel.CRITICAL,
                    resource=metric.resource,
                    message=f"{metric.resource.value.upper()} usage critical: {metric.value:.1f}{metric.unit}",
                    value=metric.value,
                    threshold=metric.threshold_critical
                )
            elif metric.value >= metric.threshold_warning:
                self._create_alert(
                    level=AlertLevel.WARNING,
                    resource=metric.resource,
                    message=f"{metric.resource.value.upper()} usage warning: {metric.value:.1f}{metric.unit}",
                    value=metric.value,
                    threshold=metric.threshold_warning
                )
    
    def _create_alert(self, level: AlertLevel, resource: ResourceType,
                     message: str, value: float, threshold: float):
        """Create a new alert."""
        self.alert_counter += 1
        
        alert = Alert(
            id=f'alert_{self.alert_counter}_{datetime.now().strftime("%Y%m%d%H%M%S")}',
            level=level,
            resource=resource,
            message=message,
            value=value,
            threshold=threshold,
            timestamp=datetime.now()
        )
        
        self.alerts.append(alert)
        
        # Keep last 100 alerts
        if len(self.alerts) > 100:
            self.alerts = self.alerts[-100:]
        
        logger.warning(f"Alert created: {alert.message}")
        
        # Save alerts
        self._save_alerts()
    
    def _save_alerts(self):
        """Save alerts to file."""
        alerts_file = self.config_dir / 'alerts.json'
        
        with open(alerts_file, 'w') as f:
            json.dump([a.to_dict() for a in self.alerts], f, indent=2)
    
    # =====================================================================
    # Task 5.1.3: Logging & Alerting
    # =====================================================================
    
    def get_health_status(self) -> SystemHealth:
        """Get overall system health status."""
        # Check resources
        metrics = self.check_resources()
        
        # Determine status
        critical_count = sum(1 for m in metrics if m.value >= m.threshold_critical)
        warning_count = sum(1 for m in metrics if m.value >= m.threshold_warning)
        
        if critical_count > 0:
            status = 'critical'
        elif warning_count > 0:
            status = 'degraded'
        else:
            status = 'healthy'
        
        # Get network I/O
        net_io = self.get_network_io()
        
        return SystemHealth(
            status=status,
            cpu_usage=next((m.value for m in metrics if m.resource == ResourceType.CPU), 0),
            memory_usage=next((m.value for m in metrics if m.resource == ResourceType.MEMORY), 0),
            disk_usage=next((m.value for m in metrics if m.resource == ResourceType.DISK), 0),
            network_rx_mb=net_io['bytes_recv'] / (1024 * 1024),
            network_tx_mb=net_io['bytes_sent'] / (1024 * 1024),
            active_processes=self.get_process_count(),
            alerts_count=len([a for a in self.alerts if not a.acknowledged]),
            last_check=datetime.now()
        )
    
    def get_alerts(self, level: Optional[AlertLevel] = None,
                  unacknowledged_only: bool = False) -> List[Alert]:
        """Get alerts with optional filtering."""
        alerts = self.alerts
        
        if level:
            alerts = [a for a in alerts if a.level == level]
        
        if unacknowledged_only:
            alerts = [a for a in alerts if not a.acknowledged]
        
        return alerts
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert."""
        for alert in self.alerts:
            if alert.id == alert_id:
                alert.acknowledged = True
                self._save_alerts()
                logger.info(f"Alert acknowledged: {alert_id}")
                return True
        
        return False
    
    def clear_acknowledged_alerts(self) -> int:
        """Clear all acknowledged alerts."""
        initial_count = len(self.alerts)
        self.alerts = [a for a in self.alerts if not a.acknowledged]
        cleared = initial_count - len(self.alerts)
        
        if cleared > 0:
            self._save_alerts()
            logger.info(f"Cleared {cleared} acknowledged alerts")
        
        return cleared
    
    def get_metrics_history(self, resource: Optional[ResourceType] = None,
                           hours: int = 1) -> List[Dict]:
        """Get metrics history."""
        cutoff = datetime.now() - timedelta(hours=hours)
        
        metrics = [m for m in self.metrics_history if m.timestamp > cutoff]
        
        if resource:
            metrics = [m for m in metrics if m.resource == resource]
        
        return [m.to_dict() for m in metrics]
    
    def export_report(self, output_path: Optional[Path] = None) -> Path:
        """Export monitoring report."""
        if not output_path:
            output_path = self.config_dir / f'report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        
        health = self.get_health_status()
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'health': {
                'status': health.status,
                'cpu_usage': health.cpu_usage,
                'memory_usage': health.memory_usage,
                'disk_usage': health.disk_usage,
                'network_rx_mb': health.network_rx_mb,
                'network_tx_mb': health.network_tx_mb,
                'active_processes': health.active_processes,
                'alerts_count': health.alerts_count
            },
            'thresholds': {
                r.value: t for r, t in self.thresholds.items()
            },
            'recent_alerts': [a.to_dict() for a in self.alerts[-20:]],
            'top_processes': self.get_top_processes(10),
            'metrics_sample': [m.to_dict() for m in self.metrics_history[-100:]]
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report exported: {output_path}")
        
        return output_path
    
    def set_threshold(self, resource: ResourceType, warning: float,
                     critical: float) -> bool:
        """Set custom thresholds for a resource."""
        if warning >= critical:
            logger.error("Warning threshold must be less than critical")
            return False
        
        self.thresholds[resource] = {
            'warning': warning,
            'critical': critical
        }
        
        self._save_config()
        
        logger.info(f"Thresholds updated for {resource.value}: warning={warning}, critical={critical}")
        
        return True


# =============================================================================
# CLI Interface
# =============================================================================

def main():
    """Command-line interface for system monitoring."""
    import argparse
    
    parser = argparse.ArgumentParser(description='KaliAgent v3 - System Monitoring')
    parser.add_argument('--status', action='store_true', help='Show system status')
    parser.add_argument('--alerts', action='store_true', help='Show alerts')
    parser.add_argument('--acknowledge', type=str, help='Acknowledge alert by ID')
    parser.add_argument('--clear-alerts', action='store_true', help='Clear acknowledged alerts')
    parser.add_argument('--history', type=int, default=1, help='Hours of history')
    parser.add_argument('--resource', type=str, choices=['cpu', 'memory', 'disk', 'network'],
                       help='Specific resource')
    parser.add_argument('--export', action='store_true', help='Export report')
    parser.add_argument('--set-threshold', type=str, help='Set threshold (resource:warning:critical)')
    
    args = parser.parse_args()
    
    monitor = SystemMonitor()
    
    if args.status:
        health = monitor.get_health_status()
        
        print("\nSystem Health Status")
        print("=" * 60)
        
        status_icon = "🟢" if health.status == 'healthy' else "🟡" if health.status == 'degraded' else "🔴"
        print(f"Status: {status_icon} {health.status.upper()}")
        print("\nResources:")
        print(f"  CPU:     {health.cpu_usage:.1f}%")
        print(f"  Memory:  {health.memory_usage:.1f}%")
        print(f"  Disk:    {health.disk_usage:.1f}%")
        print(f"  Network: RX={health.network_rx_mb:.1f}MB, TX={health.network_tx_mb:.1f}MB")
        print(f"  Processes: {health.active_processes}")
        print(f"\nAlerts: {health.alerts_count} unacknowledged")
        print(f"Last Check: {health.last_check.isoformat()}")
        print("=" * 60)
    
    elif args.alerts:
        alerts = monitor.get_alerts(unacknowledged_only=True)
        
        print(f"\nUnacknowledged Alerts: {len(alerts)}")
        print("=" * 60)
        
        for alert in alerts:
            icon = "🔴" if alert.level == AlertLevel.CRITICAL else "🟡"
            print(f"{icon} [{alert.level.value.upper()}] {alert.message}")
            print(f"   Value: {alert.value:.1f}, Threshold: {alert.threshold:.1f}")
            print(f"   Time: {alert.timestamp.isoformat()}")
            print(f"   ID: {alert.id}")
            print()
        
        print("=" * 60)
    
    elif args.acknowledge:
        success = monitor.acknowledge_alert(args.acknowledge)
        status = "✅" if success else "❌"
        print(f"{status} Alert acknowledged: {args.acknowledge}")
    
    elif args.clear_alerts:
        cleared = monitor.clear_acknowledged_alerts()
        print(f"✅ Cleared {cleared} acknowledged alerts")
    
    elif args.history:
        resource = ResourceType(args.resource) if args.resource else None
        metrics = monitor.get_metrics_history(resource, args.history)
        
        print(f"\nMetrics History ({args.history} hour(s)): {len(metrics)} data points")
        print("=" * 60)
        
        if metrics:
            print(f"Latest: {metrics[-1]['resource']} = {metrics[-1]['value']:.1f} {metrics[-1]['unit']}")
            print(f"Time Range: {metrics[0]['timestamp']} to {metrics[-1]['timestamp']}")
        
        print("=" * 60)
    
    elif args.export:
        path = monitor.export_report()
        print(f"✅ Report exported: {path}")
    
    elif args.set_threshold:
        parts = args.set_threshold.split(':')
        if len(parts) != 3:
            print("❌ Format: resource:warning:critical (e.g., cpu:70:90)")
            return
        
        try:
            resource = ResourceType(parts[0])
            warning = float(parts[1])
            critical = float(parts[2])
            
            success = monitor.set_threshold(resource, warning, critical)
            status = "✅" if success else "❌"
            print(f"{status} Thresholds updated for {resource.value}")
        except ValueError as e:
            print(f"❌ Invalid values: {e}")
    
    else:
        # Default: show status
        health = monitor.get_health_status()
        status_icon = "🟢" if health.status == 'healthy' else "🟡" if health.status == 'degraded' else "🔴"
        print(f"\n{status_icon} System Status: {health.status.upper()}")
        print(f"   CPU: {health.cpu_usage:.1f}% | Memory: {health.memory_usage:.1f}% | Disk: {health.disk_usage:.1f}%")
        print(f"   Alerts: {health.alerts_count}")
        print("\nUse --help for options")


if __name__ == '__main__':
    main()
