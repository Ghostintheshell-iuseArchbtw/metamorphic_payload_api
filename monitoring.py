"""
Advanced Monitoring and Metrics System for Metamorphic Payload API
Provides real-time monitoring, alerting, and comprehensive metrics collection.
"""

import time
import threading
import json
import sqlite3
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import psutil
import logging

from config import config
from logging_config import app_logger

@dataclass
class MetricPoint:
    """Individual metric data point"""
    timestamp: float
    metric_name: str
    value: float
    tags: Dict[str, str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = {}

@dataclass
class AlertRule:
    """Alert rule configuration"""
    name: str
    metric_name: str
    condition: str  # 'gt', 'lt', 'eq'
    threshold: float
    duration_minutes: int = 5
    enabled: bool = True
    last_triggered: Optional[float] = None

class MetricsCollector:
    """Collects and stores system and application metrics"""
    
    def __init__(self, db_path: str = "metrics.db"):
        self.db_path = Path(db_path)
        self.metrics_buffer = deque(maxlen=10000)  # In-memory buffer
        self.lock = threading.Lock()
        self.running = False
        self.collection_thread = None
        self._init_database()
        
    def _init_database(self):
        """Initialize SQLite database for metrics storage"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    metric_name TEXT NOT NULL,
                    value REAL NOT NULL,
                    tags TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_metrics_timestamp 
                ON metrics(timestamp)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_metrics_name_timestamp 
                ON metrics(metric_name, timestamp)
            """)
    
    def record_metric(self, name: str, value: float, tags: Dict[str, str] = None):
        """Record a metric data point"""
        metric = MetricPoint(
            timestamp=time.time(),
            metric_name=name,
            value=value,
            tags=tags or {}
        )
        
        with self.lock:
            self.metrics_buffer.append(metric)
    
    def start_collection(self, interval: float = 30.0):
        """Start automated system metrics collection"""
        if self.running:
            return
        
        self.running = True
        self.collection_thread = threading.Thread(
            target=self._collection_loop,
            args=(interval,),
            daemon=True
        )
        self.collection_thread.start()
        app_logger.info("Metrics collection started")
    
    def stop_collection(self):
        """Stop metrics collection"""
        self.running = False
        if self.collection_thread:
            self.collection_thread.join(timeout=5)
        app_logger.info("Metrics collection stopped")
    
    def _collection_loop(self, interval: float):
        """Main metrics collection loop"""
        while self.running:
            try:
                self._collect_system_metrics()
                self._flush_to_database()
                time.sleep(interval)
            except Exception as e:
                app_logger.error(f"Error in metrics collection: {e}")
                time.sleep(interval)
    
    def _collect_system_metrics(self):
        """Collect system performance metrics"""
        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        self.record_metric("system.cpu.percent", cpu_percent)
        
        # Memory metrics
        memory = psutil.virtual_memory()
        self.record_metric("system.memory.percent", memory.percent)
        self.record_metric("system.memory.available_mb", memory.available / 1024 / 1024)
        self.record_metric("system.memory.used_mb", memory.used / 1024 / 1024)
        
        # Disk metrics
        try:
            disk = psutil.disk_usage('/')
            self.record_metric("system.disk.percent", (disk.used / disk.total) * 100)
            self.record_metric("system.disk.free_gb", disk.free / 1024 / 1024 / 1024)
        except:
            # Windows compatibility
            try:
                disk = psutil.disk_usage('C:\\')
                self.record_metric("system.disk.percent", (disk.used / disk.total) * 100)
                self.record_metric("system.disk.free_gb", disk.free / 1024 / 1024 / 1024)
            except:
                pass
        
        # Network I/O
        try:
            net_io = psutil.net_io_counters()
            self.record_metric("system.network.bytes_sent", net_io.bytes_sent)
            self.record_metric("system.network.bytes_recv", net_io.bytes_recv)
        except:
            pass
        
        # Process metrics (for current process)
        try:
            process = psutil.Process()
            self.record_metric("process.cpu.percent", process.cpu_percent())
            self.record_metric("process.memory.rss_mb", process.memory_info().rss / 1024 / 1024)
            self.record_metric("process.memory.vms_mb", process.memory_info().vms / 1024 / 1024)
            self.record_metric("process.threads", process.num_threads())
            self.record_metric("process.open_files", len(process.open_files()))
        except:
            pass
    
    def _flush_to_database(self):
        """Flush metrics buffer to database"""
        if not self.metrics_buffer:
            return
        
        with self.lock:
            metrics_to_flush = list(self.metrics_buffer)
            self.metrics_buffer.clear()
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                for metric in metrics_to_flush:
                    conn.execute("""
                        INSERT INTO metrics (timestamp, metric_name, value, tags)
                        VALUES (?, ?, ?, ?)
                    """, (
                        metric.timestamp,
                        metric.metric_name,
                        metric.value,
                        json.dumps(metric.tags)
                    ))
        except Exception as e:
            app_logger.error(f"Error flushing metrics to database: {e}")
    
    def get_metrics(self, metric_name: str, hours: int = 24) -> List[MetricPoint]:
        """Get historical metrics"""
        cutoff_time = time.time() - (hours * 3600)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT timestamp, metric_name, value, tags
                FROM metrics
                WHERE metric_name = ? AND timestamp > ?
                ORDER BY timestamp DESC
            """, (metric_name, cutoff_time))
            
            return [
                MetricPoint(
                    timestamp=row[0],
                    metric_name=row[1],
                    value=row[2],
                    tags=json.loads(row[3]) if row[3] else {}
                )
                for row in cursor.fetchall()
            ]
    
    def get_metric_summary(self, metric_name: str, hours: int = 24) -> Dict[str, float]:
        """Get statistical summary of a metric"""
        metrics = self.get_metrics(metric_name, hours)
        if not metrics:
            return {}
        
        values = [m.value for m in metrics]
        return {
            'count': len(values),
            'min': min(values),
            'max': max(values),
            'mean': statistics.mean(values),
            'median': statistics.median(values),
            'stdev': statistics.stdev(values) if len(values) > 1 else 0
        }

class ApplicationMetrics:
    """Application-specific metrics tracking"""
    
    def __init__(self, collector: MetricsCollector):
        self.collector = collector
        self.request_times = defaultdict(list)
        self.counters = defaultdict(int)
        self.gauges = defaultdict(float)
        self.lock = threading.Lock()
    
    def record_request(self, endpoint: str, duration: float, status_code: int):
        """Record API request metrics"""
        tags = {
            'endpoint': endpoint,
            'status_code': str(status_code),
            'status_class': f"{status_code // 100}xx"
        }
        
        self.collector.record_metric("api.request.duration", duration, tags)
        self.collector.record_metric("api.request.count", 1, tags)
        
        with self.lock:
            self.request_times[endpoint].append(duration)
            self.counters[f"requests.{endpoint}"] += 1
            self.counters[f"status.{status_code}"] += 1
    
    def record_payload_generation(self, duration: float, size: int, complexity: int):
        """Record payload generation metrics"""
        self.collector.record_metric("payload.generation.duration", duration)
        self.collector.record_metric("payload.generation.size", size)
        self.collector.record_metric("payload.generation.complexity", complexity)
        
        with self.lock:
            self.counters["payloads.generated"] += 1
            self.gauges["payload.avg_size"] = size
            self.gauges["payload.avg_complexity"] = complexity
    
    def record_error(self, error_type: str, endpoint: str = None):
        """Record error metrics"""
        tags = {'error_type': error_type}
        if endpoint:
            tags['endpoint'] = endpoint
        
        self.collector.record_metric("errors.count", 1, tags)
        
        with self.lock:
            self.counters[f"errors.{error_type}"] += 1
    
    def get_request_stats(self, endpoint: str = None) -> Dict[str, Any]:
        """Get request statistics"""
        with self.lock:
            if endpoint and endpoint in self.request_times:
                times = self.request_times[endpoint]
                if times:
                    return {
                        'count': len(times),
                        'avg_duration': statistics.mean(times),
                        'min_duration': min(times),
                        'max_duration': max(times),
                        'p95_duration': sorted(times)[int(len(times) * 0.95)] if len(times) > 20 else max(times)
                    }
            
            # Return overall stats
            all_times = []
            for times in self.request_times.values():
                all_times.extend(times)
            
            if all_times:
                return {
                    'total_requests': len(all_times),
                    'avg_duration': statistics.mean(all_times),
                    'min_duration': min(all_times),
                    'max_duration': max(all_times),
                    'p95_duration': sorted(all_times)[int(len(all_times) * 0.95)] if len(all_times) > 20 else max(all_times),
                    'endpoints': list(self.request_times.keys())
                }
            
            return {}

class AlertManager:
    """Manages alerting based on metric thresholds"""
    
    def __init__(self, collector: MetricsCollector):
        self.collector = collector
        self.rules: List[AlertRule] = []
        self.running = False
        self.check_thread = None
        self.alert_callbacks = []
    
    def add_rule(self, rule: AlertRule):
        """Add an alert rule"""
        self.rules.append(rule)
        app_logger.info(f"Added alert rule: {rule.name}")
    
    def add_alert_callback(self, callback):
        """Add a callback function to be called when alerts trigger"""
        self.alert_callbacks.append(callback)
    
    def start_monitoring(self, check_interval: float = 60.0):
        """Start alert monitoring"""
        if self.running:
            return
        
        self.running = True
        self.check_thread = threading.Thread(
            target=self._monitoring_loop,
            args=(check_interval,),
            daemon=True
        )
        self.check_thread.start()
        app_logger.info("Alert monitoring started")
    
    def stop_monitoring(self):
        """Stop alert monitoring"""
        self.running = False
        if self.check_thread:
            self.check_thread.join(timeout=5)
        app_logger.info("Alert monitoring stopped")
    
    def _monitoring_loop(self, interval: float):
        """Main alert checking loop"""
        while self.running:
            try:
                for rule in self.rules:
                    if rule.enabled:
                        self._check_rule(rule)
                time.sleep(interval)
            except Exception as e:
                app_logger.error(f"Error in alert monitoring: {e}")
                time.sleep(interval)
    
    def _check_rule(self, rule: AlertRule):
        """Check a specific alert rule"""
        try:
            # Get recent metrics for the rule
            duration_seconds = rule.duration_minutes * 60
            cutoff_time = time.time() - duration_seconds
            
            with sqlite3.connect(self.collector.db_path) as conn:
                cursor = conn.execute("""
                    SELECT value FROM metrics
                    WHERE metric_name = ? AND timestamp > ?
                    ORDER BY timestamp DESC
                """, (rule.metric_name, cutoff_time))
                
                values = [row[0] for row in cursor.fetchall()]
            
            if not values:
                return
            
            # Calculate the metric value based on condition
            if rule.condition == 'avg':
                metric_value = statistics.mean(values)
            elif rule.condition == 'max':
                metric_value = max(values)
            elif rule.condition == 'min':
                metric_value = min(values)
            else:
                metric_value = values[0]  # latest value
            
            # Check threshold
            should_alert = False
            if rule.condition.endswith('_gt') or rule.condition == 'gt':
                should_alert = metric_value > rule.threshold
            elif rule.condition.endswith('_lt') or rule.condition == 'lt':
                should_alert = metric_value < rule.threshold
            elif rule.condition.endswith('_eq') or rule.condition == 'eq':
                should_alert = abs(metric_value - rule.threshold) < 0.01
            
            # Trigger alert if conditions are met
            if should_alert:
                now = time.time()
                # Prevent spam by checking if alert was recently triggered
                if (rule.last_triggered is None or 
                    now - rule.last_triggered > 300):  # 5 minute cooldown
                    
                    rule.last_triggered = now
                    self._trigger_alert(rule, metric_value)
        
        except Exception as e:
            app_logger.error(f"Error checking alert rule {rule.name}: {e}")
    
    def _trigger_alert(self, rule: AlertRule, current_value: float):
        """Trigger an alert"""
        alert_data = {
            'rule_name': rule.name,
            'metric_name': rule.metric_name,
            'threshold': rule.threshold,
            'current_value': current_value,
            'condition': rule.condition,
            'timestamp': time.time(),
            'message': f"Alert: {rule.name} - {rule.metric_name} is {current_value:.2f} (threshold: {rule.threshold})"
        }
        
        app_logger.warning(f"ALERT TRIGGERED: {alert_data['message']}")
        
        # Call registered callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert_data)
            except Exception as e:
                app_logger.error(f"Error in alert callback: {e}")

class MonitoringDashboard:
    """Simple monitoring dashboard data provider"""
    
    def __init__(self, collector: MetricsCollector, app_metrics: ApplicationMetrics):
        self.collector = collector
        self.app_metrics = app_metrics
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get comprehensive dashboard data"""
        return {
            'timestamp': time.time(),
            'system_metrics': self._get_system_metrics(),
            'application_metrics': self._get_application_metrics(),
            'recent_alerts': self._get_recent_alerts(),
            'health_status': self._get_health_status()
        }
    
    def _get_system_metrics(self) -> Dict[str, Any]:
        """Get current system metrics"""
        return {
            'cpu_percent': self.collector.get_metric_summary('system.cpu.percent', hours=1),
            'memory_percent': self.collector.get_metric_summary('system.memory.percent', hours=1),
            'disk_percent': self.collector.get_metric_summary('system.disk.percent', hours=1),
            'process_memory_mb': self.collector.get_metric_summary('process.memory.rss_mb', hours=1)
        }
    
    def _get_application_metrics(self) -> Dict[str, Any]:
        """Get application-specific metrics"""
        return {
            'request_stats': self.app_metrics.get_request_stats(),
            'payload_generation': {
                'avg_duration': self.collector.get_metric_summary('payload.generation.duration', hours=24),
                'avg_size': self.collector.get_metric_summary('payload.generation.size', hours=24),
                'avg_complexity': self.collector.get_metric_summary('payload.generation.complexity', hours=24)
            },
            'error_counts': dict(self.app_metrics.counters),
            'total_requests': sum(v for k, v in self.app_metrics.counters.items() if k.startswith('requests.'))
        }
    
    def _get_recent_alerts(self) -> List[Dict[str, Any]]:
        """Get recent alerts (placeholder - would integrate with AlertManager)"""
        return []
    
    def _get_health_status(self) -> Dict[str, str]:
        """Get overall health status"""
        # Simple health checks
        try:
            cpu_summary = self.collector.get_metric_summary('system.cpu.percent', hours=1)
            memory_summary = self.collector.get_metric_summary('system.memory.percent', hours=1)
            
            cpu_status = 'healthy'
            if cpu_summary and cpu_summary.get('mean', 0) > 80:
                cpu_status = 'warning'
            if cpu_summary and cpu_summary.get('mean', 0) > 95:
                cpu_status = 'critical'
            
            memory_status = 'healthy'
            if memory_summary and memory_summary.get('mean', 0) > 85:
                memory_status = 'warning'
            if memory_summary and memory_summary.get('mean', 0) > 95:
                memory_status = 'critical'
            
            overall_status = 'healthy'
            if cpu_status in ['warning', 'critical'] or memory_status in ['warning', 'critical']:
                overall_status = 'warning'
            if cpu_status == 'critical' or memory_status == 'critical':
                overall_status = 'critical'
            
            return {
                'overall': overall_status,
                'cpu': cpu_status,
                'memory': memory_status,
                'application': 'healthy'  # Could add more sophisticated checks
            }
        
        except Exception as e:
            app_logger.error(f"Error getting health status: {e}")
            return {
                'overall': 'unknown',
                'cpu': 'unknown',
                'memory': 'unknown',
                'application': 'unknown'
            }

# Global monitoring instances
metrics_collector = MetricsCollector()
app_metrics = ApplicationMetrics(metrics_collector)
alert_manager = AlertManager(metrics_collector)
dashboard = MonitoringDashboard(metrics_collector, app_metrics)

def setup_default_alerts():
    """Setup default alert rules"""
    # High CPU usage alert
    alert_manager.add_rule(AlertRule(
        name="High CPU Usage",
        metric_name="system.cpu.percent",
        condition="avg_gt",
        threshold=85.0,
        duration_minutes=5
    ))
    
    # High memory usage alert
    alert_manager.add_rule(AlertRule(
        name="High Memory Usage",
        metric_name="system.memory.percent",
        condition="avg_gt",
        threshold=90.0,
        duration_minutes=3
    ))
    
    # Slow payload generation alert
    alert_manager.add_rule(AlertRule(
        name="Slow Payload Generation",
        metric_name="payload.generation.duration",
        condition="avg_gt",
        threshold=10.0,
        duration_minutes=10
    ))
    
    # High error rate alert
    alert_manager.add_rule(AlertRule(
        name="High Error Rate",
        metric_name="errors.count",
        condition="max_gt",
        threshold=5.0,
        duration_minutes=5
    ))

def start_monitoring():
    """Start all monitoring services"""
    try:
        metrics_collector.start_collection(interval=30.0)
        setup_default_alerts()
        alert_manager.start_monitoring(check_interval=60.0)
        app_logger.info("Monitoring system started successfully")
    except Exception as e:
        app_logger.error(f"Failed to start monitoring: {e}")

def stop_monitoring():
    """Stop all monitoring services"""
    try:
        metrics_collector.stop_collection()
        alert_manager.stop_monitoring()
        app_logger.info("Monitoring system stopped")
    except Exception as e:
        app_logger.error(f"Error stopping monitoring: {e}")

# Alert callback example
def log_alert_callback(alert_data: Dict[str, Any]):
    """Example alert callback that logs alerts"""
    app_logger.critical(f"ALERT: {alert_data['message']}")
    
    # Here you could add integrations with:
    # - Email notifications
    # - Slack/Discord webhooks
    # - PagerDuty/OpsGenie
    # - SMS alerts
    # etc.

# Register the default alert callback
alert_manager.add_alert_callback(log_alert_callback)
