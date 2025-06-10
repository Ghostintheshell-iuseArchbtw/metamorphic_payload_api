"""
Database Integration Module for Metamorphic Payload API
Provides payload tracking, analytics, and persistent storage capabilities.
"""

import sqlite3
import json
import time
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import threading
from contextlib import contextmanager

from config import config
from logging_config import app_logger

@dataclass
class PayloadRecord:
    """Represents a payload generation record in the database"""
    id: Optional[int] = None
    hash: str = ""
    payload_type: str = ""
    generation_time: float = 0.0
    size_bytes: int = 0
    complexity_score: int = 0
    client_ip: str = ""
    user_agent: str = ""
    staging_urls: Optional[str] = None  # JSON string
    encryption_enabled: bool = False
    created_at: str = ""
    expires_at: Optional[str] = None

@dataclass
class AccessRecord:
    """Represents a payload access record"""
    id: Optional[int] = None
    payload_hash: str = ""
    client_ip: str = ""
    user_agent: str = ""
    access_type: str = ""  # 'generate', 'download', 'staging'
    endpoint: str = ""
    status_code: int = 200
    response_time: float = 0.0
    accessed_at: str = ""

@dataclass
class SecurityEvent:
    """Represents a security event in the database"""
    id: Optional[int] = None
    event_type: str = ""  # 'suspicious_activity', 'rate_limit', 'auth_failure', etc.
    severity: str = ""  # 'low', 'medium', 'high', 'critical'
    client_ip: str = ""
    user_agent: str = ""
    endpoint: str = ""
    details: str = ""  # JSON string with additional details
    created_at: str = ""

class DatabaseManager:
    """Manages database operations for payload tracking and analytics"""
    
    def __init__(self, db_path: str = None):
        self.db_path = Path(db_path or config.DATABASE_PATH or "data/payloads.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self._init_database()
        
    def _init_database(self):
        """Initialize database tables"""
        with self.get_connection() as conn:
            # Payload records table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS payload_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hash TEXT UNIQUE NOT NULL,
                    payload_type TEXT NOT NULL,
                    generation_time REAL NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    complexity_score INTEGER NOT NULL,
                    client_ip TEXT NOT NULL,
                    user_agent TEXT,
                    staging_urls TEXT,
                    encryption_enabled BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP
                )
            """)
            
            # Access records table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS access_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload_hash TEXT,
                    client_ip TEXT NOT NULL,
                    user_agent TEXT,
                    access_type TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    response_time REAL NOT NULL,
                    accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (payload_hash) REFERENCES payload_records (hash)
                )
            """)
            
            # Security events table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    user_agent TEXT,
                    endpoint TEXT,
                    details TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Analytics summary table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS analytics_summary (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT NOT NULL,
                    total_payloads INTEGER DEFAULT 0,
                    unique_ips INTEGER DEFAULT 0,
                    avg_generation_time REAL DEFAULT 0.0,
                    avg_complexity_score INTEGER DEFAULT 0,
                    total_downloads INTEGER DEFAULT 0,
                    security_events INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(date)
                )
            """)
            
            # Create indexes for better performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_payload_hash ON payload_records(hash)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_payload_created ON payload_records(created_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_access_hash ON access_records(payload_hash)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_access_ip ON access_records(client_ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_access_time ON access_records(accessed_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_security_ip ON security_events(client_ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_security_type ON security_events(event_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_security_time ON security_events(created_at)")
            
        app_logger.info("Database initialized successfully")
    
    @contextmanager
    def get_connection(self):
        """Get database connection with proper error handling"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            app_logger.error(f"Database error: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def record_payload_generation(self, record: PayloadRecord) -> bool:
        """Record a new payload generation"""
        try:
            with self.lock:
                with self.get_connection() as conn:
                    conn.execute("""
                        INSERT INTO payload_records 
                        (hash, payload_type, generation_time, size_bytes, complexity_score,
                         client_ip, user_agent, staging_urls, encryption_enabled, expires_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        record.hash,
                        record.payload_type,
                        record.generation_time,
                        record.size_bytes,
                        record.complexity_score,
                        record.client_ip,
                        record.user_agent,
                        record.staging_urls,
                        record.encryption_enabled,
                        record.expires_at
                    ))
                    conn.commit()
                    return True
        except sqlite3.IntegrityError:
            # Hash already exists
            app_logger.warning(f"Payload hash already exists: {record.hash}")
            return False
        except Exception as e:
            app_logger.error(f"Error recording payload: {e}")
            return False
    
    def record_access(self, record: AccessRecord) -> bool:
        """Record a payload access event"""
        try:
            with self.lock:
                with self.get_connection() as conn:
                    conn.execute("""
                        INSERT INTO access_records 
                        (payload_hash, client_ip, user_agent, access_type, endpoint,
                         status_code, response_time)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        record.payload_hash,
                        record.client_ip,
                        record.user_agent,
                        record.access_type,
                        record.endpoint,
                        record.status_code,
                        record.response_time
                    ))
                    conn.commit()
                    return True
        except Exception as e:
            app_logger.error(f"Error recording access: {e}")
            return False
    
    def record_security_event(self, event: SecurityEvent) -> bool:
        """Record a security event"""
        try:
            with self.lock:
                with self.get_connection() as conn:
                    conn.execute("""
                        INSERT INTO security_events 
                        (event_type, severity, client_ip, user_agent, endpoint, details)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        event.event_type,
                        event.severity,
                        event.client_ip,
                        event.user_agent,
                        event.endpoint,
                        event.details
                    ))
                    conn.commit()
                    return True
        except Exception as e:
            app_logger.error(f"Error recording security event: {e}")
            return False
    
    def get_payload_analytics(self, days: int = 30) -> Dict[str, Any]:
        """Get comprehensive payload analytics"""
        try:
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            with self.get_connection() as conn:
                # Basic stats
                cursor = conn.execute("""
                    SELECT 
                        COUNT(*) as total_payloads,
                        COUNT(DISTINCT client_ip) as unique_ips,
                        AVG(generation_time) as avg_generation_time,
                        AVG(complexity_score) as avg_complexity,
                        MAX(generation_time) as max_generation_time,
                        MIN(generation_time) as min_generation_time,
                        SUM(size_bytes) as total_bytes
                    FROM payload_records 
                    WHERE created_at > ?
                """, (cutoff_date,))
                
                basic_stats = dict(cursor.fetchone())
                
                # Payload type distribution
                cursor = conn.execute("""
                    SELECT payload_type, COUNT(*) as count
                    FROM payload_records 
                    WHERE created_at > ?
                    GROUP BY payload_type
                    ORDER BY count DESC
                """, (cutoff_date,))
                
                type_distribution = {row['payload_type']: row['count'] for row in cursor.fetchall()}
                
                # Top client IPs
                cursor = conn.execute("""
                    SELECT client_ip, COUNT(*) as count
                    FROM payload_records 
                    WHERE created_at > ?
                    GROUP BY client_ip
                    ORDER BY count DESC
                    LIMIT 10
                """, (cutoff_date,))
                
                top_ips = {row['client_ip']: row['count'] for row in cursor.fetchall()}
                
                # Daily generation counts
                cursor = conn.execute("""
                    SELECT DATE(created_at) as date, COUNT(*) as count
                    FROM payload_records 
                    WHERE created_at > ?
                    GROUP BY DATE(created_at)
                    ORDER BY date
                """, (cutoff_date,))
                
                daily_counts = {row['date']: row['count'] for row in cursor.fetchall()}
                
                # Security events summary
                cursor = conn.execute("""
                    SELECT event_type, severity, COUNT(*) as count
                    FROM security_events 
                    WHERE created_at > ?
                    GROUP BY event_type, severity
                    ORDER BY count DESC
                """, (cutoff_date,))
                
                security_summary = [
                    {'type': row['event_type'], 'severity': row['severity'], 'count': row['count']}
                    for row in cursor.fetchall()
                ]
                
                return {
                    'period_days': days,
                    'basic_stats': basic_stats,
                    'type_distribution': type_distribution,
                    'top_client_ips': top_ips,
                    'daily_generation_counts': daily_counts,
                    'security_events': security_summary,
                    'generated_at': datetime.now().isoformat()
                }
                
        except Exception as e:
            app_logger.error(f"Error getting analytics: {e}")
            return {'error': str(e)}
    
    def get_security_events(self, hours: int = 24, severity: str = None) -> List[Dict[str, Any]]:
        """Get recent security events"""
        try:
            cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()
            
            query = """
                SELECT * FROM security_events 
                WHERE created_at > ?
            """
            params = [cutoff_time]
            
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            
            query += " ORDER BY created_at DESC LIMIT 100"
            
            with self.get_connection() as conn:
                cursor = conn.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            app_logger.error(f"Error getting security events: {e}")
            return []
    
    def cleanup_expired_records(self) -> int:
        """Clean up expired payload records"""
        try:
            current_time = datetime.now().isoformat()
            
            with self.lock:
                with self.get_connection() as conn:
                    # Delete expired payloads
                    cursor = conn.execute("""
                        DELETE FROM payload_records 
                        WHERE expires_at IS NOT NULL AND expires_at < ?
                    """, (current_time,))
                    
                    deleted_payloads = cursor.rowcount
                    
                    # Clean up old access records (keep for 90 days)
                    old_cutoff = (datetime.now() - timedelta(days=90)).isoformat()
                    cursor = conn.execute("""
                        DELETE FROM access_records 
                        WHERE accessed_at < ?
                    """, (old_cutoff,))
                    
                    deleted_access = cursor.rowcount
                    
                    # Clean up old security events (keep for 180 days)
                    security_cutoff = (datetime.now() - timedelta(days=180)).isoformat()
                    cursor = conn.execute("""
                        DELETE FROM security_events 
                        WHERE created_at < ? AND severity NOT IN ('high', 'critical')
                    """, (security_cutoff,))
                    
                    deleted_security = cursor.rowcount
                    
                    conn.commit()
                    
                    app_logger.info(f"Cleanup completed: {deleted_payloads} payloads, "
                                  f"{deleted_access} access records, {deleted_security} security events")
                    
                    return deleted_payloads + deleted_access + deleted_security
                    
        except Exception as e:
            app_logger.error(f"Error during cleanup: {e}")
            return 0
    
    def update_daily_analytics(self) -> bool:
        """Update daily analytics summary"""
        try:
            today = datetime.now().strftime('%Y-%m-%d')
            yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
            
            with self.lock:
                with self.get_connection() as conn:
                    # Get yesterday's analytics
                    cursor = conn.execute("""
                        SELECT 
                            COUNT(*) as total_payloads,
                            COUNT(DISTINCT client_ip) as unique_ips,
                            AVG(generation_time) as avg_generation_time,
                            AVG(complexity_score) as avg_complexity_score
                        FROM payload_records 
                        WHERE DATE(created_at) = ?
                    """, (yesterday,))
                    
                    payload_stats = cursor.fetchone()
                    
                    # Get download counts
                    cursor = conn.execute("""
                        SELECT COUNT(*) as total_downloads
                        FROM access_records 
                        WHERE DATE(accessed_at) = ? AND access_type = 'download'
                    """, (yesterday,))
                    
                    download_stats = cursor.fetchone()
                    
                    # Get security events count
                    cursor = conn.execute("""
                        SELECT COUNT(*) as security_events
                        FROM security_events 
                        WHERE DATE(created_at) = ?
                    """, (yesterday,))
                    
                    security_stats = cursor.fetchone()
                    
                    # Insert or update summary
                    conn.execute("""
                        INSERT OR REPLACE INTO analytics_summary 
                        (date, total_payloads, unique_ips, avg_generation_time, 
                         avg_complexity_score, total_downloads, security_events)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        yesterday,
                        payload_stats['total_payloads'] or 0,
                        payload_stats['unique_ips'] or 0,
                        payload_stats['avg_generation_time'] or 0.0,
                        payload_stats['avg_complexity_score'] or 0,
                        download_stats['total_downloads'] or 0,
                        security_stats['security_events'] or 0
                    ))
                    
                    conn.commit()
                    return True
                    
        except Exception as e:
            app_logger.error(f"Error updating daily analytics: {e}")
            return False

# Global database manager instance
db_manager = DatabaseManager()

def record_payload_generation(payload_hash: str, payload_type: str, generation_time: float,
                            size_bytes: int, complexity_score: int, client_ip: str,
                            user_agent: str = "", staging_urls: List[str] = None,
                            encryption_enabled: bool = False) -> bool:
    """Convenience function to record payload generation"""
    
    # Calculate expiration time based on payload type
    if payload_type in ['staged', 'multi_stage']:
        expires_at = (datetime.now() + timedelta(hours=config.PAYLOAD_RETENTION_HOURS)).isoformat()
    else:
        expires_at = None
    
    record = PayloadRecord(
        hash=payload_hash,
        payload_type=payload_type,
        generation_time=generation_time,
        size_bytes=size_bytes,
        complexity_score=complexity_score,
        client_ip=client_ip,
        user_agent=user_agent,
        staging_urls=json.dumps(staging_urls) if staging_urls else None,
        encryption_enabled=encryption_enabled,
        expires_at=expires_at
    )
    
    return db_manager.record_payload_generation(record)

def record_access_event(payload_hash: str, client_ip: str, access_type: str,
                       endpoint: str, status_code: int, response_time: float,
                       user_agent: str = "") -> bool:
    """Convenience function to record access events"""
    
    record = AccessRecord(
        payload_hash=payload_hash,
        client_ip=client_ip,
        user_agent=user_agent,
        access_type=access_type,
        endpoint=endpoint,
        status_code=status_code,
        response_time=response_time
    )
    
    return db_manager.record_access(record)

def record_security_event(event_type: str, severity: str, client_ip: str,
                         endpoint: str = "", user_agent: str = "",
                         details: Dict[str, Any] = None) -> bool:
    """Convenience function to record security events"""
    
    event = SecurityEvent(
        event_type=event_type,
        severity=severity,
        client_ip=client_ip,
        user_agent=user_agent,
        endpoint=endpoint,
        details=json.dumps(details) if details else "{}"
    )
    
    return db_manager.record_security_event(event)
