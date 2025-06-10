import logging
import logging.handlers
import os
import time
from pathlib import Path
from typing import Optional
import threading
from config import config

class SecurityAuditLogger:
    """Specialized logger for security events and audit trails"""
    
    def __init__(self):
        self.logger = logging.getLogger('security_audit')
        self.logger.setLevel(logging.INFO)
        
        # Create logs directory if it doesn't exist
        log_dir = Path(config.LOG_FILE).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Security audit log file
        audit_file = log_dir / 'security_audit.log'
        handler = logging.handlers.RotatingFileHandler(
            audit_file, 
            maxBytes=config.LOG_MAX_BYTES,
            backupCount=config.LOG_BACKUP_COUNT
        )
        
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
    
    def log_payload_generation(self, client_ip: str, user_agent: str, payload_hash: str):
        """Log payload generation events"""
        self.logger.info(f"PAYLOAD_GENERATED - IP: {client_ip} - UA: {user_agent} - Hash: {payload_hash}")
    
    def log_authentication_attempt(self, client_ip: str, success: bool, api_key_hint: str = ""):
        """Log authentication attempts"""
        status = "SUCCESS" if success else "FAILED"
        hint = api_key_hint[:8] + "..." if api_key_hint else "None"
        self.logger.warning(f"AUTH_{status} - IP: {client_ip} - Key_Hint: {hint}")
    
    def log_rate_limit_exceeded(self, client_ip: str):
        """Log rate limiting events"""
        self.logger.warning(f"RATE_LIMIT_EXCEEDED - IP: {client_ip}")
    
    def log_suspicious_activity(self, client_ip: str, activity: str):
        """Log suspicious activities"""
        self.logger.error(f"SUSPICIOUS_ACTIVITY - IP: {client_ip} - Activity: {activity}")

class PerformanceLogger:
    """Logger for performance metrics and monitoring"""
    
    def __init__(self):
        self.logger = logging.getLogger('performance')
        self.logger.setLevel(logging.INFO)
        
        log_dir = Path(config.LOG_FILE).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        
        perf_file = log_dir / 'performance.log'
        handler = logging.handlers.RotatingFileHandler(
            perf_file,
            maxBytes=config.LOG_MAX_BYTES,
            backupCount=config.LOG_BACKUP_COUNT
        )
        
        formatter = logging.Formatter(
            '%(asctime)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
    
    def log_generation_time(self, duration: float, payload_size: int, complexity_score: int):
        """Log payload generation performance metrics"""
        self.logger.info(f"GENERATION_TIME: {duration:.3f}s - Size: {payload_size}b - Complexity: {complexity_score}")
    
    def log_endpoint_response_time(self, endpoint: str, duration: float, status_code: int):
        """Log API endpoint response times"""
        self.logger.info(f"ENDPOINT: {endpoint} - Duration: {duration:.3f}s - Status: {status_code}")

class ApplicationLogger:
    """Main application logger with enhanced features"""
    
    def __init__(self):
        self.logger = logging.getLogger('metamorphic_api')
        self.logger.setLevel(getattr(logging, config.LOG_LEVEL.upper()))
        
        # Create logs directory
        log_dir = Path(config.LOG_FILE).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # File handler with rotation
        file_handler = logging.handlers.RotatingFileHandler(
            config.LOG_FILE,
            maxBytes=config.LOG_MAX_BYTES,
            backupCount=config.LOG_BACKUP_COUNT
        )
        
        # Console handler for development
        console_handler = logging.StreamHandler()
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        if config.FLASK_DEBUG:
            self.logger.addHandler(console_handler)
    
    def info(self, message: str):
        self.logger.info(message)
    
    def warning(self, message: str):
        self.logger.warning(message)
    
    def error(self, message: str, exc_info: Optional[Exception] = None):
        self.logger.error(message, exc_info=exc_info)
    
    def debug(self, message: str):
        self.logger.debug(message)
    
    def critical(self, message: str):
        self.logger.critical(message)

# Global logger instances
security_logger = SecurityAuditLogger()
performance_logger = PerformanceLogger()
app_logger = ApplicationLogger()

class PerformanceTracker:
    """Context manager for tracking operation performance"""
    
    def __init__(self, operation_name: str):
        self.operation_name = operation_name
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        if exc_type:
            app_logger.error(f"{self.operation_name} failed after {duration:.3f}s: {exc_val}")
        else:
            app_logger.debug(f"{self.operation_name} completed in {duration:.3f}s")
        return False
