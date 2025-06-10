import time
import hashlib
from functools import wraps
from collections import defaultdict, deque
from threading import Lock
from flask import request, jsonify, g
from logging_config import security_logger, performance_logger, app_logger
from config import config

# Rate limiting storage
rate_limit_storage = defaultdict(lambda: deque())
rate_limit_lock = Lock()

# Import database functions (with fallback if not available)
try:
    from database import record_security_event
    DATABASE_AVAILABLE = True
except ImportError:
    DATABASE_AVAILABLE = False
    def record_security_event(*args, **kwargs):
        pass

def require_api_key(f):
    """Enhanced API key authentication with logging and rate limiting"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        api_key = request.headers.get('x-api-key', '')
        user_agent = request.headers.get('User-Agent', 'Unknown')
          # Check rate limiting first
        if not check_rate_limit(client_ip):
            security_logger.log_rate_limit_exceeded(client_ip)
            
            # Record rate limit event in database
            if DATABASE_AVAILABLE and config.ENABLE_DATABASE:
                record_security_event(
                    event_type='rate_limit',
                    severity='low',
                    client_ip=client_ip,
                    endpoint=request.endpoint or 'unknown',
                    user_agent=user_agent,
                    details={
                        'request_path': request.path,
                        'method': request.method,
                        'requests_per_minute': config.RATE_LIMIT_PER_MINUTE
                    }
                )
            
            return jsonify({'error': 'Rate limit exceeded'}), 429
          # Validate API key
        if not api_key or api_key != config.API_KEY:
            security_logger.log_authentication_attempt(client_ip, False, api_key)
            
            # Record security event in database
            if DATABASE_AVAILABLE and config.ENABLE_DATABASE:
                record_security_event(
                    event_type='auth_failure',
                    severity='medium',
                    client_ip=client_ip,
                    endpoint=request.endpoint or 'unknown',
                    user_agent=user_agent,
                    details={
                        'attempted_key': api_key[:8] + '...' if api_key else 'empty',
                        'request_path': request.path,
                        'method': request.method
                    }
                )
            
            # Return 404 to hide endpoint existence
            return '', 404
        
        # Log successful authentication
        security_logger.log_authentication_attempt(client_ip, True, api_key)
        
        # Store client info for later use
        g.client_ip = client_ip
        g.user_agent = user_agent
        
        return f(*args, **kwargs)
    return decorated_function

def check_rate_limit(client_ip: str) -> bool:
    """Check if client has exceeded rate limit"""
    with rate_limit_lock:
        now = time.time()
        client_requests = rate_limit_storage[client_ip]
        
        # Remove old requests (older than 1 minute)
        while client_requests and client_requests[0] < now - 60:
            client_requests.popleft()
        
        # Check if limit exceeded
        if len(client_requests) >= config.RATE_LIMIT_PER_MINUTE:
            return False
        
        # Add current request
        client_requests.append(now)
        return True

def validate_request_size(f):
    """Validate request payload size"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.content_length and request.content_length > config.MAX_PAYLOAD_SIZE:
            app_logger.warning(f"Request size {request.content_length} exceeds limit {config.MAX_PAYLOAD_SIZE}")
            return jsonify({'error': 'Request too large'}), 413
        return f(*args, **kwargs)
    return decorated_function

def track_performance(endpoint_name: str):
    """Decorator to track endpoint performance"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            start_time = time.time()
            try:
                result = f(*args, **kwargs)
                status_code = getattr(result, 'status_code', 200)
                duration = time.time() - start_time
                performance_logger.log_endpoint_response_time(endpoint_name, duration, status_code)
                return result
            except Exception as e:
                duration = time.time() - start_time
                performance_logger.log_endpoint_response_time(endpoint_name, duration, 500)
                raise
        return decorated_function
    return decorator

def detect_suspicious_activity(f):
    """Detect and log suspicious activities"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        user_agent = request.headers.get('User-Agent', '')
        
        # Check for suspicious patterns
        suspicious_patterns = [
            'sqlmap', 'nikto', 'nmap', 'masscan', 'dirb', 'gobuster',
            'burp', 'zap', 'scanner', 'bot', 'crawler'
        ]
        
        if any(pattern.lower() in user_agent.lower() for pattern in suspicious_patterns):
            security_logger.log_suspicious_activity(client_ip, f"Suspicious User-Agent: {user_agent}")
        
        # Check for unusual request patterns
        content_type = request.headers.get('Content-Type', '')
        if 'xml' in content_type or 'json' in content_type and request.method == 'POST':
            # Additional validation could be added here
            pass
        
        return f(*args, **kwargs)
    return decorated_function

def calculate_payload_hash(content: str) -> str:
    """Calculate SHA-256 hash of payload content"""
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def log_payload_generation(content: str):
    """Log payload generation with hash"""
    client_ip = getattr(g, 'client_ip', 'unknown')
    user_agent = getattr(g, 'user_agent', 'unknown')
    payload_hash = calculate_payload_hash(content)
    security_logger.log_payload_generation(client_ip, user_agent, payload_hash)
    return payload_hash
