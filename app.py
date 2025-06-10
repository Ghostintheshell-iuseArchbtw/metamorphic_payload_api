from flask import Flask, jsonify, request, abort, send_file, Response, g
from werkzeug.exceptions import RequestEntityTooLarge
import os
import time
import threading
from pathlib import Path

# Import our enhanced modules
from payload_generator_enhanced import EnhancedPayloadGenerator
from config import config
from logging_config import app_logger, performance_logger, PerformanceTracker
from security import (
    require_api_key, validate_request_size, track_performance,
    detect_suspicious_activity, log_payload_generation
)
import monitoring
from monitoring import app_metrics, metrics_collector, dashboard
import database
from database import db_manager, record_payload_generation, record_access_event, record_security_event

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = config.MAX_PAYLOAD_SIZE

# Initialize enhanced payload generator
payload_generator = EnhancedPayloadGenerator()

# Global stats for monitoring
generation_stats = {
    'total_generated': 0,
    'total_errors': 0,
    'average_generation_time': 0.0,
    'concurrent_generations': 0
}
stats_lock = threading.Lock()

def update_stats(generation_time: float, error: bool = False):
    """Update global statistics"""
    with stats_lock:
        if error:
            generation_stats['total_errors'] += 1
        else:
            generation_stats['total_generated'] += 1
            # Update rolling average
            total = generation_stats['total_generated']
            avg = generation_stats['average_generation_time']
            generation_stats['average_generation_time'] = (avg * (total - 1) + generation_time) / total

# Ensure output directory exists
output_dir = Path(config.OUTPUT_DIRECTORY)
output_dir.mkdir(parents=True, exist_ok=True)

# Health check endpoint (no authentication required)
@app.route(config.HEALTH_PATH, methods=['GET'])
@track_performance('health_check')
def health_check():
    """Health check endpoint for monitoring"""
    return jsonify({
        'status': 'healthy',
        'timestamp': time.time(),
        'version': '2.0.0',
        'stats': generation_stats.copy()
    })

# Main generation endpoint
@app.route(config.OBFUSCATED_PATH, methods=['POST'])
@detect_suspicious_activity
@validate_request_size
@require_api_key
@track_performance('generate_payload')
def generate_payload():
    """Generate and return metamorphic payload content"""
    try:
        with stats_lock:
            if generation_stats['concurrent_generations'] >= config.MAX_CONCURRENT_GENERATIONS:
                app_logger.warning("Maximum concurrent generations reached")
                return jsonify({'error': 'Server busy, try again later'}), 503
            generation_stats['concurrent_generations'] += 1
        
        try:
            with PerformanceTracker("Payload Generation"):
                start_time = time.time()
                
                # Get request parameters
                request_data = request.get_json() or {}
                payload_type = request_data.get('type', 'staged')  # staged, multi_stage, reflective, traditional
                staging_urls = request_data.get('staging_urls', None)
                encryption_key = request_data.get('encryption_key', None)
                evasion_techniques = request_data.get('evasion_techniques', None)
                complexity_level = request_data.get('complexity_level', 5)
                
                # Validate payload type
                valid_types = ['staged', 'multi_stage', 'reflective', 'traditional']
                if payload_type not in valid_types:
                    return jsonify({'error': f'Invalid payload type. Must be one of: {valid_types}'}), 400
                
                # Validate complexity level
                if not isinstance(complexity_level, int) or complexity_level < 1 or complexity_level > 10:
                    complexity_level = 5
                
                # Generate payload with specified parameters
                payload_content = payload_generator.generate_payload_content(
                    payload_type=payload_type,
                    staging_urls=staging_urls,
                    encryption_key=encryption_key,
                    evasion_techniques=evasion_techniques,
                    complexity_level=complexity_level
                )
                
                generation_time = time.time() - start_time
                  # Log the generation
                payload_hash = log_payload_generation(payload_content)
                
                # Update statistics
                update_stats(generation_time)
                
                # Record metrics for monitoring
                app_metrics.record_payload_generation(generation_time, len(payload_content), payload_generator.last_complexity_score)
                
                # Record in database if enabled
                if config.ENABLE_DATABASE:
                    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
                    user_agent = request.headers.get('User-Agent', '')
                    record_payload_generation(
                        payload_hash=payload_hash,
                        payload_type=payload_type,
                        generation_time=generation_time,
                        size_bytes=len(payload_content),
                        complexity_score=payload_generator.last_complexity_score,
                        client_ip=client_ip,
                        user_agent=user_agent,
                        staging_urls=staging_urls,
                        encryption_enabled=bool(encryption_key)
                    )
                
                app_logger.info(f"Payload generated successfully - Type: {payload_type}, Hash: {payload_hash}, Time: {generation_time:.3f}s")
                
                response_headers = {
                    'X-Payload-Hash': payload_hash,
                    'X-Generation-Time': f"{generation_time:.3f}",
                    'X-Payload-Type': payload_type,
                    'X-Complexity-Score': str(payload_generator.last_complexity_score),
                    'Cache-Control': 'no-cache, no-store, must-revalidate',
                    'Pragma': 'no-cache',
                    'Expires': '0'
                }
                
                # Add staging information to headers if applicable
                if payload_type in ['staged', 'multi_stage'] and staging_urls:
                    response_headers['X-Staging-URLs'] = ','.join(staging_urls)
                if encryption_key:
                    response_headers['X-Encryption-Enabled'] = 'true'
                
                return Response(
                    payload_content,
                    mimetype='text/plain',
                    headers=response_headers
                )
        finally:
            with stats_lock:
                generation_stats['concurrent_generations'] -= 1
                
    except Exception as e:
        update_stats(0, error=True)
        app_logger.error(f"Error generating payload: {str(e)}", exc_info=e)
        return jsonify({
            'error': 'Internal server error',
            'message': 'Payload generation failed'
        }), 500

# Download endpoint for file-based payloads
@app.route(config.DOWNLOAD_PATH + '/<filename>', methods=['GET'])
@detect_suspicious_activity
@require_api_key
@track_performance('download_payload')
def download_payload(filename):
    """Generate and serve payload as downloadable file"""
    try:
        # Sanitize filename
        if not filename.endswith('.ps1'):
            filename = filename.split('.')[0] + '.ps1'
        
        # Generate unique filename in output directory
        safe_filename = f"payload_{int(time.time())}_{filename}"
        file_path = output_dir / safe_filename
        
        with PerformanceTracker("File Payload Generation"):
            start_time = time.time()
            
            # Generate payload to file
            payload_generator.generate_payload_file(str(file_path))
            
            generation_time = time.time() - start_time
              # Read content for logging
            with open(file_path, 'r') as f:
                content = f.read()
            
            payload_hash = log_payload_generation(content)
            update_stats(generation_time)
            
            # Record download in database if enabled
            if config.ENABLE_DATABASE:
                client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
                user_agent = request.headers.get('User-Agent', '')
                record_access_event(
                    payload_hash=payload_hash,
                    client_ip=client_ip,
                    access_type='download',
                    endpoint=request.endpoint,
                    status_code=200,
                    response_time=generation_time,
                    user_agent=user_agent
                )
            
            app_logger.info(f"File payload generated - Hash: {payload_hash}, File: {safe_filename}")
            
            return send_file(
                file_path,
                mimetype='application/x-powershell',
                as_attachment=True,
                download_name=filename,
                max_age=0  # Prevent caching
            )
            
    except FileNotFoundError:
        app_logger.warning(f"Requested file not found: {filename}")
        return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        update_stats(0, error=True)
        app_logger.error(f"Error in download endpoint: {str(e)}", exc_info=e)
        return jsonify({'error': 'Internal server error'}), 500

# Metrics endpoint for monitoring (authenticated)
@app.route('/metrics', methods=['GET'])
@require_api_key
def metrics():
    """Return detailed metrics for monitoring"""
    return jsonify({
        'generation_stats': generation_stats.copy(),
        'config': {
            'max_concurrent_generations': config.MAX_CONCURRENT_GENERATIONS,
            'rate_limit_per_minute': config.RATE_LIMIT_PER_MINUTE,
            'payload_retention_hours': config.PAYLOAD_RETENTION_HOURS
        },
        'system': {
            'output_directory': str(output_dir),
            'disk_usage': _get_disk_usage()
        }
    })

def _get_disk_usage():
    """Get disk usage information"""
    try:
        import shutil
        total, used, free = shutil.disk_usage(output_dir)
        return {
            'total_gb': total // (1024**3),
            'used_gb': used // (1024**3),
            'free_gb': free // (1024**3),
            'usage_percent': (used / total) * 100
        }
    except Exception:
        return {'error': 'Unable to get disk usage'}

# Add monitoring middleware
@app.before_request
def before_request():
    """Record request start time for monitoring"""
    g.start_time = time.time()

@app.after_request
def after_request(response):
    """Record request metrics after processing"""
    if hasattr(g, 'start_time'):
        duration = time.time() - g.start_time
        endpoint = request.endpoint or 'unknown'
        app_metrics.record_request(endpoint, duration, response.status_code)
    return response

# Enhanced metrics endpoint with detailed dashboard data
@app.route('/dashboard', methods=['GET'])
@require_api_key
def dashboard_endpoint():
    """Return comprehensive dashboard data"""
    try:
        dashboard_data = dashboard.get_dashboard_data()
        
        # Add database analytics if enabled
        if config.ENABLE_DATABASE:
            dashboard_data['database_analytics'] = db_manager.get_payload_analytics(days=7)
        
        return jsonify(dashboard_data)
    except Exception as e:
        app_logger.error(f"Error getting dashboard data: {str(e)}", exc_info=e)
        return jsonify({'error': 'Failed to get dashboard data'}), 500

# Analytics endpoint for detailed payload analytics
@app.route('/analytics', methods=['GET'])
@require_api_key
def analytics_endpoint():
    """Return detailed payload analytics from database"""
    if not config.ENABLE_DATABASE:
        return jsonify({'error': 'Database not enabled'}), 503
    
    try:
        days = request.args.get('days', '30')
        try:
            days = int(days)
            if days < 1 or days > 365:
                days = 30
        except ValueError:
            days = 30
        
        analytics_data = db_manager.get_payload_analytics(days=days)
        return jsonify(analytics_data)
    except Exception as e:
        app_logger.error(f"Error getting analytics: {str(e)}", exc_info=e)
        return jsonify({'error': 'Failed to get analytics data'}), 500

# Security events endpoint
@app.route('/security/events', methods=['GET'])
@require_api_key
def security_events_endpoint():
    """Return recent security events"""
    if not config.ENABLE_DATABASE:
        return jsonify({'error': 'Database not enabled'}), 503
    
    try:
        hours = request.args.get('hours', '24')
        severity = request.args.get('severity', None)
        
        try:
            hours = int(hours)
            if hours < 1 or hours > 168:  # Max 1 week
                hours = 24
        except ValueError:
            hours = 24
        
        events = db_manager.get_security_events(hours=hours, severity=severity)
        return jsonify({
            'events': events,
            'total_count': len(events),
            'hours_requested': hours,
            'severity_filter': severity
        })
    except Exception as e:
        app_logger.error(f"Error getting security events: {str(e)}", exc_info=e)
        return jsonify({'error': 'Failed to get security events'}), 500

# Database cleanup endpoint
@app.route('/admin/cleanup', methods=['POST'])
@require_api_key
def cleanup_database():
    """Manually trigger database cleanup"""
    if not config.ENABLE_DATABASE:
        return jsonify({'error': 'Database not enabled'}), 503
    
    try:
        deleted_count = db_manager.cleanup_expired_records()
        return jsonify({
            'success': True,
            'deleted_records': deleted_count,
            'message': f'Cleanup completed, {deleted_count} records deleted'
        })
    except Exception as e:
        app_logger.error(f"Error during manual cleanup: {str(e)}", exc_info=e)
        return jsonify({'error': 'Cleanup failed'}), 500

# Evasion techniques endpoints
@app.route('/evasion/techniques', methods=['GET'])
@require_api_key
def get_evasion_techniques():
    """Get list of available evasion techniques"""
    try:
        from evasion import get_available_evasion_techniques
        techniques = get_available_evasion_techniques()
        return jsonify({
            'available_techniques': techniques,
            'total_count': len(techniques),
            'usage': 'Include technique names in evasion_techniques array when generating payloads'
        })
    except ImportError:
        return jsonify({'error': 'Evasion module not available'}), 503
    except Exception as e:
        app_logger.error(f"Error getting evasion techniques: {str(e)}", exc_info=e)
        return jsonify({'error': 'Failed to get evasion techniques'}), 500

@app.route('/evasion/generate', methods=['POST'])
@require_api_key
def generate_evasion_payload():
    """Generate standalone evasion payload for testing"""
    try:
        from evasion import evasion_engine
        
        request_data = request.get_json() or {}
        techniques = request_data.get('techniques', None)
        complexity_level = request_data.get('complexity_level', 3)
        
        # Validate complexity level
        if not isinstance(complexity_level, int) or complexity_level < 1 or complexity_level > 10:
            complexity_level = 3
        
        evasion_payload = evasion_engine.generate_evasion_payload(techniques, complexity_level)
        
        return jsonify({
            'payload': evasion_payload,
            'techniques_used': techniques or 'auto-selected',
            'complexity_level': complexity_level,
            'size_bytes': len(evasion_payload)
        })
        
    except ImportError:
        return jsonify({'error': 'Evasion module not available'}), 503
    except Exception as e:
        app_logger.error(f"Error generating evasion payload: {str(e)}", exc_info=e)
        return jsonify({'error': 'Failed to generate evasion payload'}), 500
# Error handlers
@app.errorhandler(404)
def not_found(e):
    """Custom 404 handler - no information disclosure"""
    return '', 404

@app.errorhandler(413)
@app.errorhandler(RequestEntityTooLarge)
def request_too_large(e):
    """Handle request entity too large"""
    app_logger.warning(f"Request too large: {request.content_length}")
    return jsonify({'error': 'Request too large'}), 413

@app.errorhandler(429)
def rate_limit_exceeded(e):
    """Handle rate limit exceeded"""
    return jsonify({'error': 'Rate limit exceeded'}), 429

@app.errorhandler(500)
def internal_error(e):
    """Handle internal server errors"""
    app_logger.error(f"Internal server error: {str(e)}")
    return jsonify({'error': 'Internal server error'}), 500

# Startup cleanup task
def cleanup_old_payloads():
    """Clean up old payload files"""
    try:
        import time
        cutoff_time = time.time() - (config.PAYLOAD_RETENTION_HOURS * 3600)
        
        for file_path in output_dir.glob('payload_*.ps1'):
            if file_path.stat().st_mtime < cutoff_time:
                file_path.unlink()
                app_logger.debug(f"Cleaned up old payload: {file_path.name}")
    except Exception as e:
        app_logger.error(f"Error during cleanup: {str(e)}")

if __name__ == '__main__':
    # Perform startup tasks
    app_logger.info("Starting Metamorphic Payload API v2.0.0")
    app_logger.info(f"Configuration loaded - Debug: {config.FLASK_DEBUG}, Port: {config.PORT}")
    
    # Clean up old files on startup
    cleanup_old_payloads()
    
    # Start monitoring if enabled
    if config.ENABLE_METRICS:
        monitoring.start_monitoring()
        app_logger.info("Monitoring system enabled")
    
    try:
        # Start the application
        app.run(
            host=config.HOST,
            port=config.PORT,
            debug=config.FLASK_DEBUG,
            threaded=True
        )
    finally:
        # Cleanup on shutdown
        if config.ENABLE_METRICS:
            monitoring.stop_monitoring()
