# Metamorphic Payload API v3.0 - Advanced Documentation

## Overview

The Metamorphic Payload API v3.0 is a sophisticated payload generation system with advanced evasion capabilities, comprehensive staging infrastructure, and enterprise-grade monitoring. This system provides in-memory payload execution, multi-stage deployment, and extensive anti-analysis features.

## 🚀 New Features in v3.0

### Advanced Staging Architecture
- **Staged Payloads**: Single-stage download and in-memory execution
- **Multi-Stage Payloads**: Progressive component download and assembly
- **Reflective DLL Loaders**: In-memory PE execution capabilities
- **Traditional Payloads**: Backwards compatibility support

### Comprehensive Evasion Engine
- **Environment Detection**: Sandbox username/hostname detection
- **Timing Analysis**: Sleep acceleration and uptime checks
- **Process Monitoring**: Analysis tool and suspicious process detection
- **Network Validation**: Virtual adapter and connectivity verification
- **File System Checks**: Virtualization artifact detection
- **Registry Analysis**: VM-specific registry key detection
- **Memory Validation**: Performance and resource verification
- **User Interaction**: Mouse movement and application detection
- **Geolocation Checks**: Timezone and locale validation
- **Hardware Analysis**: Virtual hardware component detection

### Enterprise Monitoring & Analytics
- **Real-time Metrics**: System performance and application monitoring
- **Security Events**: Comprehensive audit logging and threat detection
- **Database Analytics**: Payload usage tracking and trend analysis
- **Alert Management**: Configurable threshold-based alerting
- **Dashboard Interface**: Complete operational visibility

## 📡 API Endpoints

### Core Payload Generation

#### POST `/api/generate`
Generate metamorphic payloads with advanced evasion capabilities.

**Request Headers:**
```
Content-Type: application/json
x-api-key: your_api_key_here
```

**Request Body:**
```json
{
  "type": "staged|multi_stage|reflective|traditional",
  "staging_urls": ["http://staging-server:9090/stage/1", "http://staging-server:9090/stage/2"],
  "encryption_key": "optional_encryption_key",
  "evasion_techniques": ["environment_checks", "timing_checks", "process_checks"],
  "complexity_level": 5
}
```

**Response:**
```json
{
  "payload": "# Generated PowerShell payload...",
  "headers": {
    "X-Payload-Hash": "sha256_hash",
    "X-Generation-Time": "0.245",
    "X-Payload-Type": "staged",
    "X-Complexity-Score": "87",
    "X-Staging-URLs": "url1,url2",
    "X-Encryption-Enabled": "true"
  }
}
```

#### GET `/download/<filename>`
Download file-based payloads.

**Response:** PowerShell script file with enhanced obfuscation.

### Evasion Capabilities

#### GET `/evasion/techniques`
List available evasion techniques.

**Response:**
```json
{
  "available_techniques": [
    "environment_checks",
    "timing_checks", 
    "process_checks",
    "network_checks",
    "file_system_checks",
    "registry_checks",
    "memory_checks",
    "user_interaction",
    "geolocation_checks",
    "hardware_checks"
  ],
  "total_count": 10,
  "usage": "Include technique names in evasion_techniques array when generating payloads"
}
```

#### POST `/evasion/generate`
Generate standalone evasion payloads for testing.

**Request Body:**
```json
{
  "techniques": ["environment_checks", "timing_checks"],
  "complexity_level": 3
}
```

### Monitoring & Analytics

#### GET `/health`
System health check (no authentication required).

**Response:**
```json
{
  "status": "healthy",
  "timestamp": 1735858847.123,
  "version": "3.0.0",
  "uptime_seconds": 3600,
  "active_connections": 5
}
```

#### GET `/metrics`
Detailed system metrics (authenticated).

**Response:**
```json
{
  "generation_stats": {
    "total_generated": 150,
    "total_errors": 2,
    "average_generation_time": 0.234,
    "concurrent_generations": 1
  },
  "config": {
    "max_concurrent_generations": 5,
    "rate_limit_per_minute": 100,
    "payload_retention_hours": 24
  },
  "system": {
    "output_directory": "/app/output",
    "disk_usage": {
      "total_gb": 50,
      "used_gb": 12,
      "free_gb": 38,
      "usage_percent": 24.0
    }
  }
}
```

#### GET `/dashboard`
Comprehensive dashboard data with system and application metrics.

#### GET `/analytics?days=30`
Detailed payload analytics from database.

#### GET `/security/events?hours=24&severity=medium`
Recent security events and audit logs.

### Administrative

#### POST `/admin/cleanup`
Manually trigger database cleanup of expired records.

## 🏗️ Deployment Options

### Docker Compose (Recommended)

```bash
# Clone repository
git clone <repository_url>
cd metamorphic_payload_api

# Configure environment variables
cp .env.example .env
# Edit .env with your settings

# Deploy full stack
docker-compose -f docker-compose.yml up -d

# Or deploy with nginx proxy
docker-compose -f docker-compose-full.yml up -d
```

### Manual Installation

```bash
# Install Python dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit configuration

# Start main API
python app.py

# Start staging server (separate terminal)
python staging_server.py
```

## 🔧 Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `API_KEY` | Required | API authentication key (min 32 chars) |
| `FLASK_ENV` | production | Flask environment mode |
| `HOST` | 0.0.0.0 | Server bind address |
| `PORT` | 8080 | Server port |
| `RATE_LIMIT_PER_MINUTE` | 100 | API rate limiting |
| `MAX_CONCURRENT_GENERATIONS` | 5 | Concurrent payload limit |
| `ENABLE_DATABASE` | true | Database analytics |
| `ENABLE_METRICS` | true | Monitoring system |
| `LOG_LEVEL` | INFO | Logging verbosity |

### Staging Server Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `STAGING_SECRET_KEY` | Required | Staging server secret |
| `STAGING_ENCRYPTION_KEY` | Required | Payload encryption key |
| `STAGING_PORT` | 9090 | Staging server port |

## 🛡️ Security Features

### Multi-Layer Authentication
- API key validation with hash comparison
- Rate limiting per client IP
- Request size validation
- Suspicious activity detection

### Advanced Obfuscation
- Variable name morphing with Unicode support
- String literal obfuscation (base64, char arrays, splitting)
- Integer obfuscation (arithmetic, hex, scientific notation)
- AMSI bypass integration
- Junk code insertion

### Comprehensive Logging
- Security audit trail
- Performance monitoring
- Application event logging
- Database activity tracking

## 📊 Monitoring & Alerting

### Built-in Metrics
- System resource utilization (CPU, memory, disk)
- API request performance and error rates
- Payload generation statistics
- Database query performance

### Alert Rules
- High CPU/memory usage
- Slow payload generation
- High error rates
- Security event thresholds

### Dashboard Features
- Real-time system status
- Historical performance trends
- Security event timeline
- Payload usage analytics

## 🧪 Testing Framework

### Comprehensive Test Suite
```bash
# Run all tests
./enhanced_testing.py

# Test specific components
python -c "from enhanced_testing import *; test_health_endpoint()"

# PowerShell payload validation
./test_staged_payloads.ps1
```

### Performance Testing
```bash
# Load testing
./enhanced_tester.py --concurrent 10 --requests 100

# Staging server validation
./staging_examples.ps1
```

## 🚀 Usage Examples

### Basic Staged Payload
```bash
curl -X POST http://localhost:8080/api/generate \
  -H "Content-Type: application/json" \
  -H "x-api-key: your_api_key" \
  -d '{
    "type": "staged",
    "staging_urls": ["http://localhost:9090/stage/1"],
    "complexity_level": 5
  }'
```

### Multi-Stage with Evasion
```bash
curl -X POST http://localhost:8080/api/generate \
  -H "Content-Type: application/json" \
  -H "x-api-key: your_api_key" \
  -d '{
    "type": "multi_stage", 
    "staging_urls": ["http://localhost:9090/stage/1", "http://localhost:9090/stage/2"],
    "evasion_techniques": ["environment_checks", "process_checks", "timing_checks"],
    "complexity_level": 8
  }'
```

### Reflective DLL Loader
```bash
curl -X POST http://localhost:8080/api/generate \
  -H "Content-Type: application/json" \
  -H "x-api-key: your_api_key" \
  -d '{
    "type": "reflective",
    "staging_urls": ["http://localhost:9090/dll/payload"],
    "encryption_key": "secure_key_32_characters_long",
    "evasion_techniques": ["hardware_checks", "registry_checks"],
    "complexity_level": 10
  }'
```

## 🔍 Advanced Features

### Custom Evasion Techniques
The system supports 10 categories of evasion techniques that can be mixed and matched:

1. **Environment Checks** - Sandbox username/hostname detection
2. **Timing Checks** - Sleep acceleration and system uptime validation
3. **Process Checks** - Analysis tool and process count validation
4. **Network Checks** - Virtual adapter and connectivity verification
5. **File System Checks** - VM artifact and analysis tool detection
6. **Registry Checks** - Virtualization registry key detection
7. **Memory Checks** - System resource and performance validation
8. **User Interaction** - Mouse movement and application detection
9. **Geolocation Checks** - Timezone and locale validation
10. **Hardware Checks** - Virtual hardware component detection

### Staging Server Capabilities
- Multi-stage payload hosting
- Encrypted payload delivery
- Access logging and analytics
- Health monitoring endpoints
- Automatic payload cleanup

### Database Analytics
- Payload generation tracking
- Access pattern analysis
- Security event correlation
- Performance trend analysis
- Automatic data retention

## 🚨 Security Considerations

### Production Deployment
- Change default API keys and secrets
- Use HTTPS with valid certificates
- Configure firewall rules
- Enable audit logging
- Set up monitoring alerts
- Regular security updates

### Rate Limiting
- Default: 100 requests per minute per IP
- Configurable via environment variables
- Automatic blocking of abusive clients
- Gradual backoff implementation

### Data Protection
- In-memory payload execution
- Automatic file cleanup
- Encrypted staging payloads
- Secure database storage
- Audit trail preservation

## 📈 Performance Optimization

### Resource Management
- Concurrent generation limiting
- Memory usage monitoring
- Automatic cleanup processes
- Connection pooling
- Caching strategies

### Scaling Recommendations
- Load balancer configuration
- Database optimization
- Redis caching integration
- Horizontal scaling support
- Container orchestration

## 🔧 Troubleshooting

### Common Issues
1. **Import Errors**: Ensure all dependencies installed
2. **Database Connection**: Check database path and permissions
3. **Staging Server**: Verify network connectivity
4. **Rate Limiting**: Check API key and request frequency
5. **Evasion Failures**: Validate technique names and parameters

### Debug Mode
```bash
# Enable debug logging
export FLASK_DEBUG=true
export LOG_LEVEL=DEBUG
python app.py
```

### Log Analysis
```bash
# View security events
tail -f logs/security_audit.log

# Monitor performance
tail -f logs/performance.log

# Application logs
tail -f logs/app.log
```

## 📚 API Reference

Complete API documentation with request/response examples, error codes, and integration guides available in the `/docs` endpoint when running in development mode.

## 🤝 Contributing

Please follow the established patterns for:
- Security event logging
- Performance monitoring
- Error handling
- Code documentation
- Test coverage

## 📄 License

This project is licensed under the terms specified in the LICENSE file.

---

**Note**: This is a security research tool. Ensure compliance with applicable laws and regulations in your jurisdiction.
