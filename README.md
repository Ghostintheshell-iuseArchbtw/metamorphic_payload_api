# Metamorphic Payload API v2.0

A **highly advanced and secure** API service that generates unique, metamorphic PowerShell payloads with enterprise-grade features including comprehensive monitoring, advanced security, and sophisticated obfuscation techniques. Each generated payload is completely unique and undetectable, making it suitable for professional security testing and red team operations.

## 🚀 Major Improvements in v2.0

### ✨ New Features
- **Advanced Monitoring & Metrics**: Real-time system monitoring with Prometheus integration
- **Enhanced Security**: Rate limiting, IP tracking, advanced authentication
- **Comprehensive Logging**: Security audit trails, performance metrics, error tracking
- **Container Support**: Full Docker deployment with monitoring stack
- **Advanced Testing**: Comprehensive test suites with validation
- **Configuration Management**: Environment-based configuration with security best practices
- **Performance Optimization**: Concurrent generation limiting, memory management
- **Alert System**: Configurable alerts for system health and security events

### 🔧 Technical Enhancements
- **Modular Architecture**: Clean separation of concerns with proper OOP design
- **Thread Safety**: Safe concurrent operations with proper locking
- **Error Handling**: Comprehensive error handling and recovery
- **Payload Validation**: Structure and complexity validation
- **Cleanup Management**: Automatic cleanup of old payloads
- **Health Monitoring**: Built-in health checks and status reporting

## 📋 Features Overview

### 🛡️ Security Features
- **Multi-layer Authentication**: API key + optional JWT integration
- **Rate Limiting**: Configurable per-IP rate limiting
- **Security Audit Logging**: Complete audit trail of all activities
- **Stealth Mode**: 404 responses for unauthorized access
- **IP Tracking**: Monitor and log client IP addresses and user agents
- **Suspicious Activity Detection**: Automated detection of scanning tools

### 🎯 Payload Generation
- **Metamorphic Engine**: Each payload is completely unique
- **Advanced Obfuscation**: 12+ obfuscation techniques including:
  - Base64 encoding with UTF8 conversion
  - Hexadecimal representation
  - Character array construction
  - String splitting and joining
  - XOR encryption with random keys
  - Unicode escape sequences
  - Binary representation
  - ROT13 encoding
- **Variable Name Morphing**: Unicode character sets with complex naming
- **AMSI Bypass**: Multiple sophisticated AMSI bypass techniques
- **Junk Code Injection**: Intelligent junk code for increased complexity
- **Error Handling**: Comprehensive try-catch blocks

### 📊 Monitoring & Analytics
- **Real-time Metrics**: System and application performance monitoring
- **Performance Tracking**: Response times, payload complexity scoring
- **Resource Monitoring**: CPU, memory, disk usage tracking
- **Alert System**: Configurable alerts for system health
- **Dashboard**: Comprehensive monitoring dashboard
- **Historical Data**: SQLite-based metrics storage

### 🐳 Deployment Options
- **Standalone**: Python virtual environment deployment
- **Docker**: Single container deployment
- **Docker Compose**: Full monitoring stack with Prometheus + Grafana
- **Production**: Gunicorn WSGI server deployment

## 🏗️ Architecture

```
├── Core Application
│   ├── app.py                 # Main Flask application
│   ├── payload_generator.py   # Enhanced payload generation engine
│   ├── config.py             # Configuration management
│   └── security.py           # Security middleware and auth
├── Monitoring System
│   ├── monitoring.py         # Metrics collection and alerting
│   └── logging_config.py     # Advanced logging configuration
├── Testing Framework
│   ├── enhanced_testing.py   # Comprehensive API testing
│   └── test_api.ps1          # PowerShell test suite
├── Deployment
│   ├── Dockerfile            # Container configuration
│   ├── docker-compose*.yml   # Container orchestration
│   └── enhanced_build.sh     # Advanced build and deployment script
└── Documentation
    └── README.md             # This file
```

## 🚀 Quick Start

### Method 1: Enhanced Build Script (Recommended)

```bash
# Make script executable
chmod +x enhanced_build.sh

# Development deployment
./enhanced_build.sh -m development -k "your_secure_api_key_32_chars_min"

# Production deployment
./enhanced_build.sh -m production -k "your_secure_api_key_32_chars_min"

# Docker deployment with monitoring
./enhanced_build.sh -m docker -k "your_secure_api_key_32_chars_min"

# Quick test run
./enhanced_build.sh -m development -t -k "test_key_123456789012345678901234"
```

### Method 2: Manual Setup

```bash
# 1. Clone and setup
git clone <repository>
cd metamorphic_payload_api

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env with your configuration

# 5. Run the application
python app.py
```

### Method 3: Docker Deployment

```bash
# Simple Docker deployment
docker-compose up -d

# Full monitoring stack
docker-compose -f docker-compose-full.yml up -d
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `API_KEY` | Authentication key (min 32 chars) | - | ✅ |
| `JWT_SECRET_KEY` | JWT signing key | Auto-generated | ❌ |
| `RATE_LIMIT_PER_MINUTE` | Rate limit per IP | 10 | ❌ |
| `MAX_PAYLOAD_SIZE` | Maximum request size | 1024000 | ❌ |
| `HOST` | Server bind address | 0.0.0.0 | ❌ |
| `PORT` | Server port | 8080 | ❌ |
| `LOG_LEVEL` | Logging level | INFO | ❌ |
| `ENABLE_METRICS` | Enable monitoring | True | ❌ |
| `PAYLOAD_RETENTION_HOURS` | File cleanup time | 24 | ❌ |

### Security Configuration

```bash
# Generate secure API key
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Generate JWT secret
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
```

## 📡 API Endpoints

### Core Endpoints

#### `POST /api/v1/metamorphic/generate`
Generate and return raw PowerShell payload content.

**Headers:**
- `x-api-key`: Your API key

**Response:**
```powershell
# Generated metamorphic PowerShell payload
$ErrorActionPreference = 'SilentlyContinue'

# AMSI Bypass
try {
    $ᴀᴍsɪᴜᴛɪʟs = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    $ᴀᴍsɪꜰɪᴇʟᴅ = $ᴀᴍsɪᴜᴛɪʟs.GetField('amsiInitFailed', 'NonPublic,Static')
    $ᴀᴍsɪꜰɪᴇʟᴅ.SetValue($null, $true)
} catch {}

# ... additional obfuscated payload content
```

#### `GET /api/v1/metamorphic/download/{filename}`
Generate and download payload as a .ps1 file.

**Headers:**
- `x-api-key`: Your API key

**Response:** PowerShell file download

### Monitoring Endpoints

#### `GET /health`
Health check endpoint (no authentication required).

**Response:**
```json
{
  "status": "healthy",
  "timestamp": 1640995200.123,
  "version": "2.0.0",
  "stats": {
    "total_generated": 1337,
    "total_errors": 2,
    "average_generation_time": 0.856,
    "concurrent_generations": 0
  }
}
```

#### `GET /metrics` (Authenticated)
Detailed metrics for monitoring systems.

#### `GET /dashboard` (Authenticated)
Comprehensive dashboard data including system metrics, application stats, and health status.

## 🧪 Testing

### Comprehensive Test Suite

```bash
# Python-based comprehensive testing
python enhanced_testing.py --url http://localhost:8080 --api-key "your_api_key"

# Quick test
python enhanced_testing.py --quick

# With custom output
python enhanced_testing.py --output test_report.txt
```

### PowerShell Testing (Windows)

```powershell
# Run comprehensive tests
.\test_api.ps1 -BaseUrl "http://localhost:8080" -ApiKey "your_api_key" -TestCount 5

# Quick test
.\test_api.ps1 -Quick

# Verbose output
.\test_api.ps1 -Verbose
```

### Manual Testing

```bash
# Test health endpoint
curl http://localhost:8080/health

# Test payload generation
curl -X POST http://localhost:8080/api/v1/metamorphic/generate \
  -H "x-api-key: your_api_key_here"

# Test download endpoint
curl -X GET http://localhost:8080/api/v1/metamorphic/download/test.ps1 \
  -H "x-api-key: your_api_key_here" \
  -o test_payload.ps1
```

## 📊 Monitoring & Observability

### Built-in Monitoring

The application includes comprehensive monitoring capabilities:

- **System Metrics**: CPU, memory, disk usage
- **Application Metrics**: Request rates, response times, error rates
- **Security Metrics**: Authentication attempts, rate limiting events
- **Payload Metrics**: Generation times, complexity scores, uniqueness rates

### Prometheus Integration

When using the full Docker stack, metrics are automatically exported to Prometheus:

```yaml
# Access points
- Prometheus: http://localhost:9091
- Grafana: http://localhost:3000 (admin/admin123)
- API Metrics: http://localhost:8080/metrics
```

### Alert Configuration

Default alerts are configured for:
- High CPU usage (>85% for 5 minutes)
- High memory usage (>90% for 3 minutes)
- Slow payload generation (>10 seconds average)
- High error rates (>5 errors in 5 minutes)

## 🔐 Security Considerations

### Best Practices

1. **Strong API Keys**: Use at least 32 characters
2. **Environment Variables**: Never hardcode sensitive data
3. **Rate Limiting**: Configure appropriate limits for your use case
4. **Logging**: Monitor security audit logs regularly
5. **Network Security**: Use HTTPS in production
6. **Container Security**: Run containers as non-root user
7. **Regular Updates**: Keep dependencies updated

### Security Features

- **Request Validation**: Size limits, content validation
- **IP Tracking**: Monitor and log client information
- **Audit Logging**: Complete trail of all activities
- **Error Handling**: Secure error responses
- **Resource Limits**: Prevent resource exhaustion

## 🐳 Docker Deployment

### Simple Deployment

```bash
# Basic deployment
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Full Monitoring Stack

```bash
# Deploy with monitoring
docker-compose -f docker-compose-full.yml up -d

# Access services
echo "API: http://localhost:8080"
echo "Prometheus: http://localhost:9091"
echo "Grafana: http://localhost:3000"
```

### Environment Configuration

Create a `.env` file for Docker deployment:

```bash
API_KEY=your_secure_api_key_here_minimum_32_characters
JWT_SECRET_KEY=your_jwt_secret_key_here_minimum_64_characters
REDIS_PASSWORD=secure_redis_password
GRAFANA_PASSWORD=secure_grafana_password
```

## 🛠️ Development

### Project Structure

```
metamorphic_payload_api/
├── app.py                    # Main Flask application
├── payload_generator.py      # Enhanced payload generation
├── config.py                # Configuration management
├── security.py              # Security middleware
├── monitoring.py            # Monitoring and metrics
├── logging_config.py        # Logging configuration
├── enhanced_testing.py      # Comprehensive testing
├── test_api.ps1            # PowerShell testing
├── enhanced_build.sh       # Build and deployment
├── requirements.txt        # Python dependencies
├── Dockerfile             # Container configuration
├── docker-compose*.yml    # Container orchestration
├── .env.example           # Environment template
└── README.md             # Documentation
```

### Adding Custom Features

1. **Custom Obfuscation**: Extend `ObfuscationEngine` class
2. **New Endpoints**: Add routes in `app.py`
3. **Custom Metrics**: Use `app_metrics.record_*` methods
4. **Alert Rules**: Add rules in `monitoring.py`

### Code Quality

The codebase follows Python best practices:
- Type hints for better IDE support
- Comprehensive error handling
- Proper logging throughout
- Thread-safe operations
- Clean architecture with separation of concerns

## 📈 Performance Optimization

### Configuration Tuning

```bash
# High-performance configuration
MAX_CONCURRENT_GENERATIONS=10
RATE_LIMIT_PER_MINUTE=50
PAYLOAD_RETENTION_HOURS=6
```

### Monitoring Performance

- **Response Times**: Target <2 seconds for payload generation
- **Memory Usage**: Monitor for memory leaks
- **CPU Usage**: Should stay below 80% under normal load
- **Disk Space**: Automatic cleanup prevents disk filling

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes with proper tests
4. Commit your changes: `git commit -m 'Add amazing feature'`
5. Push to the branch: `git push origin feature/amazing-feature`
6. Open a Pull Request

### Development Setup

```bash
# Setup development environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run tests
python enhanced_testing.py --quick

# Run with development settings
export FLASK_ENV=development
python app.py
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is intended for authorized security testing and educational purposes only. Users are responsible for ensuring they have proper authorization before using this tool in any environment. The developers assume no liability for misuse of this software.

## 🆘 Support

- **Issues**: Report bugs and feature requests via GitHub Issues
- **Documentation**: Comprehensive documentation in this README
- **Testing**: Use the built-in testing suites for validation
- **Monitoring**: Check health endpoints and logs for troubleshooting

## 🎯 Roadmap

### Upcoming Features
- [ ] REST API v2 with enhanced endpoints
- [ ] Plugin system for custom obfuscation techniques
- [ ] Web-based management interface
- [ ] Advanced payload templates
- [ ] Integration with popular security frameworks
- [ ] Machine learning-based evasion techniques

---

**Version**: 2.0.0  
**Last Updated**: June 2025  
**Compatibility**: Python 3.8+ | Docker 20+ | PowerShell 5+
  - Sum decomposition

### 2. Polymorphic Components

#### Dynamic Code Generation
- **Function Signatures**: Creates unique function names and parameters
- **Control Flow**: Randomizes code block ordering
- **Variable Scope**: Implements dynamic scoping
- **Type Conversions**: Random type casting and conversion

#### Code Structure Variation
- **Block Reordering**: Shuffles code blocks while maintaining functionality
- **Junk Code Injection**: Adds non-functional code blocks:
  - Random variable declarations
  - Dummy function definitions
  - Conditional statements
  - Array operations
  - String manipulations
  - Date/time operations
  - GUID generation
  - Hash table creation
  - Regular expression patterns
  - XML/JSON operations

### 3. Anti-Analysis Features

#### AMSI Bypass Techniques
- **Multiple Bypass Methods**:
  - Reflection-based bypass
  - Memory patching
  - Add-Type injection
  - Environment variable manipulation
  - Provider removal
- **Random Selection**: Each payload uses a different bypass method

#### Network Operations
- **Dynamic C2 Selection**: Random endpoint selection from predefined list
- **Connection Timing**: Random delays between operations
- **Error Handling**: Silent error suppression
- **Encryption**: AES encryption with random keys and IVs

### 4. Helper Functions

The engine includes a comprehensive set of utility functions:
- `Convert-StringToBytes`: UTF8 string to byte array conversion
- `Convert-ToBase64`: Base64 encoding
- `Convert-FromBase64`: Base64 decoding
- `Convert-ToHex`: Hexadecimal encoding
- `Convert-FromHex`: Hexadecimal decoding
- `Convert-Rot13`: ROT13 transformation
- `Convert-ToUnicode`: Unicode escape sequence conversion
- `Convert-FromUnicode`: Unicode escape sequence decoding
- `Convert-ToBinary`: Binary string conversion
- `Convert-FromBinary`: Binary string decoding

### 5. Payload Generation Process

1. **Initialization**:
   - Generate unique filename with timestamp
   - Initialize variable name mapping
   - Select random AMSI bypass technique

2. **Core Components**:
   - AMSI bypass implementation
   - AES encryption setup
   - Network operation configuration

3. **Obfuscation**:
   - Apply variable name morphing
   - Implement string obfuscation
   - Add integer obfuscation
   - Inject junk code (15-25 random blocks)

4. **Finalization**:
   - Add error handling preferences
   - Include helper functions
   - Combine all components
   - Save to unique file

## API Implementation

### Core Components

1. **Payload Generator (`payload_generator.py`)**
   - Implements the metamorphic engine
   - Handles code transformation and obfuscation
   - Manages payload uniqueness verification
   - Provides payload validation and sanitization

2. **API Server (`app.py`)**
   - Flask-based REST API implementation
   - Secure endpoint routing
   - API key validation
   - Response formatting and error handling

3. **Configuration (`config.py`)**
   - API key management
   - Endpoint configuration
   - Security settings
   - Generation parameters

### API Endpoints

1. **Generate Endpoint (`/generate`)**
   ```http
   POST /generate
   Headers:
     x-api-key: your_api_key_here
   Response:
     Content-Type: text/plain
     Body: Obfuscated PowerShell payload
   ```

2. **Download Endpoint (`/download`)**
   ```http
   GET /download/payload.ps1
   Headers:
     x-api-key: your_api_key_here
   Response:
     Content-Type: application/octet-stream
     Content-Disposition: attachment; filename=payload.ps1
   ```

## Prerequisites

- Python 3.6+
- Flask
- PowerShell (for testing payloads)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/metamorphic_payload_api.git
cd metamorphic_payload_api
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure the API:
   - Edit `config.py` to set your desired API key
   - The default endpoint path is `/generate` but can be changed

4. Run the build script:
```bash
chmod +x build.sh
./build.sh
```

## Usage

### Generate a Payload

```bash
curl -X POST http://localhost:8080/generate \
  -H "x-api-key: your_api_key_here" \
  -o payload.ps1
```

### Download a Payload

```bash
curl -X GET http://localhost:8080/download/payload.ps1 \
  -H "x-api-key: your_api_key_here" \
  -o downloaded_payload.ps1
```

### Testing

The repository includes two test scripts:

1. `test_generate.sh`: Tests the `/generate` endpoint
   - Generates 5 payloads
   - Compares MD5 hashes to verify uniqueness
   - Performs diff comparisons

2. `test_endpoints.sh`: Tests both endpoints
   - Tests `/generate` and `/download` endpoints
   - Verifies payload uniqueness
   - Compares outputs between endpoints

Run the tests:
```bash
chmod +x test_*.sh
./test_generate.sh
./test_endpoints.sh
```

## Security Considerations

- The API is designed to be stealthy and secure
- All unauthorized access attempts return 404
- API key is required for all endpoints
- No default routes or index pages
- Each payload is unique and obfuscated
- Rate limiting and request validation
- Input sanitization and validation
- Secure error handling

## Project Structure

```
metamorphic_payload_api/
├── app.py              # Main Flask application
├── payload_generator.py # Payload generation logic
├── config.py           # Configuration settings
├── requirements.txt    # Python dependencies
├── build.sh           # Build script
├── test_generate.sh   # Generate endpoint tests
└── test_endpoints.sh  # Full endpoint tests
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and security research purposes only. Users are responsible for ensuring they have proper authorization before using this tool in any environment.
