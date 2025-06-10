#!/bin/bash

# Enhanced Build and Deployment Script for Metamorphic Payload API
# Supports multiple deployment modes and comprehensive testing

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
DEPLOYMENT_MODE="development"
SKIP_TESTS=false
CLEANUP=false
VERBOSE=false
API_KEY=""
BUILD_ONLY=false

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    cat << EOF
Enhanced Build and Deployment Script for Metamorphic Payload API

Usage: $0 [OPTIONS]

OPTIONS:
    -m, --mode MODE         Deployment mode: development, production, docker (default: development)
    -k, --api-key KEY       Set API key for the application
    -t, --skip-tests        Skip running tests
    -c, --cleanup           Clean up previous builds and containers
    -b, --build-only        Only build, don't deploy
    -v, --verbose           Enable verbose output
    -h, --help              Show this help message

EXAMPLES:
    $0 -m development                    # Development deployment
    $0 -m production -k "your-api-key"   # Production deployment with API key
    $0 -m docker -c                     # Docker deployment with cleanup
    $0 -t -v                            # Skip tests with verbose output

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -m|--mode)
            DEPLOYMENT_MODE="$2"
            shift 2
            ;;
        -k|--api-key)
            API_KEY="$2"
            shift 2
            ;;
        -t|--skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        -c|--cleanup)
            CLEANUP=true
            shift
            ;;
        -b|--build-only)
            BUILD_ONLY=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Enable verbose mode if requested
if [ "$VERBOSE" = true ]; then
    set -x
fi

# Validate deployment mode
case $DEPLOYMENT_MODE in
    development|production|docker)
        ;;
    *)
        print_error "Invalid deployment mode: $DEPLOYMENT_MODE"
        print_error "Valid modes: development, production, docker"
        exit 1
        ;;
esac

print_status "Starting build and deployment process..."
print_status "Deployment mode: $DEPLOYMENT_MODE"

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed"
        exit 1
    fi
    
    python_version=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1-2)
    min_version="3.8"
    
    if [ "$(printf '%s\n' "$min_version" "$python_version" | sort -V | head -n1)" != "$min_version" ]; then
        print_error "Python 3.8 or higher is required (found: $python_version)"
        exit 1
    fi
    
    print_success "Python $python_version detected"
    
    # Check pip
    if ! command -v pip3 &> /dev/null; then
        print_error "pip3 is not installed"
        exit 1
    fi
    
    # Check Docker for docker deployment
    if [ "$DEPLOYMENT_MODE" = "docker" ]; then
        if ! command -v docker &> /dev/null; then
            print_error "Docker is not installed"
            exit 1
        fi
        
        if ! command -v docker-compose &> /dev/null; then
            print_error "Docker Compose is not installed"
            exit 1
        fi
        
        print_success "Docker and Docker Compose detected"
    fi
}

# Function to cleanup previous builds
cleanup_previous() {
    if [ "$CLEANUP" = true ]; then
        print_status "Cleaning up previous builds..."
        
        # Remove Python cache
        find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
        find . -name "*.pyc" -delete 2>/dev/null || true
        
        # Remove logs
        rm -rf logs/*.log 2>/dev/null || true
        
        # Remove output files
        rm -rf output/*.ps1 2>/dev/null || true
        
        # Remove test artifacts
        rm -rf test_results/ 2>/dev/null || true
        rm -f *.ps1 2>/dev/null || true
        
        # Docker cleanup
        if [ "$DEPLOYMENT_MODE" = "docker" ]; then
            print_status "Cleaning up Docker containers and images..."
            docker-compose -f docker-compose.yml down --remove-orphans 2>/dev/null || true
            docker-compose -f docker-compose-full.yml down --remove-orphans 2>/dev/null || true
            docker image prune -f 2>/dev/null || true
        fi
        
        print_success "Cleanup completed"
    fi
}

# Function to create necessary directories
create_directories() {
    print_status "Creating necessary directories..."
    
    mkdir -p logs
    mkdir -p output
    mkdir -p data
    mkdir -p monitoring
    mkdir -p test_results
    
    print_success "Directories created"
}

# Function to generate secure API key if not provided
generate_api_key() {
    if [ -z "$API_KEY" ]; then
        print_status "Generating secure API key..."
        API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
        print_success "API key generated: ${API_KEY:0:8}..."
    fi
}

# Function to create environment file
create_env_file() {
    print_status "Creating environment configuration..."
    
    # Generate JWT secret
    JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(64))")
    
    cat > .env << EOF
# Metamorphic Payload API Configuration
# Generated on $(date)

# Security Configuration
API_KEY=$API_KEY
JWT_SECRET_KEY=$JWT_SECRET
RATE_LIMIT_PER_MINUTE=10
MAX_PAYLOAD_SIZE=1024000

# Server Configuration
FLASK_ENV=$DEPLOYMENT_MODE
FLASK_DEBUG=$([ "$DEPLOYMENT_MODE" = "development" ] && echo "True" || echo "False")
HOST=0.0.0.0
PORT=8080

# API Endpoints
OBFUSCATED_PATH=/api/v1/metamorphic/generate
DOWNLOAD_PATH=/api/v1/metamorphic/download
HEALTH_PATH=/health

# Payload Configuration
OUTPUT_DIRECTORY=./output
PAYLOAD_RETENTION_HOURS=24
MAX_CONCURRENT_GENERATIONS=5

# Logging Configuration
LOG_LEVEL=$([ "$DEPLOYMENT_MODE" = "development" ] && echo "DEBUG" || echo "INFO")
LOG_FILE=./logs/app.log
LOG_MAX_BYTES=10485760
LOG_BACKUP_COUNT=5

# Database Configuration
DATABASE_URL=sqlite:///payloads.db

# Monitoring Configuration
ENABLE_METRICS=True
METRICS_PORT=9090

# Docker-specific
REDIS_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))")
GRAFANA_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(12))")
EOF
    
    print_success "Environment file created"
}

# Function to install dependencies
install_dependencies() {
    print_status "Installing Python dependencies..."
    
    # Create virtual environment if not in Docker mode
    if [ "$DEPLOYMENT_MODE" != "docker" ]; then
        if [ ! -d "venv" ]; then
            python3 -m venv venv
        fi
        source venv/bin/activate
    fi
    
    # Upgrade pip
    pip3 install --upgrade pip
    
    # Install requirements
    pip3 install -r requirements.txt
    
    print_success "Dependencies installed"
}

# Function to run tests
run_tests() {
    if [ "$SKIP_TESTS" = false ]; then
        print_status "Running comprehensive tests..."
        
        # Create test results directory
        mkdir -p test_results
        
        # Run unit tests if they exist
        if [ -f "test_payload_generator.py" ]; then
            print_status "Running unit tests..."
            python3 -m pytest test_payload_generator.py -v --tb=short > test_results/unit_tests.log 2>&1 || true
        fi
        
        # Start the application in background for integration tests
        if [ "$DEPLOYMENT_MODE" != "docker" ]; then
            print_status "Starting application for integration tests..."
            
            # Source virtual environment if not in Docker
            if [ -d "venv" ]; then
                source venv/bin/activate
            fi
            
            python3 app.py &
            APP_PID=$!
            
            # Wait for application to start
            sleep 5
            
            # Check if application is running
            if kill -0 $APP_PID 2>/dev/null; then
                print_status "Application started successfully (PID: $APP_PID)"
                
                # Run integration tests
                if [ -f "enhanced_testing.py" ]; then
                    print_status "Running integration tests..."
                    python3 enhanced_testing.py --url http://localhost:8080 --api-key "$API_KEY" --output test_results/integration_report.txt > test_results/integration_tests.log 2>&1 || true
                fi
                
                # Stop the application
                kill $APP_PID 2>/dev/null || true
                wait $APP_PID 2>/dev/null || true
                print_status "Application stopped"
            else
                print_error "Failed to start application for testing"
                return 1
            fi
        fi
        
        print_success "Tests completed - check test_results/ for details"
    else
        print_warning "Skipping tests as requested"
    fi
}

# Function to build Docker image
build_docker() {
    print_status "Building Docker image..."
    
    docker build -t metamorphic-payload-api:latest .
    
    if [ $? -eq 0 ]; then
        print_success "Docker image built successfully"
    else
        print_error "Docker build failed"
        exit 1
    fi
}

# Function to deploy based on mode
deploy() {
    case $DEPLOYMENT_MODE in
        development)
            deploy_development
            ;;
        production)
            deploy_production
            ;;
        docker)
            deploy_docker
            ;;
    esac
}

# Function to deploy in development mode
deploy_development() {
    print_status "Deploying in development mode..."
    
    if [ -d "venv" ]; then
        source venv/bin/activate
    fi
    
    print_status "Starting development server..."
    print_success "API will be available at: http://localhost:8080"
    print_success "Health check: http://localhost:8080/health"
    print_success "API Key: $API_KEY"
    
    if [ "$BUILD_ONLY" = false ]; then
        python3 app.py
    else
        print_success "Build-only mode: Application ready to start"
    fi
}

# Function to deploy in production mode
deploy_production() {
    print_status "Deploying in production mode..."
    
    # Install production WSGI server
    pip3 install gunicorn
    
    if [ -d "venv" ]; then
        source venv/bin/activate
    fi
    
    print_status "Starting production server with Gunicorn..."
    print_success "API will be available at: http://localhost:8080"
    print_success "Health check: http://localhost:8080/health"
    print_success "API Key: $API_KEY"
    
    if [ "$BUILD_ONLY" = false ]; then
        gunicorn --bind 0.0.0.0:8080 --workers 4 --timeout 60 --access-logfile logs/access.log --error-logfile logs/error.log app:app
    else
        print_success "Build-only mode: Application ready to start with Gunicorn"
    fi
}

# Function to deploy with Docker
deploy_docker() {
    print_status "Deploying with Docker..."
    
    build_docker
    
    if [ "$BUILD_ONLY" = false ]; then
        print_status "Starting Docker containers..."
        docker-compose up -d
        
        # Wait for containers to be ready
        print_status "Waiting for containers to be ready..."
        sleep 10
        
        # Check container status
        if docker-compose ps | grep -q "Up"; then
            print_success "Docker deployment successful!"
            print_success "API available at: http://localhost:8080"
            print_success "Health check: http://localhost:8080/health"
            print_success "API Key: $API_KEY"
            
            # Show container status
            print_status "Container status:"
            docker-compose ps
        else
            print_error "Some containers failed to start"
            docker-compose logs
            exit 1
        fi
    else
        print_success "Build-only mode: Docker image ready"
    fi
}

# Function to create monitoring configuration
create_monitoring_config() {
    print_status "Creating monitoring configuration..."
    
    mkdir -p monitoring
    
    # Create Prometheus configuration
    cat > monitoring/prometheus.yml << EOF
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'metamorphic-api'
    static_configs:
      - targets: ['metamorphic-api:9090']
    scrape_interval: 15s
    metrics_path: '/metrics'
    
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
EOF
    
    # Create Grafana dashboard configuration
    mkdir -p monitoring/grafana/dashboards
    cat > monitoring/grafana/dashboards/metamorphic-api.json << 'EOF'
{
  "dashboard": {
    "id": null,
    "title": "Metamorphic Payload API",
    "tags": ["metamorphic", "api"],
    "timezone": "browser",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(api_request_count[5m])",
            "legendFormat": "{{endpoint}}"
          }
        ]
      }
    ],
    "version": 1
  }
}
EOF
    
    print_success "Monitoring configuration created"
}

# Function to show deployment summary
show_summary() {
    print_success "Deployment Summary"
    echo "=========================="
    echo "Mode: $DEPLOYMENT_MODE"
    echo "API Key: ${API_KEY:0:8}..."
    echo "Skip Tests: $SKIP_TESTS"
    echo "Cleanup: $CLEANUP"
    echo "Build Only: $BUILD_ONLY"
    echo ""
    
    case $DEPLOYMENT_MODE in
        development|production)
            echo "Application URL: http://localhost:8080"
            echo "Health Check: http://localhost:8080/health"
            ;;
        docker)
            echo "Application URL: http://localhost:8080"
            echo "Health Check: http://localhost:8080/health"
            echo "Prometheus: http://localhost:9091"
            echo "Grafana: http://localhost:3000 (admin/admin123)"
            ;;
    esac
    
    echo ""
    echo "Configuration file: .env"
    echo "Logs directory: logs/"
    echo "Output directory: output/"
    
    if [ "$SKIP_TESTS" = false ]; then
        echo "Test results: test_results/"
    fi
}

# Main execution
main() {
    print_status "Metamorphic Payload API - Enhanced Build & Deploy Script"
    print_status "========================================================"
    
    check_prerequisites
    cleanup_previous
    create_directories
    generate_api_key
    create_env_file
    create_monitoring_config
    
    if [ "$DEPLOYMENT_MODE" != "docker" ]; then
        install_dependencies
    fi
    
    run_tests
    
    if [ "$BUILD_ONLY" = false ]; then
        deploy
    else
        case $DEPLOYMENT_MODE in
            docker)
                build_docker
                ;;
            *)
                print_success "Build completed successfully"
                ;;
        esac
    fi
    
    show_summary
}

# Trap to cleanup on exit
trap 'if [ -n "$APP_PID" ]; then kill $APP_PID 2>/dev/null || true; fi' EXIT

# Run main function
main "$@"
