#!/bin/bash

# Enhanced Deployment Script for Metamorphic Payload API v3.0
# Supports Docker, standalone, and development deployments

set -e

# Configuration
PROJECT_NAME="metamorphic-payload-api"
VERSION="3.0.0"
DEFAULT_ENV_FILE=".env"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_header() { echo -e "${CYAN}=== $1 ===${NC}"; }

# Help function
show_help() {
    cat << EOF
Metamorphic Payload API v${VERSION} Deployment Script

Usage: $0 [OPTIONS] COMMAND

COMMANDS:
    docker          Deploy using Docker Compose
    docker-full     Deploy with full stack (nginx, redis)
    standalone      Deploy standalone Python application
    dev             Start development environment
    staging         Deploy staging server only
    test            Run comprehensive test suite
    stop            Stop all running services
    clean           Clean up containers and volumes
    logs            Show logs from services
    status          Show status of services

OPTIONS:
    -e, --env FILE      Use specific environment file (default: .env)
    -p, --port PORT     Override default port
    -h, --help          Show this help message
    -v, --verbose       Enable verbose output
    --no-build          Skip building images (docker only)
    --dev-mode          Enable development features

EXAMPLES:
    $0 docker                    # Deploy with Docker Compose
    $0 docker-full              # Deploy full stack with nginx
    $0 standalone -p 8080       # Standalone deployment on port 8080
    $0 dev                      # Development environment
    $0 test --verbose           # Run tests with verbose output

EOF
}

# Parse command line arguments
COMMAND=""
ENV_FILE="$DEFAULT_ENV_FILE"
PORT=""
VERBOSE=false
NO_BUILD=false
DEV_MODE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--env)
            ENV_FILE="$2"
            shift 2
            ;;
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --no-build)
            NO_BUILD=true
            shift
            ;;
        --dev-mode)
            DEV_MODE=true
            shift
            ;;
        docker|docker-full|standalone|dev|staging|test|stop|clean|logs|status)
            COMMAND="$1"
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

if [ -z "$COMMAND" ]; then
    log_error "No command specified"
    show_help
    exit 1
fi

# Set verbose mode
if [ "$VERBOSE" = true ]; then
    set -x
fi

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    
    case $COMMAND in
        docker|docker-full)
            if ! command -v docker &> /dev/null; then
                log_error "Docker is not installed"
                exit 1
            fi
            
            if ! command -v docker-compose &> /dev/null; then
                log_error "Docker Compose is not installed"
                exit 1
            fi
            ;;
        standalone|dev)
            if ! command -v python3 &> /dev/null; then
                log_error "Python 3 is not installed"
                exit 1
            fi
            
            if ! command -v pip &> /dev/null && ! command -v pip3 &> /dev/null; then
                log_error "pip is not installed"
                exit 1
            fi
            ;;
        test)
            if ! command -v curl &> /dev/null; then
                log_error "curl is required for testing"
                exit 1
            fi
            ;;
    esac
    
    log_success "Dependencies check passed"
}

# Setup environment
setup_environment() {
    log_info "Setting up environment..."
    
    # Create required directories
    mkdir -p logs output data monitoring staging_payloads
    
    # Check for environment file
    if [ ! -f "$ENV_FILE" ]; then
        if [ -f ".env.example" ]; then
            log_warning "Environment file $ENV_FILE not found, copying from .env.example"
            cp .env.example "$ENV_FILE"
            log_warning "Please edit $ENV_FILE with your configuration before continuing"
            
            if [ "$COMMAND" != "dev" ]; then
                exit 1
            fi
        else
            log_error "No environment file found and no .env.example to copy from"
            exit 1
        fi
    fi
    
    # Source environment variables
    if [ -f "$ENV_FILE" ]; then
        export $(grep -v '^#' "$ENV_FILE" | xargs)
    fi
    
    # Override port if specified
    if [ -n "$PORT" ]; then
        export PORT="$PORT"
    fi
    
    # Set development mode
    if [ "$DEV_MODE" = true ]; then
        export FLASK_ENV=development
        export FLASK_DEBUG=true
        export LOG_LEVEL=DEBUG
    fi
    
    log_success "Environment setup complete"
}

# Install Python dependencies
install_python_deps() {
    log_info "Installing Python dependencies..."
    
    # Use virtual environment if available
    if [ -d "venv" ]; then
        source venv/bin/activate
        log_info "Using existing virtual environment"
    elif [ "$COMMAND" = "dev" ] || [ "$COMMAND" = "standalone" ]; then
        log_info "Creating virtual environment..."
        python3 -m venv venv
        source venv/bin/activate
    fi
    
    # Install requirements
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
        log_success "Python dependencies installed"
    else
        log_error "requirements.txt not found"
        exit 1
    fi
}

# Docker deployment
deploy_docker() {
    log_header "Docker Deployment"
    
    local compose_file="docker-compose.yml"
    local build_flag=""
    
    if [ "$COMMAND" = "docker-full" ]; then
        compose_file="docker-compose-full.yml"
        if [ ! -f "$compose_file" ]; then
            compose_file="docker-compose.yml"
            log_warning "Full compose file not found, using standard deployment"
        fi
    fi
    
    if [ "$NO_BUILD" = false ]; then
        build_flag="--build"
    fi
    
    log_info "Starting services with $compose_file..."
    docker-compose -f "$compose_file" up -d $build_flag
    
    # Wait for services to be healthy
    log_info "Waiting for services to start..."
    sleep 10
    
    # Check service health
    if docker-compose -f "$compose_file" ps | grep -q "Up"; then
        log_success "Services started successfully"
        
        # Show service URLs
        echo ""
        log_info "Service URLs:"
        echo "  Main API: http://localhost:${PORT:-8080}"
        echo "  Staging Server: http://localhost:9090"
        echo "  Health Check: http://localhost:${PORT:-8080}/health"
        
        if [ "$COMMAND" = "docker-full" ]; then
            echo "  Nginx Proxy: http://localhost:80"
            echo "  Redis: localhost:6379"
        fi
    else
        log_error "Failed to start services"
        docker-compose -f "$compose_file" logs
        exit 1
    fi
}

# Standalone deployment
deploy_standalone() {
    log_header "Standalone Deployment"
    
    install_python_deps
    
    log_info "Starting main API server..."
    if [ "$DEV_MODE" = true ]; then
        python app.py &
    else
        nohup python app.py > logs/app.log 2>&1 &
    fi
    
    MAIN_PID=$!
    echo $MAIN_PID > .main.pid
    
    log_info "Starting staging server..."
    if [ "$DEV_MODE" = true ]; then
        python staging_server.py &
    else
        nohup python staging_server.py > logs/staging.log 2>&1 &
    fi
    
    STAGING_PID=$!
    echo $STAGING_PID > .staging.pid
    
    # Wait for services to start
    sleep 5
    
    # Check if processes are running
    if kill -0 $MAIN_PID 2>/dev/null && kill -0 $STAGING_PID 2>/dev/null; then
        log_success "Services started successfully"
        log_info "Main API PID: $MAIN_PID"
        log_info "Staging Server PID: $STAGING_PID"
        
        echo ""
        log_info "Service URLs:"
        echo "  Main API: http://localhost:${PORT:-8080}"
        echo "  Staging Server: http://localhost:9090"
        echo "  Health Check: http://localhost:${PORT:-8080}/health"
        
        if [ "$DEV_MODE" = false ]; then
            echo ""
            log_info "Logs:"
            echo "  Main API: logs/app.log"
            echo "  Staging Server: logs/staging.log"
        fi
    else
        log_error "Failed to start services"
        exit 1
    fi
}

# Development environment
deploy_dev() {
    log_header "Development Environment"
    
    export FLASK_ENV=development
    export FLASK_DEBUG=true
    export LOG_LEVEL=DEBUG
    
    install_python_deps
    
    log_info "Starting development servers..."
    
    # Start staging server in background
    python staging_server.py &
    STAGING_PID=$!
    
    # Start main API in foreground for development
    log_success "Development environment ready"
    log_info "Staging server running (PID: $STAGING_PID)"
    log_info "Starting main API in development mode..."
    
    python app.py
}

# Staging server only
deploy_staging() {
    log_header "Staging Server Deployment"
    
    install_python_deps
    
    log_info "Starting staging server..."
    python staging_server.py
}

# Run tests
run_tests() {
    log_header "Running Test Suite"
    
    # Check if API is running
    local api_url="http://localhost:${PORT:-8080}"
    
    if ! curl -s "$api_url/health" > /dev/null; then
        log_error "API is not running at $api_url"
        log_info "Start the API first with: $0 docker|standalone|dev"
        exit 1
    fi
    
    log_info "Running enhanced API tests..."
    
    # Run PowerShell tests if available
    if command -v pwsh &> /dev/null && [ -f "test_enhanced_api.ps1" ]; then
        log_info "Running PowerShell test suite..."
        pwsh -File test_enhanced_api.ps1 -BaseUrl "$api_url" -Verbose:$VERBOSE
    fi
    
    # Run Python tests if available
    if [ -f "enhanced_testing.py" ]; then
        log_info "Running Python test suite..."
        if [ "$VERBOSE" = true ]; then
            python enhanced_testing.py
        else
            python enhanced_testing.py > /dev/null 2>&1
        fi
    fi
    
    log_success "Test suite completed"
}

# Stop services
stop_services() {
    log_header "Stopping Services"
    
    # Stop Docker services
    if [ -f "docker-compose.yml" ]; then
        docker-compose down
    fi
    
    if [ -f "docker-compose-full.yml" ]; then
        docker-compose -f docker-compose-full.yml down
    fi
    
    # Stop standalone services
    if [ -f ".main.pid" ]; then
        MAIN_PID=$(cat .main.pid)
        if kill -0 $MAIN_PID 2>/dev/null; then
            kill $MAIN_PID
            log_info "Stopped main API (PID: $MAIN_PID)"
        fi
        rm -f .main.pid
    fi
    
    if [ -f ".staging.pid" ]; then
        STAGING_PID=$(cat .staging.pid)
        if kill -0 $STAGING_PID 2>/dev/null; then
            kill $STAGING_PID
            log_info "Stopped staging server (PID: $STAGING_PID)"
        fi
        rm -f .staging.pid
    fi
    
    log_success "Services stopped"
}

# Clean up
clean_up() {
    log_header "Cleaning Up"
    
    stop_services
    
    # Remove Docker containers and volumes
    if command -v docker &> /dev/null; then
        docker system prune -f
        docker volume prune -f
    fi
    
    # Clean temporary files
    rm -rf __pycache__ .pytest_cache
    rm -f .main.pid .staging.pid
    
    log_success "Cleanup completed"
}

# Show logs
show_logs() {
    log_header "Service Logs"
    
    if docker ps | grep -q "$PROJECT_NAME"; then
        log_info "Docker service logs:"
        docker-compose logs -f
    elif [ -f "logs/app.log" ] || [ -f "logs/staging.log" ]; then
        log_info "Standalone service logs:"
        if [ -f "logs/app.log" ]; then
            echo "=== Main API Logs ==="
            tail -f logs/app.log &
        fi
        if [ -f "logs/staging.log" ]; then
            echo "=== Staging Server Logs ==="
            tail -f logs/staging.log
        fi
    else
        log_warning "No log files found"
    fi
}

# Show status
show_status() {
    log_header "Service Status"
    
    # Check Docker services
    if command -v docker &> /dev/null && docker ps | grep -q "$PROJECT_NAME"; then
        log_info "Docker services:"
        docker-compose ps
    fi
    
    # Check standalone services
    local main_running=false
    local staging_running=false
    
    if [ -f ".main.pid" ]; then
        MAIN_PID=$(cat .main.pid)
        if kill -0 $MAIN_PID 2>/dev/null; then
            log_info "Main API running (PID: $MAIN_PID)"
            main_running=true
        fi
    fi
    
    if [ -f ".staging.pid" ]; then
        STAGING_PID=$(cat .staging.pid)
        if kill -0 $STAGING_PID 2>/dev/null; then
            log_info "Staging server running (PID: $STAGING_PID)"
            staging_running=true
        fi
    fi
    
    if [ "$main_running" = false ] && [ "$staging_running" = false ]; then
        log_warning "No services appear to be running"
    fi
}

# Main execution
main() {
    log_header "Metamorphic Payload API v${VERSION} Deployment"
    
    check_dependencies
    setup_environment
    
    case $COMMAND in
        docker)
            deploy_docker
            ;;
        docker-full)
            deploy_docker
            ;;
        standalone)
            deploy_standalone
            ;;
        dev)
            deploy_dev
            ;;
        staging)
            deploy_staging
            ;;
        test)
            run_tests
            ;;
        stop)
            stop_services
            ;;
        clean)
            clean_up
            ;;
        logs)
            show_logs
            ;;
        status)
            show_status
            ;;
        *)
            log_error "Unknown command: $COMMAND"
            show_help
            exit 1
            ;;
    esac
}

# Signal handlers
trap 'log_warning "Deployment interrupted"; exit 130' INT
trap 'log_error "Deployment failed"; exit 1' ERR

# Run main function
main
