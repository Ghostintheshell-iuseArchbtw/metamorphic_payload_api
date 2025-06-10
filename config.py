import os
import base64
import json
from pathlib import Path
from typing import List, Dict, Any
import secrets

class Config:
    """Enhanced configuration management with environment variable support"""
    
    def __init__(self):
        self._load_env_file()
        
    def _load_env_file(self):
        """Load environment variables from .env file if it exists"""
        env_file = Path('.env')
        if env_file.exists():
            with open(env_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        os.environ[key] = value    # Security Configuration
    @property
    def API_KEY(self) -> str:
        key = os.getenv('API_KEY', 'default_insecure_key_change_immediately')
        if len(key) < 32:
            raise ValueError("API_KEY must be at least 32 characters long")
        return key
    
    @property
    def JWT_SECRET_KEY(self) -> str:
        return os.getenv('JWT_SECRET_KEY', secrets.token_urlsafe(64))
    
    @property
    def RATE_LIMIT_PER_MINUTE(self) -> int:
        return int(os.getenv('RATE_LIMIT_PER_MINUTE', '10'))
    
    @property
    def MAX_PAYLOAD_SIZE(self) -> int:
        return int(os.getenv('MAX_PAYLOAD_SIZE', '1024000'))
    
    # Database Configuration
    @property
    def DATABASE_PATH(self) -> str:
        return os.getenv('DATABASE_PATH', 'data/payloads.db')
    
    @property
    def ENABLE_DATABASE(self) -> bool:
        return os.getenv('ENABLE_DATABASE', 'true').lower() == 'true'
    
    @property
    def DATABASE_URL(self) -> str:
        return os.getenv('DATABASE_URL', f'sqlite:///{self.DATABASE_PATH}')
    
    # Server Configuration
    @property
    def FLASK_ENV(self) -> str:
        return os.getenv('FLASK_ENV', 'production')
    
    @property
    def FLASK_DEBUG(self) -> bool:
        return os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    @property
    def HOST(self) -> str:
        return os.getenv('HOST', '0.0.0.0')
    
    @property
    def PORT(self) -> int:
        return int(os.getenv('PORT', '8080'))
    
    # API Endpoints
    @property
    def OBFUSCATED_PATH(self) -> str:
        return os.getenv('OBFUSCATED_PATH', '/api/v1/metamorphic/generate')
    
    @property
    def DOWNLOAD_PATH(self) -> str:
        return os.getenv('DOWNLOAD_PATH', '/api/v1/metamorphic/download')
    
    @property
    def HEALTH_PATH(self) -> str:
        return os.getenv('HEALTH_PATH', '/health')
    
    # Payload Configuration
    @property
    def OUTPUT_DIRECTORY(self) -> str:
        return os.getenv('OUTPUT_DIRECTORY', './output')
    
    @property
    def PAYLOAD_RETENTION_HOURS(self) -> int:
        return int(os.getenv('PAYLOAD_RETENTION_HOURS', '24'))
    
    @property
    def MAX_CONCURRENT_GENERATIONS(self) -> int:
        return int(os.getenv('MAX_CONCURRENT_GENERATIONS', '5'))
    
    # C2 Configuration
    @property
    def C2_ENDPOINTS(self) -> List[Dict[str, Any]]:
        b64_data = os.getenv('C2_ENDPOINTS_B64', '')
        if b64_data:
            try:
                return json.loads(base64.b64decode(b64_data).decode())
            except:
                pass
        # Fallback to default
        return [
            {"host": "ghostintheshellredteam.com", "port": 4444},
            {"host": "ghostintheshellredteam.com", "port": 9000},
            {"host": "66.228.62.178", "port": 4444},
            {"host": "66.228.62.178", "port": 9000}
        ]
    
    # Logging Configuration
    @property
    def LOG_LEVEL(self) -> str:
        return os.getenv('LOG_LEVEL', 'INFO')
    
    @property
    def LOG_FILE(self) -> str:
        return os.getenv('LOG_FILE', './logs/app.log')
    
    @property
    def LOG_MAX_BYTES(self) -> int:
        return int(os.getenv('LOG_MAX_BYTES', '10485760'))
    
    @property
    def LOG_BACKUP_COUNT(self) -> int:
        return int(os.getenv('LOG_BACKUP_COUNT', '5'))
    
    # Database Configuration
    @property
    def DATABASE_URL(self) -> str:
        return os.getenv('DATABASE_URL', 'sqlite:///payloads.db')
    
    # Monitoring Configuration
    @property
    def ENABLE_METRICS(self) -> bool:
        return os.getenv('ENABLE_METRICS', 'True').lower() == 'true'
    
    @property
    def METRICS_PORT(self) -> int:
        return int(os.getenv('METRICS_PORT', '9090'))

# Global configuration instance
config = Config()

# Backwards compatibility
API_KEY = config.API_KEY
OBFUSCATED_PATH = config.OBFUSCATED_PATH
