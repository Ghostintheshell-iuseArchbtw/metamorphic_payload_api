# Metamorphic Payload API

A secure and stealthy API service that generates unique, metamorphic PowerShell payloads. Each generated payload is obfuscated and unique, making it suitable for security testing and research purposes.

## Features

- **Metamorphic Payload Generation**: Each request generates a unique, obfuscated PowerShell payload
- **Security by Design**:
  - Hidden endpoint path
  - API Key authentication
  - 404 responses for unauthorized access (stealth mode)
  - No default routes or index pages
- **Dual Endpoints**:
  - `/generate`: Returns raw PowerShell content
  - `/download`: Serves payload as downloadable .ps1 file
- **Unique Payloads**: Each generation creates a different payload, verified through MD5 hashing
- **Configurable Generation**: Runtime options allow custom C2 endpoints and junk-code density

## Metamorphic Engine Architecture

The metamorphic engine employs several sophisticated techniques to generate unique, obfuscated payloads:

### 1. Code Transformation Layers

#### Variable Name Morphing
- **Unicode Character Sets**: Utilizes multiple character sets including:
  - Greek uppercase letters
  - Cyrillic characters
  - Mathematical script symbols
  - Double-struck characters
- **Dynamic Naming**: Generates unique variable names with:
  - Random prefixes (e.g., 'tmp', 'var', 'obj', 'str')
  - Random suffixes (e.g., 'Obj', 'Val', 'Str', 'Int')
  - Case mixing (random upper/lower case)
  - Length variation (8-20 characters)

#### String Obfuscation
- **Multiple Encoding Methods**:
  - Base64 encoding with UTF8 conversion
  - Hexadecimal representation
  - Character array construction
  - String splitting and joining
  - Format string manipulation
  - String concatenation
  - Reverse string operations
  - XOR encryption with random keys
  - ROT13 transformation
  - Unicode escape sequences

#### Integer Obfuscation
- **Mathematical Transformations**:
  - Random number splitting
  - Hexadecimal representation
  - String parsing
  - Sum decomposition
  - XOR masking

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
