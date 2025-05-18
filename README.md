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
