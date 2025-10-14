from flask import Flask, render_template, request, jsonify
import subprocess
import json
import os

app = Flask(__name__)

# 🏠 Home route - serves your frontend page
@app.route('/')
def home():
    return render_template('index.html')  # Make sure index.html is inside /templates folder


# 🔍 API route - runs your port scanner
@app.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        host = data.get('host')
        start_port = str(data.get('start_port', 1))
        end_port = str(data.get('end_port', 1024))
        scan_type = data.get('scan_type', 'normal')

        if not host:
            return jsonify({'error': 'Host is required'}), 400

        # Build the command for your enhanced scanner script
        command = ['python3', 'port_scanner_enhanced.py', host, '--start', start_port, '--end', end_port]

        if scan_type == 'aggressive':
            command.append('--verbose')

        # Run the scanner and capture the output
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode != 0:
            return jsonify({'error': result.stderr}), 500

        # Try to parse JSON output if your script supports it
        try:
            output = json.loads(result.stdout)
        except json.JSONDecodeError:
            output = {'raw_output': result.stdout}

        return jsonify(output)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ✅ Health check or status page
@app.route('/status')
def status():
    return "<h2>Port Scanner API Running ✅</h2>"


# Run the app locally (Render uses gunicorn)
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

