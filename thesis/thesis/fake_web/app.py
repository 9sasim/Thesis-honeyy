from flask import Flask, request, render_template, jsonify
import os
import json
import requests
from datetime import datetime
import hashlib

app = Flask(__name__)
UPLOAD_FOLDER = '/uploads'
LOG_FOLDER = '/logs'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['LOG_FOLDER'] = LOG_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
if not os.path.exists(LOG_FOLDER):
    os.makedirs(LOG_FOLDER)

# Simple in-memory log store
upload_log = []
virustotal_log = []

# Function to generate SHA256 hash of a file
def get_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read the file in chunks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Upload vulnerability - allows any file type
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        filename = file.filename
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Get the IP address of the user
        user_ip = request.remote_addr

        # Generate SHA256 hash of the uploaded file
        sha256_hash = get_sha256(file_path)

        # Log file upload event
        upload_entry = {
            "event": "file_uploaded",
            "filename": filename,
            "path": file_path,
            "status": "saved",
            "timestamp": str(datetime.now()),
            "user_ip": user_ip,
            "sha256": sha256_hash
        }
        upload_log.append(upload_entry)

        # Send file to VirusTotal for analysis
        virustotal_url = 'https://www.virustotal.com/api/v3/files'
        api_key = 'e7f11fe5d368714fd63305a37c3b38eb472a48a7fec6b0e1a15a0e466034b35b'
        headers = {
            "x-apikey": api_key
        }
        files = {'file': open(file_path, 'rb')}
        response = requests.post(virustotal_url, headers=headers, files=files)
        file_id = response.json().get('data', {}).get('id')

        # Use the file's SHA256 hash directly in the VirusTotal URL
        virustotal_url = f"https://www.virustotal.com/gui/file/{sha256_hash}/detection"

        # Log VirusTotal result
        virustotal_entry = {
            "event": "file_sent_to_virustotal",
            "filename": filename,
            "virustotal_sha256": sha256_hash,
            "virustotal_url": virustotal_url,
            "timestamp": str(datetime.now()),
            "user_ip": user_ip,
            "sha256": sha256_hash
        }
        virustotal_log.append(virustotal_entry)

        # Save logs to respective files
        with open(os.path.join(LOG_FOLDER, "upload_log.json"), "w") as upload_log_file:
            json.dump(upload_log, upload_log_file)
        with open(os.path.join(LOG_FOLDER, "virustotal_log.json"), "w") as virustotal_log_file:
            json.dump(virustotal_log, virustotal_log_file)

        return jsonify({"message": "File uploaded successfully", "sha256": sha256_hash}), 200

    return render_template('upload.html')

# View logs
@app.route('/logs')
def view_logs():
    return render_template('logs.html', upload_logs=upload_log, virustotal_logs=virustotal_log)

# View scanned files and links to VirusTotal
@app.route('/scanned_files')
def scanned_files():
    file_links = []
    for log in virustotal_log:
        file_links.append({
            "filename": log["filename"],
            "virustotal_url": log["virustotal_url"],
            "sha256": log["sha256"]
        })
    return render_template('scanned_files.html', files=file_links)

# Simple static index page for e-commerce
@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
