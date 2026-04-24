# LogLens Backend API

Backend API for LogLens Security Log Analysis Dashboard.

## Live API
https://loglens-api-57cj.onrender.com

## Features

- Login Authentication
- Upload Log Files
- Async Queue Processing
- Job Status Tracking
- Apache/Nginx Log Parsing
- Attack Detection Engine
- SQL Injection Detection
- XSS Detection
- Directory Traversal Detection
- Brute Force Detection
- Severity Scoring
- Demo Log Endpoint
- CSV / PDF Support

## API Routes

POST /login  
POST /upload  
POST /upload_async  
GET /status/<job_id>  
GET /demo  
GET /

## Tech Stack

- Python
- Flask
- Regex
- Flask-CORS
- Werkzeug Security

## Run Locally

pip install -r requirements.txt
python app.py

## Performance Note

Large files are processed asynchronously in backend jobs. This avoids browser crashes and supports bigger logs.

## Author

Suhas Pawar
