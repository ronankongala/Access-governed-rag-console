#!/bin/bash
# Azure App Service startup command for the Flask app.
# Single worker keeps the file-based audit log consistent across requests.
# Azure provides the port to bind on via the PORT environment variable.
gunicorn --workers 1 --bind=0.0.0.0:${PORT:-8000} --timeout 120 app:app
