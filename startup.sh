#!/bin/bash
# Startup script for Insider Threat Detection System
# This script ensures the application starts properly in production

echo "Starting Insider Threat Detection System..."

# Set environment variables for production
export FLASK_ENV=production
export FLASK_DEBUG=false
export SPLUNK_ENABLED=false

# Get port from environment or use default
PORT=${PORT:-5000}

echo "Starting Flask application on port $PORT..."
python run.py