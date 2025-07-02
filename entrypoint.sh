#!/bin/bash
set -e

if [ "$FLASK_ENV" = "development" ]; then
    echo "Starting Flask development server..."
    flask run --host=0.0.0.0 --port=5001
else
    echo "Starting Gunicorn production server..."
    gunicorn --bind 0.0.0.0:5001 app:app
fi 