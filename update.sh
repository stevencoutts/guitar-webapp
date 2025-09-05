#!/bin/bash

# Exit on error
set -e

echo "🚀 Starting update process..."

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for required commands
if ! command_exists docker; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
    echo "❌ Docker Compose v2 (plugin) is not installed. Please install or upgrade Docker Compose."
    exit 1
fi

# Stop any running containers
echo "🛑 Stopping running containers..."
docker compose down

# Pull latest changes from git
echo "📥 Pulling latest changes from git..."
git pull

# Update Python dependencies
echo "📦 Updating Python dependencies..."
pip install -r requirements.txt

# Clean up Docker resources
echo "🧹 Cleaning up Docker resources..."
docker system prune -af

# Rebuild the Docker image
echo "🏗️  Rebuilding Docker image..."
docker compose build

# Start the application
echo "🚀 Starting the application..."
docker compose up -d

# Wait for the application to start
echo "⏳ Waiting for the application to start..."
sleep 5

# Check if the application is running
if docker compose ps | grep -q "Up"; then
    echo "✅ Application is running successfully!"
    echo "🌐 Access the application at http://localhost:5001"
else
    echo "❌ Application failed to start. Check the logs with: docker compose logs"
    exit 1
fi

# Show logs
echo "📋 Showing application logs..."
docker compose logs --tail=50

echo "✨ Update process completed!" 