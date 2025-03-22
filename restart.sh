#!/bin/bash

echo "🔄 Stopping containers..."
docker-compose down

echo "🧹 Cleaning up..."
docker system prune -f

echo "🏗️  Rebuilding and starting containers..."
docker-compose up --build -d

echo "📝 Showing logs..."
docker-compose logs -f 