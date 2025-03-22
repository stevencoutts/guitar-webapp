# Guitar Practice Web Application

A web application for managing guitar practice sessions, songs, and chord progressions.

## Features

- User authentication and authorization
- Song management (add, edit, delete songs)
- Chord progression tracking
- Practice session recording
- One-minute chord changes practice
- Metronome functionality
- Backup and restore functionality
- Admin panel for user management

## Prerequisites

- Python 3.11 or higher
- Docker and Docker Compose
- Git

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/stevencoutts/guitar-webapp.git
   cd guitar-webapp
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. Initialize the database:
   ```bash
   flask db upgrade
   ```

6. Create an admin user:
   ```bash
   python make_admin.py
   ```

## Running with Docker

### Quick Start

1. Build and start the Docker container:
   ```bash
   docker-compose up --build
   ```

2. Access the application at http://localhost:5001

### Using the Update Script

The project includes an update script that automates the process of updating dependencies and rebuilding the Docker image:

```bash
./update.sh
```

This script will:
1. Stop any running containers
2. Pull the latest changes from git
3. Update Python dependencies
4. Clean up Docker resources
5. Rebuild the Docker image
6. Start the application
7. Show the application logs

### Manual Docker Commands

If you prefer to run Docker commands manually:

1. Build the image:
   ```bash
   docker-compose build
   ```

2. Start the application:
   ```bash
   docker-compose up -d
   ```

3. View logs:
   ```bash
   docker-compose logs -f
   ```

4. Stop the application:
   ```bash
   docker-compose down
   ```

## Development

1. Run the development server:
   ```bash
   flask run
   ```

2. Access the application at http://localhost:5000

## Database Management

1. Create a new migration:
   ```bash
   flask db migrate -m "Migration message"
   ```

2. Apply migrations:
   ```bash
   flask db upgrade
   ```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 