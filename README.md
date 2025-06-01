# Guitar Practice Web App

A web application for guitarists to track their practice sessions, manage songs, and improve chord transitions.

## Features

- **User Authentication**
  - Secure login and registration
  - Password hashing and protection
  - Admin dashboard for user management

- **Song Management**
  - Add, edit, and delete songs
  - Store chord progressions and strumming patterns
  - Track BPM and time signatures
  - Capo position tracking
  - Personal song library

### Strumming Pattern Notation

When entering a strumming pattern for a song, you can use the following characters:

- `D`: Represents a downstroke. Plays a stronger beat sound during playback.
- `U`: Represents an upstroke. Plays a standard click sound during playback.
- `-`: Represents a silent rest or missed stroke. Plays no sound.
- ` `: Represents a silent rest or pause. Plays no sound.

The playback feature interprets each character (including spaces and hyphens) as a time subdivision equivalent to an **eighth note** at the song's specified BPM.

To create rhythms:
- A sequence like `D U` represents two eighth notes (a quarter note). At 120 BPM, this would be 0.5 seconds total.
- A pattern like `D - U -` represents a downstroke on beat 1, a silent rest on the 'and' of 1, an upstroke on beat 2, and a silent rest on the 'and' of 2. Each character is an eighth note duration.
- Use spaces and hyphens to represent rests and align your strokes with the beats of the song. For example, `D DU UDU` should be entered with spaces/hyphens to represent the rests if intended as a full measure in 4/4 time (e.g., `D - D U - U D U` or similar depending on the exact rhythm).

- **Practice Tools**
  - One-minute chord change practice
  - Predefined chord pairs with difficulty levels
  - Practice session tracking
  - Progress monitoring
  - Practice history

- **Chord Diagrams**
  - Interactive SVG chord diagrams
  - Available built-in chords:
    - Basic: C, G, D, A, E
    - Minor: Am, Em, Dm, Bm
    - Seventh: G7, C7, A7, E7, B7
    - Extended: Fmaj7, Cadd9
  - DB stored chord interface
  - Chord varient support
  - Shows fret positions, open strings, muted strings, and finger positions
  - Access via `/chord/<chord_name>` (e.g., `/chord/C`)

- **Data Management**
  - Backup and restore functionality
  - SQLite database
  - Data export capabilities

## Installation

### Option 1: Docker (Recommended)

1. Build the Docker image:
```bash
docker build -t guitar-webapp .
```

2. Run the container:
```bash
docker run -d -p 5001:5001 --name guitar-webapp guitar-webapp
```

3. Access the application at `http://localhost:5001`

### Option 2: Manual Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/guitar-webapp.git
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
   Create a `.env` file in the project root with:
   ```
   SECRET_KEY=your-secret-key-here
   DATABASE_URL=sqlite:///instance/guitar.db
   ```

5. Initialize the database:
```bash
flask db upgrade
```

6. Run the application:
```bash
python app.py
```

## Usage

1. Open your browser and navigate to `http://localhost:5001`

2. Create an account or log in with the default admin credentials:
   - Username: admin
   - Password: Password1

3. Start using the application:
   - Add songs to your library
   - Use the chord changes practice tool
   - Track your practice sessions
   - Monitor your progress
   - Backup your data when needed

## Development

The application is built with:
- Flask web framework
- SQLAlchemy for database management
- Flask-Login for user authentication
- SVG for chord diagram generation
- Bootstrap 5 for styling
- Awesome icons

## Docker Development

For development with Docker, use **docker-compose** for easier management and volume mounting:

1. Build and start the development container:
```bash
docker-compose up --build -d
```

2. Access the application at `http://localhost:5001`

- The `docker-compose.yml` mounts the `./instance` directory for persistent data.
- Code changes require a container restart to take effect (unless you mount the whole app directory and use a live-reload tool).

### Rebuilding the Docker Image After a Git Pull

If you pull new changes from git (e.g., `git pull`), you should rebuild the Docker image to ensure all dependencies and code are up to date:

```bash
docker-compose down
# Optionally clean up unused Docker resources:
docker system prune -f
# Rebuild and start the container:
docker-compose up --build -d
```

Or use the provided scripts for convenience:

- **update.sh**: Pulls latest code, rebuilds the image, and restarts the app.
  ```bash
  ./update.sh
  ```
- **restart.sh**: Rebuilds and restarts the container (without pulling from git).
  ```bash
  ./restart.sh
  ```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

If you encounter any issues or have questions, please open an issue on the GitHub repository.

## License

This project is released under The Unlicense. See the [LICENSE](LICENSE) file for details.
