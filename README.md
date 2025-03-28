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

- **Practice Tools**
  - One-minute chord change practice
  - Predefined chord pairs with difficulty levels
  - Practice session tracking
  - Progress monitoring
  - Practice history

- **Chord Diagrams**
  - Interactive SVG chord diagrams
  - Available chords:
    - Basic: C, G, D, A, E
    - Minor: Am, Em, Dm, Bm
    - Seventh: G7, C7, A7, E7, B7
    - Extended: Fmaj7, Cadd9
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

For development with Docker:

1. Build the development image:
```bash
docker build -t guitar-webapp-dev -f Dockerfile.dev .
```

2. Run the development container:
```bash
docker run -d -p 5001:5001 -v $(pwd):/app guitar-webapp-dev
```

3. Access the application at `http://localhost:5001`

The development container includes hot-reloading for code changes.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

If you encounter any issues or have questions, please open an issue on the GitHub repository.

## License

This project is released under The Unlicense. See the [LICENSE](LICENSE) file for details.