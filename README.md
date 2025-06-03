# 🎸 Guitar Practice Web App

A comprehensive web application designed for guitarists to manage their song library, practice chord transitions, and improve their playing with interactive tools and audio feedback.

![License](https://img.shields.io/badge/license-Unlicense-blue.svg)
![Python](https://img.shields.io/badge/python-3.11-blue.svg)
![Flask](https://img.shields.io/badge/flask-latest-green.svg)
![Docker](https://img.shields.io/badge/docker-ready-blue.svg)

## ✨ Features

### 🎵 Song Management
- **Personal Song Library**: Add, edit, delete, and organize your songs
- **Comprehensive Song Data**: 
  - Title, artist, BPM, time signature, capo position
  - Chord progressions with support for complex notation
  - Custom strumming patterns with visual editor
  - Personal notes and practice reminders
- **Smart Chord Progression Display**: 
  - Two view modes: **Text** (compact) and **Chart** (visual cards)
  - Support for half-measures using `| |` notation
  - Bar-by-bar organization with optional numbering
  - Click-to-highlight chord functionality

### 🎼 Advanced Strumming Pattern Editor
- **Interactive Visual Editor**: Click-based pattern creation with SVG display
- **Multiple Time Signatures**: 
  - Standard signatures (4/4, 3/4, 6/8, etc.)
  - Irrational signatures (4/3, 7/5, 5/6, etc.) with triplet support
- **Flexible Pattern Length**: 1-4 measures with automatic multi-line display
- **Real-time Audio Playback**: Guitar-like sounds for down/up strums, muted strums, and rests
- **Subdivision Control**: Toggle between regular and triplet feels per beat

### 🎚️ Audio Tools
- **Interactive Metronome**: 
  - Visual dot display matching time signature
  - Distinct sounds for downbeats vs. other beats
  - Automatic tempo synchronization with song BPM
- **Strumming Pattern Playback**: 
  - Realistic guitar sounds using Web Audio API
  - Proper timing for 16th notes, triplets, and complex patterns
  - Volume-balanced audio across all features

### 🎯 Interactive Chord Library
- **Dynamic Chord Diagrams**: SVG-generated chord fingerings
- **Multiple Variants**: Support for different chord voicings and positions
- **Visual Chord Display**: 
  - Fret positions, open strings, muted strings
  - Finger placement indicators
  - Starting fret position for barre chords
- **Extensive Chord Database**: 
  - Basic chords: C, G, D, A, E, F
  - Minor chords: Am, Em, Dm, Bm, Fm
  - Seventh chords: G7, C7, A7, E7, B7, D7
  - Extended chords: Fmaj7, Cadd9, Dm9, CMaj7
  - Admin interface for adding custom chords

### 🏃‍♂️ Practice Tools
- **Chord Change Practice**: 
  - One-minute timed sessions
  - Predefined chord pairs with difficulty ratings
  - Real-time scoring and feedback
  - Progress tracking over time
- **Practice History**: Detailed session logs with performance metrics
- **Chord Pair Analytics**: Track which transitions need more work

### 👥 User Management
- **Secure Authentication**: Password hashing with strength requirements
- **Multi-user Support**: Each user has their own song library and practice data
- **Admin Dashboard**: 
  - User management (create, disable, promote to admin)
  - Password reset functionality
  - System administration tools

### 💾 Data Management
- **Backup & Restore**: Full database export/import functionality
- **Persistent Storage**: Docker volume mounting for data preservation
- **Migration Support**: Database schema versioning with Flask-Migrate

## 🚀 Quick Start

### Using Docker (Recommended)

1. **Clone and Start**:
   ```bash
   git clone https://github.com/yourusername/guitar-webapp.git
   cd guitar-webapp
   docker-compose up --build -d
   ```

2. **Access the App**: Navigate to `http://localhost:5001`

3. **Login**: Use the default admin account:
   - Username: `admin`
   - Password: `Password1`

### Manual Installation

1. **Prerequisites**: Python 3.11+, pip, git

2. **Setup Environment**:
   ```bash
   git clone https://github.com/yourusername/guitar-webapp.git
   cd guitar-webapp
   python3.11 -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Configure Environment**:
   Create `.env` file:
   ```env
   SECRET_KEY=your-secret-key-change-this-in-production
   DATABASE_URL=sqlite:///instance/guitar.db
   FLASK_ENV=production
   ```

4. **Initialize Database**:
   ```bash
   flask db upgrade
   ```

5. **Run Application**:
   ```bash
   python app.py
   ```

## 📖 User Guide

### Managing Songs

1. **Add a Song**: Click "Add New Song" and fill in the details
2. **Set Time Signature**: Use standard (4/4, 3/4) or irrational (4/3, 7/5) formats
3. **Create Chord Progression**: 
   - Use chord names separated by spaces or vertical bars
   - Half-measures: `C | F G | C` (F and G share one measure)
4. **Design Strumming Pattern**:
   - Click grid slots to cycle through: Down ↓, Up ↑, Rest -, Mute X
   - Click beat numbers (1,2,3,4) to toggle triplet subdivisions
   - Use display beats selector for multi-measure patterns

### Using Practice Tools

1. **Chord Changes Practice**:
   - Select a chord pair or let the app choose
   - Practice for 60 seconds, hitting space bar for each successful change
   - Review your score and track improvement over time

2. **Song Practice**:
   - Use the metronome for tempo guidance
   - Play along with strumming pattern audio
   - Switch between text and chart views for chord progressions

### Audio Features

- **Metronome**: Click "Start Metronome" on any song page
- **Strumming Playback**: Use "Play Pattern" button
- **Volume**: Audio levels are balanced for comfortable practice

## 🛠️ Technical Details

### Architecture
- **Backend**: Flask with SQLAlchemy ORM
- **Frontend**: Bootstrap 5 + vanilla JavaScript
- **Audio**: Web Audio API for real-time sound generation
- **Graphics**: SVG for chord diagrams and strumming patterns
- **Database**: SQLite with migration support
- **Authentication**: Flask-Login with CSRF protection

### Key Components
- **Song Model**: Stores song data with JSON strumming patterns
- **Chord Engine**: Dynamic SVG generation for chord diagrams
- **Audio Engine**: Real-time audio synthesis for practice tools
- **Pattern Editor**: Interactive strumming pattern creation
- **Practice Tracker**: Session recording and analytics

### Docker Configuration
- **Persistent Data**: Volume mount for database preservation
- **Environment Variables**: Configurable via `.env` file
- **Multi-stage Build**: Optimized container size
- **Health Checks**: Container monitoring capabilities

## 🔧 Development

### Development Setup
```bash
# Start development environment
docker-compose up --build -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Making Changes
1. **Code Changes**: Edit files and rebuild container
2. **Database Changes**: Use Flask-Migrate for schema updates
3. **Testing**: Test locally before deploying

### Useful Scripts
- `./update.sh`: Pull latest code and rebuild
- `./restart.sh`: Quick container restart
- `python make_admin.py`: Create admin user
- `python init_db.py`: Initialize fresh database

## 🐳 Docker Management

### Database Persistence
Your database is automatically preserved between container rebuilds:
- Database file: `./instance/guitar.db` (on host)
- Volume mount: `./instance:/app/instance`
- Safe rebuilding: `docker-compose down && docker-compose up --build -d`

### Container Commands
```bash
# View running containers
docker-compose ps

# Access container shell
docker-compose exec web bash

# View application logs
docker-compose logs web

# Clean up everything
docker-compose down --volumes --rmi all
```

## 🎯 Advanced Usage

### Custom Chord Shapes
1. Access admin panel (`/admin`)
2. Navigate to "Chord Management"
3. Add new chord with fret positions
4. Specify variant names for multiple voicings

### Time Signatures
- **Standard**: `4/4`, `3/4`, `6/8`, `2/4`
- **Irrational**: `4/3`, `7/5`, `5/6` (denominators create triplet feels)
- **Complex**: Any numeric combination supported

### Strumming Patterns
- **Symbols**: ↓ (down), ↑ (up), - (rest), X (mute)
- **Subdivisions**: 16th notes (regular) or triplets per beat
- **Multi-measure**: Up to 4 measures with automatic line wrapping

## 🤝 Contributing

We welcome contributions! Here's how to get started:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature-name`
3. **Make** your changes with tests
4. **Submit** a pull request with clear description

### Development Guidelines
- Follow Python PEP 8 style conventions
- Add tests for new features
- Update documentation for user-facing changes
- Test Docker builds before submitting

## 📋 Requirements

### System Requirements
- **Python**: 3.11 or higher
- **Database**: SQLite (included) or PostgreSQL
- **Browser**: Modern browser with Web Audio API support
- **Docker**: Optional but recommended for deployment

### Python Dependencies
See `requirements.txt` for complete list:
- Flask + extensions (SQLAlchemy, Login, Migrate, WTF)
- Database libraries
- Security and authentication tools

## 🔒 Security

- **Password Hashing**: bcrypt with salt
- **CSRF Protection**: All forms protected
- **Session Management**: Secure cookie configuration
- **Input Validation**: Server-side validation on all inputs
- **SQL Injection**: Prevented via SQLAlchemy ORM

## 📚 API Endpoints

### Public Endpoints
- `GET /chord/<chord_name>` - Chord diagram SVG
- `GET /login` - User authentication
- `GET /register` - User registration

### Protected Endpoints
- `GET /` - Song library dashboard
- `GET /song/<id>` - View song details
- `POST /song/<id>/edit` - Edit song
- `GET /practice/chord-changes` - Practice interface
- `GET /admin` - Admin dashboard (admin only)

## 🐛 Troubleshooting

### Common Issues

**Database is empty after rebuild**:
- Ensure `.env` file exists with correct `DATABASE_URL`
- Check volume mount in `docker-compose.yml`
- Verify `./instance/guitar.db` exists on host

**Audio not working**:
- Check browser console for Web Audio API errors
- Ensure user interaction before audio (browser requirement)
- Try refreshing the page

**Chord diagrams not displaying**:
- Check for JavaScript errors in browser console
- Verify chord exists in database
- Try accessing chord directly: `/chord/C`

**Performance issues**:
- Check Docker resource allocation
- Monitor container logs: `docker-compose logs -f`
- Consider PostgreSQL for larger datasets

### Support Resources
- **Issues**: [GitHub Issues](https://github.com/yourusername/guitar-webapp/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/guitar-webapp/discussions)
- **Wiki**: [Project Wiki](https://github.com/yourusername/guitar-webapp/wiki)

## 📄 License

This project is released under [The Unlicense](LICENSE) - feel free to use it however you'd like!

## 🙏 Acknowledgments

- **Flask Community**: For the excellent web framework
- **Guitar Community**: For feedback and feature suggestions
- **Open Source**: Built on the shoulders of giants

---

**Happy practicing! 🎸🎵**
