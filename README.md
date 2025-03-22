# Guitar Practice Web App

A Flask-based web application for guitarists to manage their songs, practice chord changes, and track their progress.

## Features

### Song Management
- Add, edit, and delete songs
- Store chord progressions, strumming patterns, and notes
- Track BPM and time signatures
- Artist attribution for songs
- Beautiful card-based song list view
- Metronome feature for practice

### One-Minute Chord Changes Practice
- Practice changing between chord pairs
- Track your scores and progress
- Predefined chord pairs with difficulty levels
- Customizable practice sessions
- Visual feedback during practice
- Score tracking and history

### Backup and Restore
- Export all your data to JSON
- Import data from previous backups
- Includes songs, practice records, and settings
- Timestamped backup files
- Secure data handling

### User Management
- User registration and login
- Password security with hashing
- Admin user functionality
- Session management
- Responsive design for all devices

### Admin Features
- User management interface
- View all users and their data
- Promote users to admin status
- Delete user accounts
- CLI tool for admin management

## Installation

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
SECRET_KEY=your-secret-key
DATABASE_URL=sqlite:///instance/guitar.db
```

5. Initialize the database:
```bash
python init_db.py
```

## Usage

1. Start the development server:
```bash
python app.py
```

2. Open your browser and navigate to `http://localhost:5000`

3. Register a new account or log in

4. Start adding your songs and practicing!

### Making a User Admin

To make a user an admin from the command line:
```bash
python make_admin.py username
```

## Project Structure

```
guitar-webapp/
├── app.py              # Main application file
├── init_db.py          # Database initialization
├── make_admin.py       # Admin user management
├── requirements.txt    # Python dependencies
├── static/            # Static files (CSS, JS)
├── templates/         # HTML templates
└── instance/          # Database and instance files
```

## Development

### Adding New Features
1. Create a new branch for your feature
2. Make your changes
3. Test thoroughly
4. Submit a pull request

### Database Migrations
The application uses SQLAlchemy for database management. The database schema is automatically created when you run `init_db.py`.

## Security Features

- Password hashing with Werkzeug
- CSRF protection
- Secure session handling
- Input validation
- SQL injection prevention
- XSS protection

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 