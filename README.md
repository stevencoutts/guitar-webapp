# Guitar Practice Web App

A web application for managing guitar songs, practicing chord changes, and tracking progress.

## Features

- **Song Management**
  - Add, edit, and delete songs
  - Store chord progressions
  - Track practice history
  - Backup and restore functionality

- **One-Minute Chord Changes Practice**
  - Practice predefined chord pairs
  - Track scores and progress
  - Visual and audio metronome
  - Difficulty levels (Easy, Medium, Hard, Very Hard)

- **Backup and Restore**
  - Export all songs and practice data
  - Import data from backup files
  - Automatic backup before deletion

- **User Management**
  - User registration and login
  - Password security with requirements
  - Account deletion with confirmation
  - Session management

- **Admin Features**
  - User management
  - Password reset capability
  - User disable/enable functionality
  - Admin status management

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
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

4. Create a `.env` file in the project root with the following variables:
```env
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///instance/guitar.db
ADMIN_PASSWORD=your-secure-admin-password
```

5. Initialize the database:
```bash
python init_db.py
```

## Usage

1. Start the development server:
```bash
flask run
```

2. Access the application at `http://localhost:5001`

3. Default admin credentials:
   - Username: `admin`
   - Password: Value set in `ADMIN_PASSWORD` environment variable

4. To make a user an admin from the command line:
```bash
python make_admin.py username
```

## Project Structure

```
guitar-webapp/
├── app.py              # Main application file
├── init_db.py          # Database initialization
├── make_admin.py       # Admin user management script
├── requirements.txt    # Python dependencies
├── .env               # Environment variables
├── instance/          # Database and instance files
├── migrations/        # Database migrations
├── static/           # Static files (CSS, JS, images)
└── templates/        # HTML templates
```

## Development

- Uses Flask for the web framework
- SQLAlchemy for database ORM
- Flask-Login for user authentication
- Flask-WTF for form handling and CSRF protection
- Bootstrap 5 for styling
- Font Awesome for icons

## Security Features

- Password hashing using Werkzeug
- CSRF protection on all forms
- Secure session handling
- HTTP-only cookies
- HTTPS-only cookies in production
- Session timeout after 30 minutes
- Password requirements:
  - Minimum 8 characters
  - Must contain uppercase letters
  - Must contain lowercase letters
  - Must contain numbers

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under The Unlicense - see the LICENSE file for details.

The Unlicense is a template for disclaiming copyright monopoly interest in software you've written; in other words, it is a template for dedicating your software to the public domain. 