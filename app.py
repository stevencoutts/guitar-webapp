from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, session, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
import re
from datetime import datetime, timedelta
from flask_wtf.csrf import CSRFProtect
import json
import io
import logging
from logging.handlers import RotatingFileHandler
import humanize
from version import VERSION

from io import StringIO, BytesIO
from werkzeug.utils import secure_filename
import requests
from bs4 import BeautifulSoup

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Configure logging
if not app.debug:
    # Set up file handler
    file_handler = RotatingFileHandler('guitar_app.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Guitar app startup')

# Security configurations
if not os.environ.get('SECRET_KEY'):
    raise ValueError("No SECRET_KEY set for Flask application")
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

# Ensure the instance folder exists
os.makedirs('instance', exist_ok=True)

# Configure SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///instance/guitar.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'

# Development vs Production settings
if app.debug:
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes session timeout
else:
    app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to session cookie
    app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes session timeout

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
csrf = CSRFProtect(app)  # Initialize CSRF protection

# Add datetime filter
@app.template_filter('datetime')
def format_datetime(value):
    if value is None:
        return ""
    return value.strftime('%Y-%m-%d %H:%M')

# Add timeago filter
@app.template_filter('timeago')
def timeago_filter(date):
    return humanize.naturaltime(datetime.utcnow() - date)

# Password validation
def is_valid_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    return True

# Models
class User(UserMixin, db.Model):
    """User model for storing user information and authentication"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    disabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    songs = db.relationship('Song', backref='user', lazy=True)
    practice_records = db.relationship('PracticeRecord', backref='user', lazy=True)

    def set_password(self, password):
        """Hash and set user password"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verify user password"""
        return check_password_hash(self.password_hash, password)

class Song(db.Model):
    """Song model for storing song information and chord progressions"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    artist = db.Column(db.String(100))
    time_signature = db.Column(db.String(10), nullable=False)  # Format: "4/4"
    bpm = db.Column(db.Integer, nullable=False)  # Beats per minute
    capo = db.Column(db.String(10), default='None', nullable=False)  # Capo position
    chord_progression = db.Column(db.Text, nullable=False)
    strumming_pattern = db.Column(db.Text)
    notes = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class PracticeRecord(db.Model):
    """Practice record model for tracking practice sessions"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    chord_pair = db.Column(db.String(50), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

class ChordPair(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_chord = db.Column(db.String(10), nullable=False)
    second_chord = db.Column(db.String(10), nullable=False)
    difficulty = db.Column(db.Integer, default=1)  # 1: Easy, 2: Medium, 3: Hard
    description = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def display_name(self):
        return f"{self.first_chord}→{self.second_chord}"

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    return db.session.get(User, int(user_id))

def create_default_admin():
    with app.app_context():
        # Check if admin user exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', is_admin=True)
            admin.set_password('Password1')
            db.session.add(admin)
            db.session.commit()

def create_default_chord_pairs():
    common_pairs = [
        # Easy chord pairs
        {"first": "C", "second": "G", "difficulty": 1, "description": "Common in folk and pop music"},
        {"first": "C", "second": "Am", "difficulty": 1, "description": "Basic minor transition"},
        {"first": "G", "second": "Em", "difficulty": 1, "description": "Natural minor progression"},
        {"first": "Am", "second": "F", "difficulty": 1, "description": "Common minor to major transition"},
        {"first": "C", "second": "F", "difficulty": 1, "description": "Basic major chord movement"},
        
        # Medium difficulty pairs
        {"first": "C", "second": "Dm", "difficulty": 2, "description": "Major to minor transition"},
        {"first": "G", "second": "D", "difficulty": 2, "description": "Common in country music"},
        {"first": "Em", "second": "C", "difficulty": 2, "description": "Minor to major resolution"},
        {"first": "Am", "second": "Em", "difficulty": 2, "description": "Minor chord progression"},
        {"first": "F", "second": "G", "difficulty": 2, "description": "Common in pop music"},
        
        # Harder chord pairs
        {"first": "C", "second": "E", "difficulty": 3, "description": "Major third movement"},
        {"first": "G", "second": "Bm", "difficulty": 3, "description": "Major to minor third"},
        {"first": "Am", "second": "Dm", "difficulty": 3, "description": "Minor progression"},
        {"first": "F", "second": "Dm", "difficulty": 3, "description": "Major to minor transition"},
        {"first": "C", "second": "G7", "difficulty": 3, "description": "Dominant seventh resolution"}
    ]
    
    for pair in common_pairs:
        existing = ChordPair.query.filter_by(
            first_chord=pair["first"],
            second_chord=pair["second"]
        ).first()
        
        if not existing:
            new_pair = ChordPair(
                first_chord=pair["first"],
                second_chord=pair["second"],
                difficulty=pair["difficulty"],
                description=pair["description"]
            )
            db.session.add(new_pair)
    
    db.session.commit()

# Routes
@app.route('/')
def index():
    """Display the main dashboard"""
    if current_user.is_authenticated:
        songs = Song.query.filter_by(user_id=current_user.id).all()
        return render_template('index.html', songs=songs)
    return render_template('index.html', songs=None)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if user.disabled:
                flash('Your account has been disabled. Please contact an administrator.')
                return redirect(url_for('login'))
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password are required')
            return redirect(url_for('register'))
            
        if not is_valid_password(password):
            flash('Password must be at least 8 characters long and contain uppercase, lowercase, and numbers')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    """Handle user logout"""
    logout_user()
    return redirect(url_for('index'))

@app.route('/song/new', methods=['GET', 'POST'])
@login_required
def new_song():
    """Handle adding new songs"""
    if request.method == 'POST':
        title = request.form.get('title')
        artist = request.form.get('artist')
        time_signature = request.form.get('time_signature')
        bpm = request.form.get('bpm')
        capo = request.form.get('capo', 'None')  # Default to 'None' if not specified
        chord_progression = request.form.get('chord_progression')
        strumming_pattern = request.form.get('strumming_pattern')
        notes = request.form.get('notes', '')  # Get notes with empty string as default
        
        if not all([title, time_signature, bpm, chord_progression, strumming_pattern]):
            flash('All required fields must be filled out')
            return redirect(url_for('new_song'))
            
        # Basic input validation
        if len(title) > 100:
            flash('Title is too long')
            return redirect(url_for('new_song'))
            
        if not re.match(r'^\d+/\d+$', time_signature):
            flash('Invalid time signature format')
            return redirect(url_for('new_song'))
            
        try:
            bpm = int(bpm)
            if bpm < 20 or bpm > 300:
                flash('BPM must be between 20 and 300')
                return redirect(url_for('new_song'))
        except ValueError:
            flash('BPM must be a valid number')
            return redirect(url_for('new_song'))
        
        # Log the capo value for debugging
        app.logger.info(f"Creating song with capo: {capo}")
        
        song = Song(
            title=title,
            artist=artist,
            time_signature=time_signature,
            bpm=bpm,
            capo=capo,
            chord_progression=chord_progression,
            strumming_pattern=strumming_pattern,
            notes=notes,
            user_id=current_user.id
        )
        db.session.add(song)
        db.session.commit()
        flash('Song added successfully!')
        return redirect(url_for('index'))
    return render_template('new_song.html')

@app.route('/song/<int:song_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_song(song_id):
    """Handle editing existing songs"""
    song = db.session.get(Song, song_id)
    if not song or song.user_id != current_user.id:
        flash('Song not found or access denied')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        song.title = request.form.get('title')
        song.artist = request.form.get('artist')
        song.time_signature = request.form.get('time_signature')
        song.bpm = request.form.get('bpm')
        song.capo = request.form.get('capo', 'None')  # Get capo value, default to 'None'
        song.chord_progression = request.form.get('chord_progression')
        song.strumming_pattern = request.form.get('strumming_pattern')
        song.notes = request.form.get('notes')
        db.session.commit()
        flash('Song updated successfully!')
        return redirect(url_for('view_song', song_id=song.id))
    return render_template('edit_song.html', song=song)

@app.route('/song/<int:song_id>/delete', methods=['POST'])
@login_required
def delete_song(song_id):
    """Handle deleting songs"""
    song = db.session.get(Song, song_id)
    if not song or song.user_id != current_user.id:
        flash('Song not found', 'error')
        return redirect(url_for('index'))
    db.session.delete(song)
    db.session.commit()
    flash('Song deleted successfully', 'success')
    return redirect(url_for('index'))

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    """Handle user account management"""
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not current_password or not new_password or not confirm_password:
            flash('All fields are required')
            return redirect(url_for('account'))
            
        if not check_password_hash(current_user.password_hash, current_password):
            flash('Current password is incorrect')
            return redirect(url_for('account'))
            
        if new_password != confirm_password:
            flash('New passwords do not match')
            return redirect(url_for('account'))
            
        if not is_valid_password(new_password):
            flash('New password must be at least 8 characters long and contain uppercase, lowercase, and numbers')
            return redirect(url_for('account'))
            
        current_user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        flash('Password updated successfully!')
        return redirect(url_for('account'))
        
    return render_template('account.html')

@app.route('/account/delete', methods=['POST'])
@login_required
def delete_account():
    """Handle user account deletion"""
    password = request.form.get('password')
    
    if not password:
        flash('Password is required to delete account')
        return redirect(url_for('account'))
        
    if not check_password_hash(current_user.password_hash, password):
        flash('Incorrect password')
        return redirect(url_for('account'))
    
    try:
        # Delete all user's songs first
        Song.query.filter_by(user_id=current_user.id).delete()
        # Then delete the user
        db.session.delete(current_user)
        db.session.commit()
        logout_user()
        flash('Your account has been deleted successfully')
        return redirect(url_for('index'))
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while deleting your account')
        return redirect(url_for('account'))

@app.route('/song/<int:song_id>', methods=['GET'])
@login_required
def view_song(song_id):
    """Display detailed view of a song"""
    # Extend session lifetime when viewing song details
    session.permanent = True
    app.permanent_session_lifetime = timedelta(hours=4)  # 4 hours for song viewing
    
    song = db.session.get(Song, song_id)
    if not song or song.user_id != current_user.id:
        flash('Song not found', 'error')
        return redirect(url_for('index'))
    
    # Get all predefined chord pairs
    predefined_pairs = ChordPair.query.all()
    
    return render_template('view_song.html', song=song, predefined_pairs=predefined_pairs)

@app.route('/admin')
@login_required
def admin():
    """Admin dashboard for managing users and system settings"""
    if not current_user.is_admin:
        flash('You do not have permission to access the admin page.')
        return redirect(url_for('index'))
    
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/admin/user/<int:user_id>/toggle_admin', methods=['POST'])
@login_required
def toggle_admin(user_id):
    """Handle toggling admin status for users"""
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.')
        return redirect(url_for('index'))
    
    user = db.session.get(User, user_id)
    if user.id == current_user.id:
        flash('You cannot modify your own admin status.')
        return redirect(url_for('admin'))
    
    user.is_admin = not user.is_admin
    db.session.commit()
    
    status = "admin" if user.is_admin else "regular user"
    flash(f'User {user.username} is now a {status}.')
    return redirect(url_for('admin'))

@app.route('/admin/user/create', methods=['POST'])
@login_required
def create_user():
    """Handle creating new users"""
    if not current_user.is_admin:
        flash('You do not have permission to create users.', 'danger')
        return redirect(url_for('admin'))
    
    username = request.form.get('username')
    password = request.form.get('password')
    is_admin = 'is_admin' in request.form
    
    if not username or not password:
        flash('Username and password are required.', 'danger')
        return redirect(url_for('admin'))
    
    if not is_valid_password(password):
        flash('Password must be at least 8 characters long and contain uppercase, lowercase, and numbers.', 'danger')
        return redirect(url_for('admin'))
    
    if User.query.filter_by(username=username).first():
        flash('Username already exists.', 'danger')
        return redirect(url_for('admin'))
    
    new_user = User(
        username=username,
        password_hash=generate_password_hash(password),
        is_admin=is_admin,
        created_at=datetime.utcnow()
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    flash('User created successfully.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    """Handle deleting a user"""
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.')
        return redirect(url_for('index'))
    
    user = db.session.get(User, user_id)
    if user.id == current_user.id:
        flash('You cannot delete your own account.')
        return redirect(url_for('admin'))
    
    # Delete all user's songs first
    Song.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    
    flash(f'User {user.username} has been deleted.')
    return redirect(url_for('admin'))

@app.route('/admin/user/<int:user_id>/change_password', methods=['POST'])
@login_required
def change_user_password(user_id):
    """Handle changing a user's password"""
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.')
        return redirect(url_for('index'))
    
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found.')
        return redirect(url_for('admin'))
    
    new_password = request.form.get('new_password')
    if not new_password:
        flash('New password is required.')
        return redirect(url_for('admin'))
    
    user.set_password(new_password)
    db.session.commit()
    
    flash(f'Password changed for user {user.username}.')
    return redirect(url_for('admin'))

@app.route('/admin/user/<int:user_id>/toggle_disabled', methods=['POST'])
@login_required
def toggle_user_disabled(user_id):
    """Handle toggling a user's disabled status"""
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.')
        return redirect(url_for('index'))
    
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found.')
        return redirect(url_for('admin'))
    
    if user.id == current_user.id:
        flash('You cannot disable your own account.')
        return redirect(url_for('admin'))
    
    user.disabled = not user.disabled
    db.session.commit()
    
    status = 'disabled' if user.disabled else 'enabled'
    flash(f'User {user.username} has been {status}.')
    return redirect(url_for('admin'))

@app.route('/practice/chord-changes', methods=['GET', 'POST'])
@login_required
def chord_changes():
    """Handle chord changes practice interface"""
    if request.method == 'POST':
        score = request.form.get('score')
        if score:
            # Handle manual score entry
            chord_pair = request.form.get('chord_pair')
            if chord_pair:
                practice_record = PracticeRecord(
                    user_id=current_user.id,
                    chord_pair=chord_pair,
                    score=int(score),
                    date=datetime.utcnow()
                )
                db.session.add(practice_record)
                db.session.commit()
                flash('Practice record saved successfully!', 'success')
                return redirect(url_for('chord_changes'))
            
            # Handle timer-based practice submission
            chord_pairs = json.loads(request.form.get('chord_pairs', '[]'))
            for pair in chord_pairs:
                practice_record = PracticeRecord(
                    user_id=current_user.id,
                    chord_pair=pair,
                    score=int(score),
                    date=datetime.utcnow()
                )
                db.session.add(practice_record)
            db.session.commit()
            flash('Practice session saved successfully!', 'success')
            return redirect(url_for('chord_changes'))

    # Get practice records for the current user
    records = PracticeRecord.query.filter_by(user_id=current_user.id).order_by(PracticeRecord.date.desc()).all()
    
    # Get best scores for each chord pair
    best_scores = {}
    for record in records:
        if record.chord_pair not in best_scores or record.score > best_scores[record.chord_pair]:
            best_scores[record.chord_pair] = record.score

    # Get predefined chord pairs
    predefined_pairs = ChordPair.query.order_by(ChordPair.difficulty).all()

    return render_template('chord_changes.html', records=records, best_scores=best_scores, predefined_pairs=predefined_pairs)

@app.route('/backup', methods=['GET', 'POST'])
@login_required
def backup():
    """Handle backup and restore functionality"""
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'backup':
            # Get user's data for backup
            songs = Song.query.filter_by(user_id=current_user.id).all()
            practice_records = PracticeRecord.query.filter_by(user_id=current_user.id).all()
            
            # Get all users and their data (for admin only)
            users = []
            all_songs = []
            all_practice_records = []
            if current_user.is_admin:
                users = User.query.all()
                all_songs = Song.query.all()
                all_practice_records = PracticeRecord.query.all()
            
            # Prepare backup data
            backup_data = {
                'version': '1.0',
                'timestamp': datetime.utcnow().isoformat(),
                'user': {
                    'id': current_user.id,
                    'username': current_user.username,
                    'password_hash': current_user.password_hash,
                    'is_admin': current_user.is_admin,
                    'disabled': current_user.disabled,
                    'created_at': current_user.created_at.isoformat() if current_user.created_at else None
                },
                'songs': [{
                    'id': song.id,
                    'user_id': song.user_id,
                    'title': song.title,
                    'artist': song.artist,
                    'time_signature': song.time_signature,
                    'bpm': song.bpm,
                    'chord_progression': song.chord_progression,
                    'strumming_pattern': song.strumming_pattern,
                    'notes': song.notes,
                    'created_at': song.created_at.isoformat() if song.created_at else None,
                    'updated_at': song.updated_at.isoformat() if song.updated_at else None
                } for song in (all_songs if current_user.is_admin else songs)],
                'practice_records': [{
                    'id': record.id,
                    'user_id': record.user_id,
                    'chord_pair': record.chord_pair,
                    'score': record.score,
                    'date': record.date.isoformat() if record.date else None
                } for record in (all_practice_records if current_user.is_admin else practice_records)]
            }
            
            # Add all users data if admin
            if current_user.is_admin:
                backup_data['users'] = [{
                    'id': user.id,
                    'username': user.username,
                    'password_hash': user.password_hash,
                    'is_admin': user.is_admin,
                    'disabled': user.disabled,
                    'created_at': user.created_at.isoformat() if user.created_at else None
                } for user in users]
            
            # Create backup file
            json_str = json.dumps(backup_data, indent=2)
            backup_file = BytesIO(json_str.encode('utf-8'))
            
            return send_file(
                backup_file,
                mimetype='application/json',
                as_attachment=True,
                download_name=f'guitar_practice_backup_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.json'
            )
            
        elif action == 'restore':
            if 'backup_file' not in request.files:
                app.logger.error('No file selected for restore')
                flash('No file selected', 'error')
                return redirect(url_for('backup'))
            
            file = request.files['backup_file']
            if file.filename == '':
                app.logger.error('Empty filename for restore')
                flash('No file selected', 'error')
                return redirect(url_for('backup'))
            
            if file and file.filename.endswith('.json'):
                try:
                    backup_data = json.load(file)
                    app.logger.info(f"Current user: {current_user.username} (admin: {current_user.is_admin})")
                    app.logger.info(f"Loaded backup data: {json.dumps(backup_data, indent=2)}")
                    
                    # Validate backup data structure
                    if not isinstance(backup_data, dict) or 'version' not in backup_data:
                        app.logger.error('Invalid backup file format')
                        flash('Invalid backup file format', 'error')
                        return redirect(url_for('backup'))
                    
                    # Check if trying to restore user data without admin privileges
                    if 'users' in backup_data and not current_user.is_admin:
                        app.logger.error('Non-admin user attempting to restore user data')
                        flash('You do not have permission to restore user data', 'error')
                        return redirect(url_for('backup'))
                    
                    # Delete existing data
                    if current_user.is_admin:
                        app.logger.info("Deleting all existing data (admin mode)")
                        # Admin can restore all data
                        Song.query.delete()
                        PracticeRecord.query.delete()
                        User.query.filter(User.id != current_user.id).delete()
                    else:
                        app.logger.info(f"Deleting existing data for user {current_user.id}")
                        # Regular users can only restore their own data
                        Song.query.filter_by(user_id=current_user.id).delete()
                        PracticeRecord.query.filter_by(user_id=current_user.id).delete()
                    
                    # Create a mapping of old user IDs to new user IDs
                    user_id_mapping = {}
                    if current_user.is_admin and 'users' in backup_data:
                        app.logger.info(f"Restoring users: {backup_data['users']}")
                        for user_data in backup_data['users']:
                            if user_data.get('id') != current_user.id:  # Don't restore current admin user
                                user = User.query.get(user_data.get('id'))
                                if user:
                                    user.username = user_data.get('username')
                                    user.password_hash = user_data.get('password_hash')
                                    user.is_admin = user_data.get('is_admin', False)
                                    user.disabled = user_data.get('disabled', False)
                                else:
                                    user = User(
                                        id=user_data.get('id'),
                                        username=user_data.get('username'),
                                        password_hash=user_data.get('password_hash'),
                                        is_admin=user_data.get('is_admin', False),
                                        disabled=user_data.get('disabled', False)
                                    )
                                    db.session.add(user)
                                user_id_mapping[user_data.get('id')] = user.id
                    
                    # Restore songs
                    songs_to_restore = backup_data.get('songs', [])
                    app.logger.info(f"Found {len(songs_to_restore)} songs to restore")
                    for song_data in songs_to_restore:
                        # For admin, restore all songs. For regular users, only restore their own songs
                        if current_user.is_admin or song_data.get('user_id') == current_user.id:
                            # Map the user_id to the new user ID if it exists, or use current user's ID
                            user_id = song_data.get('user_id')
                            if user_id in user_id_mapping:
                                user_id = user_id_mapping[user_id]
                            else:
                                user_id = current_user.id  # Use current user's ID if no mapping exists
                            
                            try:
                                # Create new song without specifying ID to let database auto-generate it
                                song = Song(
                                    user_id=user_id,
                                    title=song_data.get('title'),
                                    artist=song_data.get('artist'),
                                    time_signature=song_data.get('time_signature'),
                                    bpm=song_data.get('bpm'),
                                    capo=song_data.get('capo', 'None'),
                                    chord_progression=song_data.get('chord_progression'),
                                    strumming_pattern=song_data.get('strumming_pattern'),
                                    notes=song_data.get('notes')
                                )
                                db.session.add(song)
                            except Exception as e:
                                app.logger.error(f"Error adding song {song_data.get('title')}: {str(e)}")
                                raise
                    
                    # Restore practice records
                    records_to_restore = backup_data.get('practice_records', [])
                    app.logger.info(f"Found {len(records_to_restore)} practice records to restore")
                    for record_data in records_to_restore:
                        if current_user.is_admin or record_data.get('user_id') == current_user.id:
                            # Map the user_id to the new user ID if it exists, or use current user's ID
                            user_id = record_data.get('user_id')
                            if user_id in user_id_mapping:
                                user_id = user_id_mapping[user_id]
                            else:
                                user_id = current_user.id  # Use current user's ID if no mapping exists
                            
                            try:
                                # Create new practice record without specifying ID
                                record = PracticeRecord(
                                    user_id=user_id,
                                    chord_pair=record_data.get('chord_pair'),
                                    score=record_data.get('score'),
                                    date=datetime.fromisoformat(record_data.get('date'))
                                )
                                db.session.add(record)
                            except Exception as e:
                                app.logger.error(f"Error adding practice record {record_data.get('chord_pair')}: {str(e)}")
                                raise
                    
                    try:
                        db.session.commit()
                        app.logger.info("Backup restored successfully!")
                        flash('Backup restored successfully!', 'success')
                        return redirect(url_for('index'))
                    except Exception as e:
                        db.session.rollback()
                        app.logger.error(f"Error during commit: {str(e)}")
                        raise
                except Exception as e:
                    db.session.rollback()
                    app.logger.error(f"Error restoring backup: {str(e)}")
                    flash(f'Error restoring backup: {str(e)}', 'error')
                    return redirect(url_for('backup'))
            else:
                app.logger.error('Invalid file format for restore')
                flash('Invalid file format. Please upload a JSON file.', 'error')
                return redirect(url_for('backup'))
    
    # Show backup page
    return render_template('backup.html')

@app.route('/chord_pair_history/<chord_pair>')
@login_required
def chord_pair_history(chord_pair):
    """Display practice history for a specific chord pair"""
    # Get all practice records for this chord pair, ordered by date
    records = PracticeRecord.query.filter_by(
        user_id=current_user.id,
        chord_pair=chord_pair
    ).order_by(PracticeRecord.date.desc()).all()
    
    return render_template('chord_pair_history.html', 
                         chord_pair=chord_pair,
                         records=records)

@app.route('/chord/<chord_name>')
def get_chord_diagram(chord_name):
    """Generate a basic chord diagram"""
    # Basic chord shapes (fret positions for each string in EADGBE order)
    # Each chord is defined as a list of tuples, one for each string from low E to high E
    # Each tuple contains (fret_number, symbol) where:
    # - fret_number: 0 for open string, 1-12 for fretted notes
    # - symbol: 'x' for muted string, or the finger number (1-4) for fretted notes
    # Example: 'C' chord [(0, 'x'), (1, 1), (0, 0), (2, 2), (3, 3), (0, 'x')]
    # means: x32010 (from low E to high E)
    # - Low E: muted (x)
    # - A: 3rd fret, finger 1
    # - D: 2nd fret, finger 0 (open)
    # - G: 0th fret, finger 2
    # - B: 1st fret, finger 3
    # - High E: muted (x)
    chord_shapes = {
        'C': [(0, 'x'), (3, 1), (2, 1), (0, 0), (1, 1), (0, 0)],  # x32010
        'G': [(3, 3), (2, 0), (0, 0), (0, 0), (0, 0), (3, 3)],  # 320003
        'D': [(2, 'x'), (2, 'x'), (0, 0), (2, 2), (3, 3), (2, 2)],  # xx0232
        'A': [(0, 'x'), (0, 0), (2, 2), (2, 2), (2, 2), (0, 0)],  # x02220
        'E': [(0, 0), (2, 2), (2, 2), (1, 1), (0, 0), (0, 0)],  # 022100
        'Am': [(0, 'x'), (0, 0), (2, 2), (2, 2), (1, 1), (0, 0)],  # x02210
        'Em': [(0, 0), (2, 2), (2, 2), (0, 0), (0, 0), (0, 0)],  # 022000
        'F': [(1, 1), (3, 3), (3, 3), (2, 2), (1, 1), (1, 1)],  # 133211
        'Dm': [(0, 'x'), (0, 'x'), (0, 0), (2, 2), (3, 3), (1, 1)],  # xx0231
        'G7': [(3, 3), (2, 2), (0, 0), (0, 0), (0, 0), (1, 1)],  # 320001
        'C7': [(0, 'x'), (3, 3), (2, 2), (3, 3), (1, 1), (0, 0)],  # x32310
        'A7': [(0, 'x'), (0, 0), (2, 2), (0, 0), (2, 2), (0, 0)],  # x02020
        'E7': [(0, 0), (2, 2), (0, 0), (1, 1), (0, 0), (0, 0)],  # 020100
        'B7': [(2, 2), (1, 1), (2, 2), (0, 0), (2, 2), (0, 'x')],  # 212020
        'Bm': [(2, 2), (2, 2), (4, 4), (4, 4), (3, 3), (2, 2)],  # 224432
        'Fmaj7': [(0, 'x'), (0, 'x'), (3, 3), (2, 2), (1, 1), (0, 0)],  # 133211
        'Cadd9': [(0, 'x'), (3, 3), (2, 2), (0, 0), (3, 3), (3, 3)],  # x32030
    }
    
    # SVG dimensions
    width = 150
    height = 200
    fret_height = 30
    string_spacing = 20
    left_margin = 25
    top_margin = 20
    
    # Start SVG content
    svg = f'''
    <svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">
        <style>
            .fret {{ stroke: #666; stroke-width: 1; }}
            .string {{ stroke: #666; stroke-width: 1; }}
            .dot {{ fill: #000; }}
            .open {{ fill: none; stroke: #000; stroke-width: 1; }}
            .x {{ font-family: Arial; font-size: 14px; }}
            .chord-name {{ font-family: Arial; font-size: 16px; }}
        </style>
    '''
    
    # Draw frets
    for i in range(5):
        y = top_margin + i * fret_height
        svg += f'<line x1="{left_margin}" y1="{y}" x2="{left_margin + 5 * string_spacing}" y2="{y}" class="fret"/>'
    
    # Draw strings
    for i in range(6):
        x = left_margin + i * string_spacing  # Draw from low E to high E
        svg += f'<line x1="{x}" y1="{top_margin}" x2="{x}" y2="{top_margin + 4 * fret_height}" class="string"/>'
    
    # Draw dots for the chord if we know it
    if chord_name in chord_shapes:
        for string_idx, (fret, symbol) in enumerate(chord_shapes[chord_name]):
            x = left_margin + string_idx * string_spacing  # Draw from low E to high E
            if symbol == 'x':
                # X mark for muted string
                svg += f'<text x="{x}" y="{top_margin - 5}" text-anchor="middle" class="x">×</text>'
            elif fret == 0:
                # Open string
                svg += f'<circle cx="{x}" cy="{top_margin - 10}" r="4" class="open"/>'
            else:
                # Fretted note
                y = top_margin + (fret - 0.5) * fret_height
                svg += f'<circle cx="{x}" cy="{y}" r="6" class="dot"/>'
    
    # Close SVG
    svg += '</svg>'
    
    # Return SVG as response
    return Response(svg, mimetype='image/svg+xml')

# Make version available to all templates
@app.context_processor
def inject_version():
    """Inject version number into all templates"""
    return dict(version=VERSION)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_admin()
        create_default_chord_pairs()
    app.run(host='0.0.0.0', port=5001, debug=True) 