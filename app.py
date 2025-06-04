from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, session, Response, abort
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
import sys

from io import StringIO, BytesIO
from werkzeug.utils import secure_filename
import requests
from bs4 import BeautifulSoup

# Define the Config class
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess' # Provide a fallback for development
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = 'uploads'

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
# Load configuration from the Config class
app.config.from_object(Config)

# Set debug mode to False
# app.debug = True # Commenting out or removing debug = True
app.debug = False

# Define application version (if it exists here)
# Assuming version is defined somewhere, let's add a placeholder if not found or update if found
app.config['VERSION'] = '1.1' # Set the version number

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

# Configure SQLite database URI
basedir = os.path.abspath(os.path.dirname(__file__))
database_url = os.environ.get('DATABASE_URL')

if database_url and database_url.startswith('sqlite:///file:'):
    # Assuming the URI is already in the correct format with uri=true
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
elif database_url and database_url.startswith('sqlite:///'):
     # If DATABASE_URL is set and is a relative SQLite path, convert to absolute
     # Remove the 'sqlite:///' prefix to get the relative path part
     relative_db_path = database_url[len('sqlite:///'):]
     # Construct the absolute path and format as SQLite URI with uri=true
     absolute_db_path = os.path.join(basedir, relative_db_path)
     app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///file:{absolute_db_path}?uri=true'
else:
     # Otherwise, use the DATABASE_URL as is, or the default absolute path
     default_db_path = os.path.join(basedir, 'instance', 'guitar.db')
     app.config['SQLALCHEMY_DATABASE_URI'] = database_url or f'sqlite:///file:{default_db_path}?uri=true'

# Ensure the instance folder exists for SQLite database if a relative path is used
# Check if the database URI is a relative path that requires the 'instance' folder
db_uri = app.config.get('SQLALCHEMY_DATABASE_URI')
if db_uri and 'sqlite:///file:' in db_uri:
    # Extract the path from the URI (handle uri=true format)
    db_path = db_uri.replace('sqlite:///file:', '').split('?')[0]
    # If the path is relative and contains 'instance/', ensure the folder exists
    if 'instance/' in db_path and not os.path.isabs(db_path):
        instance_dir = os.path.join(basedir, 'instance')
        os.makedirs(instance_dir, exist_ok=True)

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
    strumming_pattern = db.Column(db.Text) # Stores JSON string of 16th note strumming pattern (e.g., '["D", "U", "-", "X", ...]')
    notes = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    selected_variants = db.Column(db.Text, default='{}', nullable=False) # Stores JSON string of selected variants {chord_name: variant_name}
    display_beats = db.Column(db.Integer, default=4, nullable=False) # Number of beats to display in the editor (4 or 8)

    @property
    def strumming_pattern_list(self):
        """Deserialize the JSON strumming pattern into a list."""
        if self.strumming_pattern:
            try:
                pattern_data = json.loads(self.strumming_pattern)
                
                # Handle new triplet format with subdivisions
                if isinstance(pattern_data, dict) and 'pattern' in pattern_data:
                    return pattern_data['pattern']
                # Handle legacy format (just array)
                elif isinstance(pattern_data, list):
                    return pattern_data
                else:
                    return []
            except json.JSONDecodeError:
                # Log error and return empty list for invalid JSON
                if app.logger:
                    app.logger.error(f"Invalid JSON in strumming_pattern for song {self.id}: {self.strumming_pattern}")
                return []
        return []

    @strumming_pattern_list.setter
    def strumming_pattern_list(self, value):
        """Serialize pattern data into the JSON strumming pattern string."""
        if isinstance(value, list):
            # Legacy format - just the pattern array
            self.strumming_pattern = json.dumps(value)
        elif isinstance(value, dict):
            # New format - includes subdivisions
            self.strumming_pattern = json.dumps(value)
        elif value is None or value == '':
            self.strumming_pattern = None
        else:
            # Log error for unexpected type
            if app.logger:
                 app.logger.error(f"Attempted to set strumming_pattern_list with unexpected type for song {self.id}: {type(value)}")
            self.strumming_pattern = None

    @property
    def strumming_pattern_subdivisions(self):
        """Get subdivision data for triplet support."""
        if self.strumming_pattern:
            try:
                pattern_data = json.loads(self.strumming_pattern)
                if isinstance(pattern_data, dict) and 'subdivisions' in pattern_data:
                    return pattern_data['subdivisions']
            except json.JSONDecodeError:
                pass
        return None

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

class ChordShape(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)
    variant = db.Column(db.String(50), nullable=True) # e.g. 'open', 'E shape barre'
    shape = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    start_fret = db.Column(db.Integer, default=0, nullable=False)  # 0 = nut

    __table_args__ = (db.UniqueConstraint('name', 'variant', name='_chordshape_name_variant_uc'),)

    def get_shape(self):
        try:
            return json.loads(self.shape)
        except Exception:
            return None

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

# Add a simple SiteOption model for global settings
class SiteOption(db.Model):
    __tablename__ = 'site_option'
    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.String(256), nullable=False)

    @staticmethod
    def get(key, default=None):
        opt = SiteOption.query.filter_by(key=key).first()
        return opt.value if opt else default

    @staticmethod
    def set(key, value):
        opt = SiteOption.query.filter_by(key=key).first()
        if not opt:
            opt = SiteOption(key=key, value=value)
            db.session.add(opt)
        else:
            opt.value = value
        db.session.commit()

# Routes
@app.route('/')
def index():
    """Display the main dashboard"""
    registration_enabled = SiteOption.get('registration_enabled', '1') == '1'
    if current_user.is_authenticated:
        songs = Song.query.filter_by(user_id=current_user.id).all()
        return render_template('index.html', songs=songs, registration_enabled=registration_enabled)
    return render_template('index.html', songs=None, registration_enabled=registration_enabled)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    registration_enabled = SiteOption.get('registration_enabled', '1') == '1'
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
    return render_template('login.html', registration_enabled=registration_enabled)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration"""
    # Check if registration is disabled
    if SiteOption.get('registration_enabled', '1') != '1':
        flash('New user registration is currently disabled by the administrator.', 'danger')
        return redirect(url_for('login'))
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
        
        # Handle strumming pattern JSON data
        strumming_pattern_json = request.form.get('strumming_pattern')
        strumming_pattern_to_save = None
        if strumming_pattern_json:
            try:
                # Validate and deserialize the JSON
                strumming_pattern_data = json.loads(strumming_pattern_json)
                
                # Handle new triplet format with subdivisions
                if isinstance(strumming_pattern_data, dict) and 'pattern' in strumming_pattern_data:
                    pattern = strumming_pattern_data['pattern']
                    subdivisions = strumming_pattern_data.get('subdivisions', [])
                    
                    if isinstance(pattern, list) and all(isinstance(item, str) for item in pattern):
                        # Store the complete data structure
                        strumming_pattern_to_save = strumming_pattern_data
                    else:
                        flash('Invalid strumming pattern data format.', 'danger')
                        # Optionally, log the invalid data
                        if app.logger:
                            app.logger.error(f"Invalid pattern array in strumming_pattern JSON for new song: {strumming_pattern_json}")
                # Handle legacy format (just array)
                elif isinstance(strumming_pattern_data, list) and all(isinstance(item, str) for item in strumming_pattern_data):
                    # Use the setter to handle serialization to text
                    strumming_pattern_to_save = strumming_pattern_data
                else:
                    flash('Invalid strumming pattern data format.', 'danger')
                    # Optionally, log the invalid data
                    if app.logger:
                        app.logger.error(f"Received invalid strumming_pattern JSON for new song: {strumming_pattern_json}")
            except json.JSONDecodeError:
                flash('Invalid JSON data for strumming pattern.', 'danger')
                # Optionally, log the error
                if app.logger:
                    app.logger.error(f"Error decoding strumming_pattern JSON for new song: {strumming_pattern_json}")
        # If no strumming pattern is provided or it's empty, strumming_pattern_to_save remains None

        notes = request.form.get('notes', '')  # Get notes with empty string as default
        display_beats = int(request.form.get('display_beats', 4)) # Get selected display beats, default to 4
        
        # app.logger.info(f"New song form submission - chord_progression: {chord_progression!r}") # Log received chord progression

        if not all([title, time_signature, bpm, chord_progression]): # Strumming pattern is now optional
            flash('Title, Time Signature, BPM, and Chord Progression are required fields')
            return redirect(url_for('new_song'))
            
        # Basic input validation
        if len(title) > 100:
            flash('Title is too long')
            return redirect(url_for('new_song'))
            
        if not re.match(r'^\d+/\d+$', time_signature):
            flash('Invalid time signature format. Use format like 4/4, 3/4, 4/3, 7/5, etc.')
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
        # app.logger.info(f"Creating song with capo: {capo}")
        
        song = Song(
            title=title,
            artist=artist,
            time_signature=time_signature,
            bpm=bpm,
            capo=capo,
            chord_progression=chord_progression,
            strumming_pattern_list=strumming_pattern_to_save, # Use the setter
            notes=notes,
            user_id=current_user.id,
            display_beats=display_beats
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
        abort(403) # Forbidden
    if request.method == 'POST':
        song.title = request.form['title']
        song.artist = request.form.get('artist')
        song.time_signature = request.form.get('time_signature')
        song.bpm = request.form.get('bpm')
        song.capo = request.form.get('capo', 'None')  # Get capo value, default to 'None'
        song.chord_progression = request.form.get('chord_progression')

        # Handle strumming pattern JSON data
        strumming_pattern_json = request.form.get('strumming_pattern')
        if strumming_pattern_json:
            try:
                # Validate and deserialize the JSON
                strumming_pattern_data = json.loads(strumming_pattern_json)
                # Handle new triplet format with subdivisions
                if isinstance(strumming_pattern_data, dict) and 'pattern' in strumming_pattern_data:
                    pattern = strumming_pattern_data['pattern']
                    subdivisions = strumming_pattern_data.get('subdivisions', [])
                    
                    if isinstance(pattern, list) and all(isinstance(item, str) for item in pattern):
                        # Store the complete data structure
                        song.strumming_pattern_list = strumming_pattern_data
                    else:
                        flash('Invalid strumming pattern data format.', 'danger')
                        if app.logger:
                            app.logger.error(f"Invalid pattern array in strumming_pattern JSON for song {song_id}: {strumming_pattern_json}")
                        
                # Handle legacy format (just array)
                elif isinstance(strumming_pattern_data, list) and all(isinstance(item, str) for item in strumming_pattern_data):
                    # Use the setter to handle serialization to text
                    song.strumming_pattern_list = strumming_pattern_data
                else:
                    flash('Invalid strumming pattern data format.', 'danger')
                    # Optionally, log the invalid data
                    if app.logger:
                        app.logger.error(f"Received invalid strumming_pattern JSON for song {song_id}: {strumming_pattern_json}")

            except json.JSONDecodeError:
                flash('Invalid JSON data for strumming pattern.', 'danger')
                 # Optionally, log the error
                if app.logger:
                     app.logger.error(f"Error decoding strumming_pattern JSON for song {song_id}: {strumming_pattern_json}")
        # If no strumming pattern is provided or it's empty, preserve the existing pattern
        # This prevents accidental clearing of the pattern when other fields are updated

        song.notes = request.form.get('notes')
        song.display_beats = int(request.form.get('display_beats', 4)) # Update display beats, default to 4

        # app.logger.info(f"Edit song form submission - chord_progression: {song.chord_progression!r}") # Log received chord progression

        db.session.commit()
        flash('Song updated successfully!')
        return redirect(url_for('view_song', song_id=song.id))
    
    # Add print statement to check strumming_pattern value before rendering template

    return render_template('edit_song.html', song=song, initial_display_beats=song.display_beats)

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
    app.permanent_session_lifetime = timedelta(hours=4)
    
    song = db.session.get(Song, song_id)
    if not song or song.user_id != current_user.id:
        flash('Song not found', 'error')
        return redirect(url_for('index'))
    
    # Get all predefined chord pairs (still needed for practice records section)
    predefined_pairs = ChordPair.query.all()
    
    # Extract potential chord names from the song progression by splitting and validating
    ordered_unique_chords = []
    if song.chord_progression:
        # Split the progression by spaces or other delimiters if necessary (simple split for now)
        potential_chords = song.chord_progression.split()
        
        # Define a simpler regex to validate individual chord words
        # This regex checks if a word looks like a chord (starts with A-G, can have accidentals, extensions, and an optional slash part)
        chord_regex = re.compile(r'^[A-G][b#]?[a-zA-Z0-9+\-/#]*$')
        
        for word in potential_chords:
            # Clean up the word (remove leading/trailing whitespace or punctuation if necessary)
            cleaned_word = word.strip().replace(',', '').replace(';', '') # Example cleaning
            
            if cleaned_word:
                # Check if the cleaned word matches the chord regex pattern
                if chord_regex.match(cleaned_word):
                    chord_name = cleaned_word
                    if chord_name not in ordered_unique_chords:
                        ordered_unique_chords.append(chord_name)

    # Initialize chord_shapes_dict with all unique chords found in the progression
    chord_shapes_dict = {chord_name: [] for chord_name in ordered_unique_chords}

    if ordered_unique_chords:
        # Get all shapes that match any of the unique chord names FROM THE DATABASE
        all_shapes_from_db = ChordShape.query.filter(ChordShape.name.in_(ordered_unique_chords)).order_by(ChordShape.name, ChordShape.variant).all()
        # Organize database shapes by chord name in the dictionary
        for shape in all_shapes_from_db:
            # Initialize list for this chord name if it doesn't exist yet
            chord_shapes_dict[shape.name].append(shape)

    # Define hardcoded shapes locally for augmentation logic
    # Note: These are used as fallbacks if no matching shape is found in the database
    hardcoded_shapes_data = {
        'C': {'shape': [(0, 'x'), (3, 3), (2, 2), (0, 0), (1, 1), (0, 0)], 'start_fret': 0, 'variant': None},
        'G': {'shape': [(3, 1), (2, 2), (0, 0), (0, 0), (0, 0), (3, 3)], 'start_fret': 0, 'variant': None},
        'D': {'shape': [(0, 'x'), (0, 'x'), (0, 0), (2, 2), (3, 1), (2, 3)], 'start_fret': 0, 'variant': None},
        'A': {'shape': [(0, 'x'), (0, 0), (2, 1), (2, 2), (2, 3), (0, 0)], 'start_fret': 0, 'variant': None},
        'E': {'shape': [(0, 0), (2, 2), (2, 2), (1, 1), (0, 0), (0, 0)], 'start_fret': 0, 'variant': None},
        'Am': {'shape': [(0, 'x'), (0, 0), (2, 2), (2, 3), (1, 1), (0, 0)], 'start_fret': 0, 'variant': None},
        'Em': {'shape': [(0, 0), (2, 2), (2, 3), (0, 0), (0, 0), (0, 0)], 'start_fret': 0, 'variant': None},
        'F': {'shape': [(1, 1), (3, 4), (3, 3), (2, 2), (1, 1), (1, 1)], 'start_fret': 1, 'variant': None},
        'Dm': {'shape': [(0, 'x'), (0, 'x'), (0, 0), (2, 2), (3, 3), (1, 1)], 'start_fret': 0, 'variant': None},
        'G7': {'shape': [(3, 3), (2, 2), (0, 0), (0, 0), (0, 0), (1, 1)], 'start_fret': 0, 'variant': None},
        'C7': {'shape': [(0, 'x'), (3, 3), (2, 2), (3, 3), (1, 1), (0, 0)], 'start_fret': 0, 'variant': None},
        'A7': {'shape': [(0, 'x'), (0, 0), (2, 2), (0, 0), (2, 2), (0, 0)], 'start_fret': 0, 'variant': None},
        'E7': {'shape': [(0, 0), (2, 2), (0, 0), (1, 1), (0, 0), (0, 0)], 'start_fret': 0, 'variant': None},
        'B7': {'shape': [(2, 2), (1, 1), (2, 2), (0, 0), (2, 2), (0, 'x')], 'start_fret': 0, 'variant': None},
        'Fmaj7': {'shape': [(0, 'x'), (0, 'x'), (3, 4), (2, 2), (1, 1), (0, 0)], 'start_fret': 0, 'variant': None},
        'Bm': {'shape': [(2, 2), (2, 2), (4, 4), (4, 4), (3, 3), (2, 2)], 'start_fret': 0, 'variant': None},
        'Cadd9': {'shape': [(0, 'x'), (3, 2), (2, 1), (0, 0), (3, 3), (3, 4)], 'start_fret': 0, 'variant': None},
        'D7': {'shape': [(0, 'x'), (0, 'x'), (0, 0), (2, 1), (1, 2), (2, 3)], 'start_fret': 0, 'variant': None}, # Added D7 shape
    }

    # For each unique chord, check if a hardcoded default exists and add it if no database default exists
    for chord_name in ordered_unique_chords:
        # Try the full chord name first (e.g., 'Fmaj7/C')
        hardcoded_shape = hardcoded_shapes_data.get(chord_name)

        # If no hardcoded shape for the full name, and it's a slash chord, try the base chord name (e.g., 'Fmaj7')
        if not hardcoded_shape and '/' in chord_name:
            base_chord_name = chord_name.split('/')[0]
            hardcoded_shape = hardcoded_shapes_data.get(base_chord_name)
            # If a base chord shape is found, we will use it but still associate it with the original slash chord name
            # if hardcoded_shape:
                 # app.logger.info(f"Using hardcoded shape for base chord {base_chord_name} for slash chord {chord_name}")

        if hardcoded_shape:
            # Get the list of database shapes for this chord name
            db_shapes_for_chord = chord_shapes_dict.get(chord_name, [])
            # Check if any of the database shapes are considered default (variant is None or empty string)
            db_default_exists = any(shape.variant is None or shape.variant == '' for shape in db_shapes_for_chord)
            # If no database default exists, add the hardcoded shape as a default option
            if not db_default_exists:
                # Represent hardcoded shape similar to a DB object for template consistency
                class HardcodedShapeDummy:
                    def __init__(self, name, shape, start_fret, variant):
                        self.name = name
                        # Store shape as JSON string internally for consistency with DB model
                        self.shape = json.dumps(shape)
                        self.start_fret = start_fret
                        self.variant = variant

                    def get_shape(self):
                        # Deserialize the shape JSON string when requested
                        return json.loads(self.shape)

                dummy_shape = HardcodedShapeDummy(chord_name, hardcoded_shape['shape'], hardcoded_shape['start_fret'], hardcoded_shape['variant'])
                chord_shapes_dict[chord_name].append(dummy_shape)

    # Sort the shapes for each chord name to ensure consistent dropdown order (e.g., default first)
    for chord_name in chord_shapes_dict:
        chord_shapes_dict[chord_name].sort(key=lambda shape: (shape.variant is not None, shape.variant if shape.variant is not None else '')) # Sorts None/\'\' first

    # Determine the initially selected shape for each chord based on saved variants or default logic
    initial_shapes_dict = {}
    # Load selected variants, defaulting to an empty dictionary if the field is None or invalid JSON
    selected_variants_dict = json.loads(song.selected_variants or '{}')

    for chord_name in ordered_unique_chords:
        shapes = chord_shapes_dict.get(chord_name, [])
        initial_shape = None
        current_variant = selected_variants_dict.get(chord_name)

        # New logic: If no shapes were found (neither DB nor hardcoded default), try getting a hardcoded shape for the base name if it's a slash chord.
        if not shapes and '/' in chord_name:
             base_chord_name = chord_name.split('/')[0]
             # Use the get_chord_shape utility to retrieve the hardcoded shape (which now handles the HardcodedShapeDummy wrapper)
             base_shape_dummy = get_chord_shape(base_chord_name)
             if base_shape_dummy:
                 # If a base shape is found, add it as the only option for this slash chord and set it as the initial shape.
                 # app.logger.info(f"Adding fallback hardcoded shape for {base_chord_name} to {chord_name}")
                 chord_shapes_dict[chord_name] = [base_shape_dummy]
                 shapes = chord_shapes_dict[chord_name] # Update shapes list for the following logic
                 # We don't explicitly set initial_shape here, the logic below will pick it up as the first shape

        if shapes:
            # Prioritize the saved variant if it exists in the available shapes
            if current_variant is not None and current_variant != '':
                found_saved_variant = next((s for s in shapes if s.variant == current_variant), None)
                if found_saved_variant:
                    initial_shape = found_saved_variant

            # If no saved variant found or matched, try finding the explicit default (variant is None)
            if initial_shape is None:
                found_none_variant = next((s for s in shapes if s.variant is None), None)
                if found_none_variant:
                    initial_shape = found_none_variant

            # If still no shape found, try finding the empty string variant as default
            if initial_shape is None and current_variant == '': # Only check empty string if the selected variant is empty string (default) or none was saved
                found_empty_variant = next((s for s in shapes if s.variant == ''), None)
                if found_empty_variant:
                    initial_shape = found_empty_variant

            # If after all attempts, initial_shape is still None, use the very first shape as a fallback
            # This handles cases where a saved variant no longer exists, or the default logic above didn't find a match
            if initial_shape is None and shapes:
                initial_shape = shapes[0] # Use the first available shape

        # Store the determined initial shape for this chord name
        initial_shapes_dict[chord_name] = initial_shape

    # Generate SVG for the initially selected shape of each chord
    initial_diagram_svgs = {}
    for chord_name, initial_shape in initial_shapes_dict.items():
        if initial_shape:
            chord_shape = initial_shape.get_shape()
            start_fret = int(initial_shape.start_fret)

            # SVG dimensions (copying from get_chord_diagram)
            width = 220
            height = 220
            fret_height = 30
            string_spacing = 20
            left_margin = 40
            top_margin = 20

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
                x = left_margin + i * string_spacing
                svg += f'<line x1="{x}" y1="{top_margin}" x2="{x}" y2="{top_margin + 4 * fret_height}" class="string"/>'
            # Draw starting fret number label (e.g., '5fr') to the left of the first fret, inline with the second fret line
            if start_fret > 0:
                # Position the label inline with the second horizontal line (first fret line)
                # The second horizontal line is at y = top_margin + 1 * fret_height
                y_label = top_margin + fret_height # Target the vertical position of the first fret line
                label = f'{start_fret}fr'
                # Adjusted x position and text-anchor for the label
                svg += f'<text x="{left_margin - 15}" y="{y_label + fret_height/2}" font-size="14" fill="#333" text-anchor="end" dominant-baseline="middle">{label}</text>'

            # Draw dots and finger numbering in a single pass
            if chord_shape:
                for string_idx, (fret, symbol) in enumerate(chord_shape):
                    x = left_margin + string_idx * string_spacing
                    if symbol == 'x':
                        # Draw 'x' for muted strings
                        svg += f'<text x="{x}" y="{top_margin - 10}" text-anchor="middle" class="x">×</text>'
                    elif fret == 0:
                        # Draw open circle for open strings
                        svg += f'<circle cx="{x}" cy="{top_margin - 15}" r="4" class="open"/>'
                    elif isinstance(fret, int) and fret > 0:
                        # Draw dot for fretted notes
                        y = top_margin + (fret - 0.5) * fret_height
                        svg += f'<circle cx="{x}" cy="{y}" r="6" class="dot"/>'
                        # Add finger numbering inside the dot if the symbol is an integer finger number > 0
                        if isinstance(symbol, int) and symbol > 0:
                            # Position text at the center of the dot, adjusted slightly upwards
                            svg += f'<text x="{x}" y="{y + 2}" text-anchor="middle" font-size="12" fill="#fff" alignment-baseline="middle">{symbol}</text>'

            svg += '</svg>'

            # Store the generated SVG string
            initial_diagram_svgs[chord_name] = svg.strip()
        else:
            # If no shape was found, generate a fallback SVG directly with improved styling for readability
            # Increased width and centered text
            initial_diagram_svgs[chord_name] = '<svg width="400" height="100" xmlns="http://www.w3.org/2000/svg"><text x="50%" y="50%" font-size="14" fill="#333" text-anchor="middle" dominant-baseline="middle">Please add chord shape</text></svg>'

    # Pass the initial_shapes_dict and initial_diagram_svgs to the template
    # app.logger.info(f"Rendering view_song template for song {song_id} - strumming_pattern: {song.strumming_pattern!r}") # Log strumming pattern before rendering

    return render_template('view_song.html', 
                           song=song, 
                           predefined_pairs=predefined_pairs, 
                           chord_shapes_dict=chord_shapes_dict,
                           ordered_unique_chords=ordered_unique_chords,
                           initial_shapes_dict=initial_shapes_dict,
                           selected_variants=selected_variants_dict,
                           initial_diagram_svgs=initial_diagram_svgs)

@app.route('/admin')
@login_required
def admin():
    """Admin dashboard for managing users and system settings"""
    if not current_user.is_admin:
        flash('You do not have permission to access the admin page.')
        return redirect(url_for('index'))
    users = User.query.all()
    registration_enabled = SiteOption.get('registration_enabled', '1') == '1'
    return render_template('admin.html', users=users, registration_enabled=registration_enabled)

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

@app.route('/song/<int:song_id>/save_variant', methods=['POST'])
@login_required
def save_selected_variant(song_id):
    """Save the selected variant for a chord in a song"""
    song = db.session.get(Song, song_id)
    if not song or song.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Song not found or access denied'}), 404

    data = request.get_json()
    chord_name = data.get('chord_name')
    variant = data.get('variant') # The selected variant name (string) or None for default

    if not chord_name:
        return jsonify({'success': False, 'message': 'Chord name is required'}), 400

    try:
        # Load existing selected variants
        # Handle cases where selected_variants might be None or invalid JSON initially
        selected_variants = json.loads(song.selected_variants or '{}')
    except json.JSONDecodeError:
        # If still invalid after handling None, log error and start fresh
        app.logger.error(f"Invalid JSON in selected_variants for song {song_id}: {song.selected_variants}")
        selected_variants = {}

    # Update the selected variant for the given chord name
    # Store None/default variant as empty string in JSON for consistency
    selected_variants[chord_name] = variant if variant is not None else ''

    # Save the updated JSON back to the database
    try:
        song.selected_variants = json.dumps(selected_variants)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Variant saved successfully'})
    except Exception as e:
        db.session.rollback()
        # Ensure logger is available
        if app.logger:
            app.logger.error(f"Error saving selected variant for song {song_id}, chord {chord_name}: {e}")
        return jsonify({'success': False, 'message': f'Error saving variant: {e}'}), 500

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

    # Sorting logic for unique chord pairs
    sort = request.args.get('sort', 'date')
    order = request.args.get('order', 'desc')
    # Get all records for the user
    all_records = PracticeRecord.query.filter_by(user_id=current_user.id).all()
    # Build a dict: chord_pair -> latest record
    latest_records = {}
    best_scores = {}
    for record in all_records:
        cp = record.chord_pair
        if cp not in latest_records or record.date > latest_records[cp].date:
            latest_records[cp] = record
        if cp not in best_scores or record.score > best_scores[cp]:
            best_scores[cp] = record.score
    # Convert to list for sorting
    unique_records = list(latest_records.values())
    if sort == 'chord_pair':
        unique_records.sort(key=lambda r: r.chord_pair, reverse=(order=='desc'))
    else:  # sort by date
        unique_records.sort(key=lambda r: r.date, reverse=(order=='desc'))

    # Get predefined chord pairs
    predefined_pairs = ChordPair.query.order_by(ChordPair.difficulty).all()

    return render_template('chord_changes.html', records=unique_records, best_scores=best_scores, predefined_pairs=predefined_pairs, sort=sort, order=order)

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
            
            # Get all chord shapes
            chord_shapes = ChordShape.query.all()
            
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
                    'capo': song.capo,
                    'chord_progression': song.chord_progression,
                    'strumming_pattern': song.strumming_pattern,
                    'notes': song.notes,
                    'created_at': song.created_at.isoformat() if song.created_at else None,
                    'updated_at': song.updated_at.isoformat() if song.updated_at else None,
                    'selected_variants': song.selected_variants,
                    'display_beats': song.display_beats
                } for song in (all_songs if current_user.is_admin else songs)],
                'practice_records': [{
                    'id': record.id,
                    'user_id': record.user_id,
                    'chord_pair': record.chord_pair,
                    'score': record.score,
                    'date': record.date.isoformat() if record.date else None
                } for record in (all_practice_records if current_user.is_admin else practice_records)],
                'chord_shapes': [{
                    'id': cs.id,
                    'name': cs.name,
                    'variant': cs.variant,
                    'shape': cs.shape,
                    'created_at': cs.created_at.isoformat() if cs.created_at else None
                } for cs in chord_shapes]
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
                flash('No file selected', 'error')
                return redirect(url_for('backup'))
            
            file = request.files['backup_file']
            if file.filename == '':
                flash('No file selected', 'error')
                return redirect(url_for('backup'))
            
            if file and file.filename.endswith('.json'):
                try:
                    backup_data = json.load(file)
                    
                    # Validate backup data structure
                    if not isinstance(backup_data, dict) or 'version' not in backup_data:
                        flash('Invalid backup file format', 'error')
                        return redirect(url_for('backup'))
                    
                    # Check if trying to restore user data without admin privileges
                    if 'users' in backup_data and not current_user.is_admin:
                        flash('You do not have permission to restore user data', 'error')
                        return redirect(url_for('backup'))
                    
                    # Delete existing data
                    if current_user.is_admin:
                        Song.query.delete()
                        PracticeRecord.query.delete()
                        User.query.filter(User.id != current_user.id).delete()
                        ChordShape.query.delete()
                    else:
                        Song.query.filter_by(user_id=current_user.id).delete()
                        PracticeRecord.query.filter_by(user_id=current_user.id).delete()
                    
                    # Restore chord shapes (admin only or if present)
                    if 'chord_shapes' in backup_data:
                        if current_user.is_admin:
                            for cs_data in backup_data['chord_shapes']:
                                chord = ChordShape(
                                    id=cs_data.get('id'),
                                    name=cs_data.get('name'),
                                    variant=cs_data.get('variant'),
                                    shape=cs_data.get('shape'),
                                    created_at=datetime.fromisoformat(cs_data['created_at']) if cs_data.get('created_at') else None
                                )
                                db.session.add(chord)
                    
                    # Create a mapping of old user IDs to new user IDs
                    user_id_mapping = {}
                    if current_user.is_admin and 'users' in backup_data:
                        for user_data in backup_data['users']:
                            username_from_backup = user_data.get('username')
                            old_user_id_from_backup = user_data.get('id')

                            # Explicitly handle the 'admin' user when restoring as admin
                            if username_from_backup == 'admin':
                                # Map the old admin ID to the current admin's ID
                                user_id_mapping[old_user_id_from_backup] = current_user.id
                                # Optionally log a warning if backup admin data differs from current
                                if app.logger:
                                    existing_admin = User.query.filter_by(username='admin').first()
                                    if existing_admin and (existing_admin.is_admin != user_data.get('is_admin', True) or existing_admin.disabled != user_data.get('disabled', False)):
                                         app.logger.warning(f"Backup data for admin user (old ID {old_user_id_from_backup}) differs from current admin user. Current admin details will be kept.")
                                continue # Skip the rest of the loop for the admin user

                            # For other users, try to find an existing user by username
                            existing_user = User.query.filter_by(username=username_from_backup).first()

                            if existing_user:
                                # If user exists (and is not the current admin, which was handled above), update their details
                                existing_user.password_hash = user_data.get('password_hash', existing_user.password_hash) # Update password hash
                                existing_user.is_admin = user_data.get('is_admin', False)
                                existing_user.disabled = user_data.get('disabled', False)
                                # The username is used for lookup, so we don't update it here
                                # Add to mapping from old backup ID to existing user's current ID
                                user_id_mapping[old_user_id_from_backup] = existing_user.id

                            else:
                                # If user does not exist, create a new one
                                user = User(
                                    # Do NOT set ID here, let the database assign a new one
                                    username=user_data.get('username'),
                                    password_hash=user_data.get('password_hash'),
                                    is_admin=user_data.get('is_admin', False),
                                    disabled=user_data.get('disabled', False)
                                )
                                db.session.add(user)
                                # We need to flush to get the new ID for the mapping
                                db.session.flush()
                                user_id_mapping[old_user_id_from_backup] = user.id
                    
                    # Restore songs
                    songs_to_restore = backup_data.get('songs', [])
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
                                    notes=song_data.get('notes'),
                                    selected_variants=song_data.get('selected_variants', '{}'),
                                    display_beats=song_data.get('display_beats', 4)
                                )
                                
                                # Handle strumming pattern restoration properly using the setter
                                strumming_pattern_data = song_data.get('strumming_pattern')
                                if strumming_pattern_data:
                                    if isinstance(strumming_pattern_data, str):
                                        # If it's a JSON string, parse it and use the setter
                                        try:
                                            pattern_list = json.loads(strumming_pattern_data)
                                            song.strumming_pattern_list = pattern_list
                                        except json.JSONDecodeError:
                                            # If JSON parsing fails, set to None
                                            song.strumming_pattern_list = None
                                    elif isinstance(strumming_pattern_data, list):
                                        # If it's already a list, use the setter directly
                                        song.strumming_pattern_list = strumming_pattern_data
                                    else:
                                        # For any other type, set to None
                                        song.strumming_pattern_list = None
                                
                                db.session.add(song)
                            except Exception as e:
                                raise
                    
                    # Restore practice records
                    records_to_restore = backup_data.get('practice_records', [])
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
                                raise
                    
                    try:
                        db.session.commit()
                        flash('Backup restored successfully!', 'success')
                        return redirect(url_for('index'))
                    except Exception as e:
                        db.session.rollback()
                        raise
                except Exception as e:
                    db.session.rollback()
                    flash(f'Error restoring backup: {str(e)}', 'error')
                    return redirect(url_for('backup'))
            else:
                flash('Invalid file format for restore', 'error')
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

@app.route('/chord/<path:chord_name>')
def get_chord_diagram(chord_name):
    """Generate a basic chord diagram"""
    # Get variant from request arguments, default to None if not present or empty
    variant = request.args.get('variant')
    if variant == '':
        variant = None

    # Use the refined utility function to get the shape (either from DB or hardcoded)
    # First, try the full chord name (e.g., 'Fmaj7/C')
    shape_data = get_chord_shape(chord_name, variant=variant)

    # If no shape found for the full name, and it's a slash chord, try the base name
    if not shape_data and '/' in chord_name:
        base_chord_name = chord_name.split('/')[0]
        shape_data = get_chord_shape(base_chord_name, variant=variant)

    # If no shape data is found, return an empty SVG or an error indicator
    if not shape_data:
        # Return a small, empty SVG or similar to avoid breaking the page layout
        return Response('<svg width="150" height="200"><text x="10" y="20" font-size="12">Please add chord shape</text></svg>', mimetype='image/svg+xml')

    chord_shape = shape_data.get_shape()
    # Explicitly get start_fret and ensure it's an integer
    start_fret = int(shape_data.start_fret)

    # app.logger.info(f"Generating SVG for {chord_name} with shape: {chord_shape} and start_fret: {start_fret}")
    
    # SVG dimensions
    width = 220
    height = 220
    fret_height = 30
    string_spacing = 20
    left_margin = 40
    top_margin = 20
    
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
        x = left_margin + i * string_spacing
        svg += f'<line x1="{x}" y1="{top_margin}" x2="{x}" y2="{top_margin + 4 * fret_height}" class="string"/>'
    # Draw starting fret number label (e.g., '5fr') to the left of the first fret, inline with the second fret line
    if start_fret > 0:
        # Position the label inline with the second horizontal line (first fret line)
        # The second horizontal line is at y = top_margin + 1 * fret_height
        y_label = top_margin + fret_height # Target the vertical position of the first fret line
        label = f'{start_fret}fr'
        svg += f'<text x="{left_margin - 10}" y="{y_label}" font-size="14" fill="#333" text-anchor="end" dominant-baseline="middle">{label}</text>'

    # Draw dots and finger numbering in a single pass
    if chord_shape:
        for string_idx, (fret, symbol) in enumerate(chord_shape):
            x = left_margin + string_idx * string_spacing
            if symbol == 'x':
                # Draw 'x' for muted strings
                svg += f'<text x="{x}" y="{top_margin - 10}" text-anchor="middle" class="x">×</text>'
            elif fret == 0:
                # Draw open circle for open strings
                svg += f'<circle cx="{x}" cy="{top_margin - 15}" r="4" class="open"/>'
            elif isinstance(fret, int) and fret > 0:
                # Draw dot for fretted notes
                y = top_margin + (fret - 0.5) * fret_height
                svg += f'<circle cx="{x}" cy="{y}" r="6" class="dot"/>'
                # Add finger numbering inside the dot if the symbol is an integer finger number > 0
                if isinstance(symbol, int) and symbol > 0:
                    # Position text at the center of the dot
                    svg += f'<text x="{x}" y="{y + 2}" text-anchor="middle" font-size="12" fill="#fff" alignment-baseline="middle">{symbol}</text>'
    
    svg += '</svg>'
    
    # Return the SVG string without any trailing newlines
    return Response(svg.strip(), mimetype='image/svg+xml')

# Make version available to all templates
@app.context_processor
def inject_version():
    """Inject version number into all templates"""
    return dict(version=VERSION)

# Utility to get chord shape by name and optional variant
def get_chord_shape(name, variant=None):
    # Define HardcodedShapeDummy class locally if it's not globally accessible
    class HardcodedShapeDummy:
        def __init__(self, name, shape, start_fret, variant):
            self.name = name
            # Store shape as JSON string internally for consistency with DB model
            self.shape = json.dumps(shape)
            self.start_fret = start_fret
            self.variant = variant

        def get_shape(self):
            # Deserialize the shape JSON string when requested
            return json.loads(self.shape)

    # First, try to find a shape in the database matching name and specified variant (if provided)
    db_chord = None
    if variant is not None and variant != '':
        db_chord = ChordShape.query.filter_by(name=name, variant=variant).first()
        if db_chord:
            # Return the ChordShape object directly
            return db_chord

    # If no specific variant was requested, or not found, try to find the default (variant=None) in DB
    # This handles cases where the variant was explicitly saved as None
    if variant is None or variant == '':
        db_chord_none_variant = ChordShape.query.filter_by(name=name, variant=None).first()
        if db_chord_none_variant:
            # Return the ChordShape object directly
            return db_chord_none_variant

    # If variant=None not found, also try to find shape with variant='' (empty string) in DB
    # This handles cases where the blank variant field in the form was saved as an empty string
    db_chord_empty_variant = ChordShape.query.filter_by(name=name, variant='').first()
    if db_chord_empty_variant:
        # Return the ChordShape object directly
        return db_chord_empty_variant

    # If not found in DB, check if it's a slash chord and try the base name
    if '/' in name:
        base_name = name.split('/')[0]
        # Recursively call get_chord_shape with the base name and the same variant
        # This handles cases where a specific variant of the base chord is requested for a slash chord
        base_shape = get_chord_shape(base_name, variant=variant)
        if base_shape:
             return base_shape

    # If still not found, fallback to hardcoded shapes
    hardcoded_shapes = {
        'C': {'shape': [(0, 'x'), (3, 3), (2, 2), (0, 0), (1, 1), (0, 0)], 'start_fret': 0},
        'G': {'shape': [(3, 1), (2, 2), (0, 0), (0, 0), (0, 0), (3, 3)], 'start_fret': 0},
        'D': {'shape': [(0, 'x'), (0, 'x'), (0, 0), (2, 2), (3, 1), (2, 3)], 'start_fret': 0},
        'A': {'shape': [(0, 'x'), (0, 0), (2, 1), (2, 2), (2, 3), (0, 0)], 'start_fret': 0},
        'E': {'shape': [(0, 0), (2, 2), (2, 2), (1, 1), (0, 0), (0, 0)], 'start_fret': 0},
        'Am': {'shape': [(0, 'x'), (0, 0), (2, 2), (2, 3), (1, 1), (0, 0)], 'start_fret': 0},
        'Em': {'shape': [(0, 0), (2, 2), (2, 3), (0, 0), (0, 0), (0, 0)], 'start_fret': 0},
        'F': {'shape': [(1, 1), (3, 4), (3, 3), (2, 2), (1, 1), (1, 1)], 'start_fret': 1},
        'Dm': {'shape': [(0, 'x'), (0, 'x'), (0, 0), (2, 2), (3, 3), (1, 1)], 'start_fret': 0},
        'G7': {'shape': [(3, 3), (2, 2), (0, 0), (0, 0), (0, 0), (1, 1)], 'start_fret': 0},
        'C7': {'shape': [(0, 'x'), (3, 3), (2, 2), (3, 3), (1, 1), (0, 0)], 'start_fret': 0},
        'A7': {'shape': [(0, 'x'), (0, 0), (2, 2), (0, 0), (2, 2), (0, 0)], 'start_fret': 0},
        'E7': {'shape': [(0, 0), (2, 2), (0, 0), (1, 1), (0, 0), (0, 0)], 'start_fret': 0},
        'B7': {'shape': [(2, 2), (1, 1), (2, 2), (0, 0), (2, 2), (0, 'x')], 'start_fret': 0},
        'Fmaj7': {'shape': [(0, 'x'), (0, 'x'), (3, 4), (2, 2), (1, 1), (0, 0)], 'start_fret': 0},
        'Bm': {'shape': [(2, 2), (2, 2), (4, 4), (4, 4), (3, 3), (2, 2)], 'start_fret': 0},
        'Cadd9': {'shape': [(0, 'x'), (3, 2), (2, 1), (0, 0), (3, 3), (3, 4)], 'start_fret': 0},
    }

    hardcoded_shape_data = hardcoded_shapes.get(name)
    if hardcoded_shape_data:
        # Wrap hardcoded shape data in a dummy object for consistent structure
        return HardcodedShapeDummy(name, hardcoded_shape_data['shape'], hardcoded_shape_data['start_fret'], None) # Treat hardcoded as variant=None

    return None # No shape found at all

@app.route('/admin/chords')
@login_required
def admin_chords():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))
    chords = ChordShape.query.order_by(ChordShape.name).all()
    return render_template('admin_chords.html', chords=chords)

@app.route('/admin/chords/new', methods=['GET', 'POST'])
@login_required
def new_chord_shape():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form.get('name')
        variant = request.form.get('variant', '').strip() # Get variant, default to empty string if not provided
        # Set variant to None if it's an empty string
        if not variant:
            variant = None

        shape = request.form.get('shape')
        start_fret = int(request.form.get('start_fret', 0))

        if not name or not shape:
            flash('Name and shape are required.')
            return redirect(url_for('new_chord_shape'))

        # Check for uniqueness of name and variant combination
        existing_chord = ChordShape.query.filter_by(name=name, variant=variant).first()
        if existing_chord:
            flash(f"Chord shape with name \"{name}\" and variant \"{variant if variant else ''}\" already exists.")
            return redirect(url_for('new_chord_shape'))

        try:
            # Validate shape is valid JSON
            json_shape = json.loads(shape)
            chord = ChordShape(name=name, variant=variant, shape=json.dumps(json_shape), start_fret=start_fret)
            db.session.add(chord)
            db.session.commit()
            flash('Chord shape added successfully!')
            return redirect(url_for('admin_chords'))
        except Exception as e:
            flash(f'Invalid shape format: {e}')
            return redirect(url_for('new_chord_shape'))
    return render_template('edit_chord_shape.html', chord=None)

@app.route('/admin/chords/<int:chord_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_chord_shape(chord_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))
    chord = ChordShape.query.get_or_404(chord_id)
    if request.method == 'POST':
        name = request.form.get('name')
        variant = request.form.get('variant', '').strip() # Get variant, default to empty string if not provided
        # Set variant to None if it's an empty string
        if not variant:
            variant = None

        shape = request.form.get('shape')
        start_fret = int(request.form.get('start_fret', 0))

        if not name or not shape:
            flash('Name and shape are required.')
            return redirect(url_for('edit_chord_shape', chord_id=chord_id))

        # Check for uniqueness of name and variant combination, excluding the current chord being edited
        existing_chord = ChordShape.query.filter(ChordShape.name == name, ChordShape.variant == variant, ChordShape.id != chord.id).first()
        if existing_chord:
            flash(f"Chord shape with name \"{name}\" and variant \"{variant if variant else ''}\" already exists.")
            return redirect(url_for('edit_chord_shape', chord_id=chord_id))

        try:
            json_shape = json.loads(shape)
            chord.name = name
            chord.variant = variant # Update the variant
            chord.shape = json.dumps(json_shape)
            chord.start_fret = start_fret
            db.session.commit()
            flash('Chord shape updated successfully!')
            return redirect(url_for('admin_chords'))
        except Exception as e:
            flash(f'Invalid shape format: {e}')
            return redirect(url_for('edit_chord_shape', chord_id=chord_id))
    return render_template('edit_chord_shape.html', chord=chord)

@app.route('/admin/chords/<int:chord_id>/delete', methods=['POST'])
@login_required
def delete_chord_shape(chord_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))
    chord = ChordShape.query.get_or_404(chord_id)
    db.session.delete(chord)
    db.session.commit()
    flash('Chord shape deleted successfully!')
    return redirect(url_for('admin_chords'))

# Admin route to toggle registration
@app.route('/admin/toggle_registration', methods=['POST'])
@login_required
def toggle_registration():
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.')
        return redirect(url_for('admin'))
    enabled = SiteOption.get('registration_enabled', '1')
    SiteOption.set('registration_enabled', '0' if enabled == '1' else '1')
    flash(f"User registration is now {'enabled' if enabled == '0' else 'disabled'}.", 'success')
    return redirect(url_for('admin'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_admin()
        create_default_chord_pairs()
    app.run(host='0.0.0.0', port=5001, debug=False) 