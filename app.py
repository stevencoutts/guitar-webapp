from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
import os
import re

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Security configurations
if not os.environ.get('SECRET_KEY'):
    raise ValueError("No SECRET_KEY set for Flask application")
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///guitar_app.db'
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
csrf = CSRFProtect(app)  # Initialize CSRF first
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_SECRET_KEY'] = os.environ.get('SECRET_KEY')
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

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
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=True)  # All existing users will be admins
    songs = db.relationship('Song', backref='user', lazy=True)

class Song(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    time_signature = db.Column(db.String(10), nullable=False)
    bpm = db.Column(db.Integer, nullable=False, default=120)  # Default BPM of 120
    chord_progression = db.Column(db.Text, nullable=False)
    strumming_pattern = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        songs = Song.query.filter_by(user_id=current_user.id).all()
    else:
        songs = []
    return render_template('index.html', songs=songs)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
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
    logout_user()
    return redirect(url_for('index'))

@app.route('/song/new', methods=['GET', 'POST'])
@login_required
def new_song():
    if request.method == 'POST':
        title = request.form.get('title')
        time_signature = request.form.get('time_signature')
        bpm = request.form.get('bpm')
        chord_progression = request.form.get('chord_progression')
        strumming_pattern = request.form.get('strumming_pattern')
        
        if not all([title, time_signature, bpm, chord_progression, strumming_pattern]):
            flash('All fields are required')
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
        
        song = Song(
            title=title,
            time_signature=time_signature,
            bpm=bpm,
            chord_progression=chord_progression,
            strumming_pattern=strumming_pattern,
            user_id=current_user.id
        )
        db.session.add(song)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('new_song.html')

@app.route('/song/<int:song_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_song(song_id):
    song = Song.query.get_or_404(song_id)
    
    # Ensure the user owns this song
    if song.user_id != current_user.id:
        flash('You do not have permission to edit this song.')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        title = request.form.get('title')
        time_signature = request.form.get('time_signature')
        bpm = request.form.get('bpm')
        chord_progression = request.form.get('chord_progression')
        strumming_pattern = request.form.get('strumming_pattern')
        
        if not all([title, time_signature, bpm, chord_progression, strumming_pattern]):
            flash('All fields are required')
            return redirect(url_for('edit_song', song_id=song_id))
            
        # Basic input validation
        if len(title) > 100:
            flash('Title is too long')
            return redirect(url_for('edit_song', song_id=song_id))
            
        if not re.match(r'^\d+/\d+$', time_signature):
            flash('Invalid time signature format')
            return redirect(url_for('edit_song', song_id=song_id))
            
        try:
            bpm = int(bpm)
            if bpm < 20 or bpm > 300:
                flash('BPM must be between 20 and 300')
                return redirect(url_for('edit_song', song_id=song_id))
        except ValueError:
            flash('BPM must be a valid number')
            return redirect(url_for('edit_song', song_id=song_id))
        
        song.title = title
        song.time_signature = time_signature
        song.bpm = bpm
        song.chord_progression = chord_progression
        song.strumming_pattern = strumming_pattern
        
        db.session.commit()
        flash('Song updated successfully!')
        return redirect(url_for('index'))
        
    return render_template('edit_song.html', song=song)

@app.route('/song/<int:song_id>/delete', methods=['POST'])
@login_required
def delete_song(song_id):
    song = Song.query.get_or_404(song_id)
    
    # Ensure the user owns this song
    if song.user_id != current_user.id:
        flash('You do not have permission to delete this song.')
        return redirect(url_for('index'))
    
    try:
        db.session.delete(song)
        db.session.commit()
        flash('Song deleted successfully!')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while deleting the song.')
    
    return redirect(url_for('index'))

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
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
    song = Song.query.get_or_404(song_id)
    
    # Ensure the user owns this song
    if song.user_id != current_user.id:
        flash('You do not have permission to view this song.')
        return redirect(url_for('index'))
    
    return render_template('view_song.html', song=song)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('You do not have permission to access the admin page.')
        return redirect(url_for('index'))
    
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/admin/user/<int:user_id>/toggle_admin', methods=['POST'])
@login_required
def toggle_admin(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
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
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.')
        return redirect(url_for('index'))
    
    username = request.form.get('username')
    password = request.form.get('password')
    is_admin = request.form.get('is_admin') == 'on'
    
    if not username or not password:
        flash('Username and password are required.')
        return redirect(url_for('admin'))
    
    if User.query.filter_by(username=username).first():
        flash('Username already exists.')
        return redirect(url_for('admin'))
    
    if not is_valid_password(password):
        flash('Password must be at least 8 characters long and contain uppercase, lowercase, and numbers.')
        return redirect(url_for('admin'))
    
    user = User(
        username=username,
        password_hash=generate_password_hash(password),
        is_admin=is_admin
    )
    db.session.add(user)
    db.session.commit()
    
    flash(f'User {username} has been created successfully.')
    return redirect(url_for('admin'))

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot delete your own account.')
        return redirect(url_for('admin'))
    
    # Delete all user's songs first
    Song.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    
    flash(f'User {user.username} has been deleted.')
    return redirect(url_for('admin'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Set all existing users as admins
        User.query.update({User.is_admin: True})
        db.session.commit()
    app.run(debug=True, port=5001)  # Enable debug mode for development 