from app import app, db, User, Song, PracticeRecord, ChordPair
from datetime import datetime

def init_db():
    with app.app_context():
        # Drop all tables if they exist
        db.drop_all()
        
        # Create all tables
        db.create_all()
        
        # Create predefined chord pairs
        predefined_pairs = [
            # Easy pairs
            ChordPair(first_chord='Am', second_chord='Em', difficulty=1, description='Easy: Am to Em'),
            ChordPair(first_chord='C', second_chord='G', difficulty=1, description='Easy: C to G'),
            ChordPair(first_chord='Dm', second_chord='Am', difficulty=1, description='Easy: Dm to Am'),
            
            # Medium pairs
            ChordPair(first_chord='F', second_chord='C', difficulty=2, description='Medium: F to C'),
            ChordPair(first_chord='G', second_chord='Em', difficulty=2, description='Medium: G to Em'),
            ChordPair(first_chord='Am', second_chord='F', difficulty=2, description='Medium: Am to F'),
            
            # Hard pairs
            ChordPair(first_chord='Bm', second_chord='F#m', difficulty=3, description='Hard: Bm to F#m'),
            ChordPair(first_chord='C#m', second_chord='G#m', difficulty=3, description='Hard: C#m to G#m'),
            ChordPair(first_chord='F#', second_chord='B', difficulty=3, description='Hard: F# to B'),
            
            # Very hard pairs
            ChordPair(first_chord='B', second_chord='F#', difficulty=4, description='Very Hard: B to F#'),
            ChordPair(first_chord='C#m', second_chord='A', difficulty=4, description='Very Hard: C#m to A'),
            ChordPair(first_chord='F#m', second_chord='D', difficulty=4, description='Very Hard: F#m to D')
        ]
        
        # Add all chord pairs to the database
        for pair in predefined_pairs:
            db.session.add(pair)
        
        # Create a default admin user
        admin = User(username='admin', is_admin=True)
        admin.set_password('admin123')  # Change this password in production!
        db.session.add(admin)
        
        # Commit all changes
        db.session.commit()
        
        print("Database initialized successfully!")

if __name__ == '__main__':
    init_db() 