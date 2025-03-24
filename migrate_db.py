from app import app, db
from sqlalchemy import text

def migrate():
    with app.app_context():
        try:
            # Check if capo column exists
            result = db.session.execute(text("SELECT capo FROM song LIMIT 1"))
            print("Capo column already exists")
        except Exception:
            print("Adding capo column...")
            # Add capo column with default value 'None'
            db.session.execute(text('ALTER TABLE song ADD COLUMN capo VARCHAR(10) DEFAULT "None" NOT NULL'))
            db.session.commit()
            print("Capo column added successfully")

if __name__ == '__main__':
    migrate() 