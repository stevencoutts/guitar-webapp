from app import app, db
from sqlalchemy import text

def migrate():
    with app.app_context():
        # Add capo column with default value 'None'
        db.session.execute(text('ALTER TABLE song ADD COLUMN capo VARCHAR(10) DEFAULT "None"'))
        db.session.commit()

if __name__ == '__main__':
    migrate() 