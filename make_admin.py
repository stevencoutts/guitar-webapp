from app import app, db, User

def make_admin(username):
    """
    Makes a user an admin by setting their is_admin flag to True.
    
    Args:
        username (str): The username of the user to make an admin
        
    Returns:
        None: Prints success or error message to console
    """
    # Create an application context to access the database
    with app.app_context():
        # Query the database for a user with the given username
        user = User.query.filter_by(username=username).first()
        
        if user:
            # If user exists, set their is_admin flag to True
            user.is_admin = True
            # Commit the change to the database
            db.session.commit()
            print(f"Successfully made {username} an admin")
        else:
            # If user doesn't exist, print error message
            print(f"User {username} not found")

if __name__ == '__main__':
    # Check if a username was provided as a command line argument
    import sys
    if len(sys.argv) != 2:
        print("Usage: python make_admin.py <username>")
        sys.exit(1)
        
    # Get the username from command line arguments and call make_admin
    username = sys.argv[1]
    make_admin(username) 