import os
from app import create_app, db

app = create_app()

@app.cli.command("create-db")
def create_db():
    """Create database tables"""
    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")

@app.cli.command("create-test-user")
def create_test_user():
    """Create a test user for development"""
    from app.models import User
    
    username = "admin"
    email = "admin@example.com"
    password = "password"
    
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if user:
            print(f"User {username} already exists")
            return
        
        user = User(username=username, email=email, password=password, is_admin=True)
        db.session.add(user)
        db.session.commit()
        print(f"Test user {username} created")

if __name__ == "__main__":
    with app.app_context():
        # Create database tables if they don't exist
        db.create_all()
    app.run(debug=True)
