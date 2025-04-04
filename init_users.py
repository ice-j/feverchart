from app import app, db, User

with app.app_context():
    db.create_all()
    
    # Create a test user
    test_user = User(username="testuser", password="password123")  # Use hashed passwords in production!
    db.session.add(test_user)
    db.session.commit()

    print("Test user created!")
