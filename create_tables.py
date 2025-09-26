# create_tables.py
from app import app, db

# The app.app_context() ensures that the application is configured
# before we try to interact with the database.
with app.app_context():
    print("Creating database tables...")
    db.create_all()
    print("✅ Done! Tables created successfully.")