from werkzeug.security import generate_password_hash
from datetime import datetime, timezone
from .models import User
from . import db
import logging

logger = logging.getLogger('db')


def initialize_database():
    """
    Initialize the database with required tables and initial data.
    This function:
    1. Creates all tables if they don't exist
    2. Creates a default admin user if none exists
    """
    logger.info("Initializing database")

    # Create all tables
    db.create_all()
    logger.info("Created tables")

    # Check if a user exists and create one if not
    user_exists = db.session.query(User).first() is not None
    if not user_exists:
        # Create default admin user (username: admin, password: Admin123!)
        default_user = User(
            username="admin",
            email="admin@example.com",
            password=generate_password_hash("Admin123!"),
            created_at=datetime.now(timezone.utc),
            is_active=True
        )
        db.session.add(default_user)
        db.session.commit()
        logger.info("Created default admin user (username: admin, password: Admin123!)")

    logger.info("Database initialization complete")
