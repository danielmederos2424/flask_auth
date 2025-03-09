import os
import tempfile
import pytest
from auth_api import create_app, db
from auth_api.models import User
from werkzeug.security import generate_password_hash


@pytest.fixture(scope='session')
def app():
    """Create and configure a Flask app for testing."""
    # Create a temporary file to isolate the database for each test
    db_fd, db_path = tempfile.mkstemp()
    db_uri = f'sqlite:///{db_path}'

    app = create_app({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': db_uri,
        'JWT_SECRET_KEY': 'test-jwt-key'
    })

    # Create the database and load test data
    with app.app_context():
        db.create_all()

        # Create a default test user
        default_user = User(
            username="testadmin",
            email="testadmin@example.com",
            password=generate_password_hash("testpassword"),
            is_active=True
        )
        db.session.add(default_user)
        db.session.commit()

    # Add the app context to ensure it's available for all tests
    ctx = app.app_context()
    ctx.push()

    yield app

    # Clean up
    ctx.pop()
    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """A test CLI runner for the app."""
    return app.test_cli_runner()


# Add a database fixture to allow easy database access
@pytest.fixture
def database():
    """Access to the database within tests."""
    return db
