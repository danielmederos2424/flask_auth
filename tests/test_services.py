import pytest
from datetime import datetime, timedelta
from auth_api.services import register_user, login_user, logout_user, refresh_access_token
from auth_api.models import User, TokenBlacklist
from auth_api import db
from werkzeug.security import generate_password_hash, check_password_hash
import json
from flask_jwt_extended import create_access_token, decode_token


def test_register_user_service(app):
    """Test the register_user service function."""
    with app.app_context():
        # Test valid registration
        data = {
            'username': 'servicetest',
            'email': 'service@example.com',
            'password': 'Password123'
        }
        response, status = register_user(data)

        assert status == 201
        assert response['msg'] == 'User registered successfully'
        assert 'access_token' in response
        assert 'refresh_token' in response
        assert response['user']['username'] == 'servicetest'

        # Verify user was created in database
        user = User.query.filter_by(username='servicetest').first()
        assert user is not None
        assert user.email == 'service@example.com'
        assert check_password_hash(user.password, 'Password123')

        # Test duplicate username
        duplicate_data = {
            'username': 'servicetest',
            'email': 'another@example.com',
            'password': 'Password123'
        }
        response, status = register_user(duplicate_data)

        assert status == 409
        assert response['msg'] == 'Username already exists'

        # Test duplicate email
        duplicate_email_data = {
            'username': 'anotheruser',
            'email': 'service@example.com',
            'password': 'Password123'
        }
        response, status = register_user(duplicate_email_data)

        assert status == 409
        assert response['msg'] == 'Email already exists'


def test_login_user_service(app):
    """Test the login_user service function."""
    with app.app_context():
        # Create a test user
        user = User(
            username='loginservicetest',
            email='loginservice@example.com',
            password=generate_password_hash('Password123'),
            is_active=True
        )
        db.session.add(user)
        db.session.commit()

        # Test valid login
        data = {
            'username': 'loginservicetest',
            'password': 'Password123'
        }
        response, status = login_user(data)

        assert status == 200
        assert response['msg'] == 'Login successful'
        assert 'access_token' in response
        assert 'refresh_token' in response
        assert response['user']['username'] == 'loginservicetest'

        # Test invalid password
        invalid_data = {
            'username': 'loginservicetest',
            'password': 'WrongPassword'
        }
        response, status = login_user(invalid_data)

        assert status == 401
        assert response['msg'] == 'Invalid credentials'

        # Test non-existent user
        nonexistent_data = {
            'username': 'nonexistentuser',
            'password': 'Password123'
        }
        response, status = login_user(nonexistent_data)

        assert status == 401
        assert response['msg'] == 'Invalid credentials'

        # Test inactive user
        user.is_active = False
        db.session.commit()

        response, status = login_user(data)
        assert status == 401
        assert response['msg'] == 'Account is deactivated'


def test_logout_user_service(app):
    """Test the logout_user service function."""
    with app.app_context():
        # Create a test token payload manually instead of decoding
        # Use timestamp (integer) for exp, not datetime object
        future_timestamp = int((datetime.now() + timedelta(hours=1)).timestamp())

        jwt_payload = {
            'jti': 'test-jti-123',
            'sub': '1',  # User ID as string
            'type': 'access',
            'exp': future_timestamp
        }

        # Test logout
        response, status = logout_user(jwt_payload)

        assert status == 200
        assert response['msg'] == 'Successfully logged out'

        # Verify token was blacklisted
        blacklisted = TokenBlacklist.query.filter_by(jti='test-jti-123').first()
        assert blacklisted is not None
        assert blacklisted.user_id == 1  # Changed from '1' to 1 (integer)
        assert blacklisted.token_type == 'access'
        assert blacklisted.revoked is True


def test_refresh_access_token_service(app):
    """Test the refresh_access_token service function."""
    with app.app_context():
        # Create a test user
        user = User(
            username='refreshservicetest',
            email='refreshservice@example.com',
            password=generate_password_hash('Password123'),
            is_active=True,
            id=999  # Specific ID for testing
        )
        db.session.add(user)
        db.session.commit()

        # Test refresh for valid user
        response, status = refresh_access_token(999)

        assert status == 200
        assert response['msg'] == 'Token refreshed'
        assert 'access_token' in response

        # Test refresh for non-existent user
        response, status = refresh_access_token(9999)

        assert status == 404
        assert response['msg'] == 'User not found'

        # Test refresh for inactive user
        user.is_active = False
        db.session.commit()

        response, status = refresh_access_token(999)

        assert status == 401
        assert response['msg'] == 'Account is deactivated'
