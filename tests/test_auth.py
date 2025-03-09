import json
import pytest
from datetime import datetime, timedelta
from flask_jwt_extended import create_access_token


def test_register_success(client):
    """Test successful user registration."""
    response = client.post('/register', json={
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'Password123'
    })

    assert response.status_code == 201
    data = json.loads(response.data)
    assert 'access_token' in data
    assert 'refresh_token' in data
    assert data['msg'] == 'User registered successfully'
    assert data['user']['username'] == 'testuser'
    assert data['user']['email'] == 'test@example.com'


def test_register_duplicate_username(client):
    """Test registration with a duplicate username."""
    # First create a user
    client.post('/register', json={
        'username': 'duplicate',
        'email': 'first@example.com',
        'password': 'Password123'
    })

    # Try to register with the same username
    response = client.post('/register', json={
        'username': 'duplicate',
        'email': 'second@example.com',
        'password': 'Password123'
    })

    assert response.status_code == 409
    data = json.loads(response.data)
    assert data['msg'] == 'Username already exists'


def test_register_duplicate_email(client):
    """Test registration with a duplicate email."""
    # First create a user
    client.post('/register', json={
        'username': 'user1',
        'email': 'duplicate@example.com',
        'password': 'Password123'
    })

    # Try to register with the same email
    response = client.post('/register', json={
        'username': 'user2',
        'email': 'duplicate@example.com',
        'password': 'Password123'
    })

    assert response.status_code == 409
    data = json.loads(response.data)
    assert data['msg'] == 'Email already exists'


def test_register_invalid_username(client):
    """Test registration with an invalid username."""
    response = client.post('/register', json={
        'username': 'invalid username with spaces',
        'email': 'test@example.com',
        'password': 'Password123'
    })

    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'Invalid username format' in data['msg']


def test_register_invalid_email(client):
    """Test registration with an invalid email."""
    response = client.post('/register', json={
        'username': 'testuser',
        'email': 'not-an-email',
        'password': 'Password123'
    })

    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'Invalid email format' in data['msg']


def test_register_weak_password(client):
    """Test registration with a weak password."""
    response = client.post('/register', json={
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'weak'
    })

    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'Password must be at least 8 characters' in data['msg']


def test_login_success(client):
    """Test successful login."""
    # First register a user
    client.post('/register', json={
        'username': 'logintest',
        'email': 'login@example.com',
        'password': 'Password123'
    })

    # Now login
    response = client.post('/login', json={
        'username': 'logintest',
        'password': 'Password123'
    })

    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'access_token' in data
    assert 'refresh_token' in data
    assert data['msg'] == 'Login successful'
    assert data['user']['username'] == 'logintest'


def test_login_nonexistent_user(client):
    """Test login with a non-existent user."""
    response = client.post('/login', json={
        'username': 'nonexistent',
        'password': 'Password123'
    })

    assert response.status_code == 401
    data = json.loads(response.data)
    assert data['msg'] == 'Invalid credentials'


def test_login_wrong_password(client):
    """Test login with the wrong password."""
    # First register a user
    client.post('/register', json={
        'username': 'passwordtest',
        'email': 'password@example.com',
        'password': 'Password123'
    })

    # Now try to login with wrong password
    response = client.post('/login', json={
        'username': 'passwordtest',
        'password': 'WrongPassword123'
    })

    assert response.status_code == 401
    data = json.loads(response.data)
    assert data['msg'] == 'Invalid credentials'


def test_protected_endpoint_with_token(client, app):
    """Test accessing a protected endpoint with a valid token."""
    with app.app_context():
        # Create a token directly with proper string identity
        access_token = create_access_token(identity='1')

        # Access protected endpoint
        response = client.get('/protected', headers={
            'Authorization': f'Bearer {access_token}'
        })

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['msg'] == 'This is a protected endpoint'


def test_protected_endpoint_without_token(client):
    """Test accessing a protected endpoint without a token."""
    response = client.get('/protected')

    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'Missing Authorization Header' in data['msg']


def test_protected_endpoint_with_invalid_token(client):
    """Test accessing a protected endpoint with an invalid token."""
    response = client.get('/protected', headers={
        'Authorization': 'Bearer invalid_token'
    })

    # Either 401 or 422 is acceptable depending on how JWT is configured
    assert response.status_code in [401, 422]
    data = json.loads(response.data)
    assert 'Invalid token' in data['msg'] or 'Not enough segments' in data['msg']


def test_refresh_token(client, app):
    """Test refreshing an access token using a refresh token."""
    with app.app_context():
        # Create a refresh token directly with proper string identity
        refresh_token = create_access_token(
            identity='1',
            additional_claims={'type': 'refresh'}
        )

        # Refresh access token
        response = client.post('/refresh', headers={
            'Authorization': f'Bearer {refresh_token}'
        })

        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'access_token' in data
        assert data['msg'] == 'Token refreshed'


def test_refresh_with_access_token(client, app):
    """Test refreshing with an access token instead of refresh token."""
    with app.app_context():
        # Create an access token
        access_token = create_access_token(identity='1')

        # Try to refresh with access token
        response = client.post('/refresh', headers={
            'Authorization': f'Bearer {access_token}'
        })

        # Either 401 or 422 is acceptable
        assert response.status_code in [401, 422]
        data = json.loads(response.data)
        assert 'Only refresh tokens are allowed' in data['msg'] or 'Token has invalid type' in data[
            'msg'] or 'Invalid token' in data['msg']


def test_logout(client, app):
    """Test user logout."""
    with app.app_context():
        # Create an access token directly with proper string identity
        access_token = create_access_token(identity='1')

        # Logout
        response = client.post('/logout', headers={
            'Authorization': f'Bearer {access_token}'
        })

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['msg'] == 'Successfully logged out'

        # Try to access protected endpoint with the same token
        protected_response = client.get('/protected', headers={
            'Authorization': f'Bearer {access_token}'
        })

        assert protected_response.status_code == 401
        protected_data = json.loads(protected_response.data)
        assert 'Token has been revoked' in protected_data['msg']
