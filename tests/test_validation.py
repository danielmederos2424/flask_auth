import pytest
from auth_api.validation_utils import (
    validate_email, validate_username, validate_password,
    validate_json_data, sanitize_string, validate_required_fields
)


def test_validate_email():
    """Test email validation."""
    # Valid emails
    assert validate_email('user@example.com') is True
    assert validate_email('user.name@example.co.uk') is True
    assert validate_email('user+tag@example.com') is True

    # Invalid emails
    assert validate_email('') is False
    assert validate_email('user@') is False
    assert validate_email('user@.com') is False
    assert validate_email('user@example') is False
    assert validate_email('user.example.com') is False


def test_validate_username():
    """Test username validation."""
    # Valid usernames
    assert validate_username('user123') is True
    assert validate_username('user_name') is True
    assert validate_username('User123_') is True

    # Invalid usernames
    assert validate_username('') is False
    assert validate_username('user name') is False
    assert validate_username('user-name') is False
    assert validate_username('user@name') is False


def test_validate_password():
    """Test password validation."""
    # Valid passwords (at least 8 chars, 1 letter, 1 number)
    assert validate_password('Password123') is True
    assert validate_password('pass1234') is True
    assert validate_password('1234Pass') is True
    assert validate_password('Pass@123') is True

    # Invalid passwords
    assert validate_password('') is False
    assert validate_password('pass') is False  # Too short
    assert validate_password('password') is False  # No numbers
    assert validate_password('12345678') is False  # No letters


def test_sanitize_string():
    """Test string sanitization."""
    assert sanitize_string('<script>alert("XSS")</script>') == 'alert("XSS")'
    assert sanitize_string('Normal text') == 'Normal text'

    # Test max length
    long_string = 'a' * 20
    assert sanitize_string(long_string, max_length=10) == 'a' * 10

    # Test with None
    assert sanitize_string(None) is None

    # Test with non-string
    assert sanitize_string(123) == '123'


def test_validate_json_data():
    """Test JSON data validation."""
    # Valid data
    valid_data = {
        'username': 'user123',
        'email': 'user@example.com',
        'profile': {
            'age': 25,
            'interests': ['coding', 'reading']
        }
    }
    assert validate_json_data(valid_data) == (True, None)

    # Invalid key
    invalid_key_data = {
        'username': 'user123',
        'invalid-key': 'value'  # Keys must be alphanumeric with underscores
    }
    valid, message = validate_json_data(invalid_key_data)
    assert valid is False
    assert 'Invalid field name' in message


def test_validate_required_fields():
    """Test required fields validation."""
    data = {
        'username': 'user123',
        'email': 'user@example.com',
        'password': 'password123'
    }

    # All required fields present
    valid, message = validate_required_fields(data, ['username', 'email', 'password'])
    assert valid is True
    assert message is None

    # Missing field
    valid, message = validate_required_fields(data, ['username', 'email', 'password', 'missing'])
    assert valid is False
    assert 'missing' in message

    # Empty value
    data_with_empty = {
        'username': 'user123',
        'email': '',
        'password': 'password123'
    }
    valid, message = validate_required_fields(data_with_empty, ['username', 'email', 'password'])
    assert valid is True  # Empty strings are still values

    # None value
    data_with_none = {
        'username': 'user123',
        'email': None,
        'password': 'password123'
    }
    valid, message = validate_required_fields(data_with_none, ['username', 'email', 'password'])
    assert valid is False
    assert 'email' in message
