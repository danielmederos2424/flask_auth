import re
from functools import wraps
from flask import request, jsonify
import bleach
import logging

logger = logging.getLogger('validation')

# Define validation patterns
EMAIL_PATTERN = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
USERNAME_PATTERN = r'^[a-zA-Z0-9_]+$'
PASSWORD_PATTERN = r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]{8,}$'
JSON_FIELDS_PATTERN = r'^[a-zA-Z0-9_]+$'  # For keys in JSON objects

# Maximum lengths for string fields
MAX_LENGTHS = {
    'username': 255,
    'email': 255,
    'password': 255
}


def validate_required_fields(data, required_fields):
    """Validate that all required fields are present in the data."""
    missing_fields = [field for field in required_fields if field not in data or data[field] is None]
    if missing_fields:
        return False, f"Missing required fields: {', '.join(missing_fields)}"
    return True, None


def sanitize_string(text, max_length=None):
    """Sanitize a string to prevent XSS and other injection attacks."""
    if text is None:
        return None

    # Convert to string if not already
    if not isinstance(text, str):
        text = str(text)

    # Clean the text
    cleaned = bleach.clean(text, strip=True)

    # Truncate if needed
    if max_length and len(cleaned) > max_length:
        cleaned = cleaned[:max_length]

    return cleaned


def validate_email(email):
    """Validate email format."""
    if not email:
        return False
    return bool(re.match(EMAIL_PATTERN, email))


def validate_username(username):
    """Validate username format."""
    if not username:
        return False
    return bool(re.match(USERNAME_PATTERN, username))


def validate_password(password):
    """Validate password format - at least 8 chars, 1 letter and 1 number."""
    if not password:
        return False
    return bool(re.match(PASSWORD_PATTERN, password))


def validate_json_data(data):
    """Validate all JSON object keys to prevent injection."""
    if isinstance(data, dict):
        # Check keys
        for k in data.keys():
            if not isinstance(k, str) or not re.match(JSON_FIELDS_PATTERN, k):
                return False, f"Invalid field name: {k}"
        # Recursively check values
        for v in data.values():
            if isinstance(v, (dict, list)):
                valid, message = validate_json_data(v)
                if not valid:
                    return False, message
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, (dict, list)):
                valid, message = validate_json_data(item)
                if not valid:
                    return False, message
    return True, None


def sanitize_json_data(data):
    """Recursively sanitize all strings in a JSON object."""
    if isinstance(data, dict):
        return {k: sanitize_json_data(v) for k, v in data.items() if isinstance(k, str)}
    elif isinstance(data, list):
        return [sanitize_json_data(item) for item in data]
    elif isinstance(data, str):
        return sanitize_string(data)
    else:
        return data


def validate_request_json(required_fields=None):
    """
    Decorator to validate JSON in request.
    Checks if the required fields are present and validates/sanitizes inputs.
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({"msg": "Missing JSON in request"}), 400

            try:
                data = request.get_json()

                # Validate JSON structure
                valid, message = validate_json_data(data)
                if not valid:
                    return jsonify({"msg": message}), 400

                # Check required fields
                if required_fields:
                    valid, message = validate_required_fields(data, required_fields)
                    if not valid:
                        return jsonify({"msg": message}), 400

                # Sanitize all string values
                sanitized_data = sanitize_json_data(data)

                # Replace the request JSON with sanitized data
                request.data = sanitized_data  # noqa

                return f(*args, **kwargs)
            except Exception as e:
                logger.exception(f"Validation error: {str(e)}")
                return jsonify({"msg": "Invalid request data"}), 400

        return decorated_function

    return decorator
