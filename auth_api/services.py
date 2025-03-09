from datetime import datetime, timezone, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt
import logging
from . import db
from .models import User, TokenBlacklist
from .validation_utils import sanitize_string, validate_email, validate_username, validate_password

# Get logger
logger = logging.getLogger('service')


def register_user(data):
    """Register a new user"""
    username = sanitize_string(data.get('username'), 255)
    email = sanitize_string(data.get('email'), 255)
    password = data.get('password')

    # Validate inputs
    if not username or not validate_username(username):
        return {"msg": "Invalid username format. Use only letters, numbers, and underscores."}, 400

    if not email or not validate_email(email):
        return {"msg": "Invalid email format."}, 400

    if not password or not validate_password(password):
        return {"msg": "Password must be at least 8 characters and contain at least one letter and one number."}, 400

    # Check if username already exists
    if User.query.filter_by(username=username).first():
        return {"msg": "Username already exists"}, 409

    # Check if email already exists
    if User.query.filter_by(email=email).first():
        return {"msg": "Email already exists"}, 409

    # Create new user
    hashed_password = generate_password_hash(password)
    new_user = User(
        username=username,
        email=email,
        password=hashed_password,
        created_at=datetime.now(timezone.utc)
    )

    try:
        db.session.add(new_user)
        db.session.commit()
        logger.info(f"User registered successfully: {username}")

        # Generate tokens - Make sure to convert ID to string for JWT
        access_token = create_access_token(identity=str(new_user.id))
        refresh_token = create_refresh_token(identity=str(new_user.id))

        return {
            "msg": "User registered successfully",
            "user": {
                "id": new_user.id,
                "username": new_user.username,
                "email": new_user.email
            },
            "access_token": access_token,
            "refresh_token": refresh_token
        }, 201
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error registering user: {str(e)}")
        return {"msg": "Error registering user"}, 500


def login_user(data):
    """Login a user"""
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        logger.warning(f"Login attempt with missing fields")
        return {"msg": "Username and password required"}, 400

    # Find user by username
    user = User.query.filter_by(username=username).first()

    if not user:
        logger.warning(f"Login attempt with non-existent username: {username}")
        return {"msg": "Invalid credentials"}, 401

    # Check password
    if not check_password_hash(user.password, password):
        logger.warning(f"Login attempt with invalid password for user: {username}")
        return {"msg": "Invalid credentials"}, 401

    # Check if user is active
    if not user.is_active:
        logger.warning(f"Login attempt for inactive user: {username}")
        return {"msg": "Account is deactivated"}, 401

    logger.info(f"Successful login for user: {username}")

    # Generate tokens - Make sure to convert ID to string for JWT
    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))

    return {
        "msg": "Login successful",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email
        },
        "access_token": access_token,
        "refresh_token": refresh_token
    }, 200


def logout_user(jwt_payload):
    """Logout a user by blacklisting their tokens"""
    jti = jwt_payload['jti']
    user_id = jwt_payload['sub']  # This is a string from the token
    token_type = jwt_payload['type']
    expires = datetime.fromtimestamp(jwt_payload['exp'])

    # Convert user_id to integer for database storage
    try:
        user_id_int = int(user_id)
    except ValueError:
        logger.warning(f"Invalid user ID format in token: {user_id}")
        return {"msg": "Invalid user ID"}, 400

    # Add token to blacklist
    blacklist_token = TokenBlacklist(
        jti=jti,
        token_type=token_type,
        user_id=user_id_int,  # Store as integer
        expires=expires
    )

    try:
        db.session.add(blacklist_token)
        db.session.commit()
        logger.info(f"Token blacklisted for user {user_id}")
        return {"msg": "Successfully logged out"}, 200
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error blacklisting token: {str(e)}")
        return {"msg": "Error logging out"}, 500


def refresh_access_token(user_id):
    """Generate a new access token using a refresh token"""
    # The user_id comes as a string from the JWT token
    # Convert to int for database lookup
    try:
        user_id_int = int(user_id)
        # Use db.session.get() instead of the deprecated Query.get()
        user = db.session.get(User, user_id_int)

        if not user:
            logger.warning(f"Token refresh attempt for non-existent user: {user_id}")
            return {"msg": "User not found"}, 404

        if not user.is_active:
            logger.warning(f"Token refresh attempt for inactive user: {user_id}")
            return {"msg": "Account is deactivated"}, 401

        # Generate new access token
        access_token = create_access_token(identity=str(user.id))
        logger.info(f"Access token refreshed for user: {user_id}")

        return {
            "msg": "Token refreshed",
            "access_token": access_token
        }, 200
    except ValueError:
        logger.warning(f"Invalid user ID format in refresh token: {user_id}")
        return {"msg": "Invalid user ID"}, 400


def check_token_in_blacklist(jti):
    """Check if token is in the blacklist"""
    return TokenBlacklist.query.filter_by(jti=jti, revoked=True).first() is not None
