from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    jwt_required, create_access_token, create_refresh_token,
    get_jwt_identity, get_jwt
)
from functools import wraps
from datetime import datetime, timedelta
import logging
from . import jwt
from .services import register_user, login_user, logout_user, refresh_access_token, check_token_in_blacklist
from .validation_utils import validate_request_json

# Get logger
jwt_logger = logging.getLogger('auth')
route_logger = logging.getLogger('route')

auth = Blueprint('auth', __name__)


# Rate limiting decorator
def rate_limit(max_requests=30, window=60):
    """
    Simple rate limiting decorator.
    In a production environment, use flask-limiter or a similar library
    """
    from datetime import datetime, timedelta
    from functools import wraps
    from flask import request, jsonify, current_app

    # Store requests by IP
    # In production, use Redis or another distributed cache
    request_history = {}

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Skip rate limiting in test environment
            if current_app.config.get('TESTING', False):
                return f(*args, **kwargs)

            ip = request.remote_addr

            # Initialize if new IP
            if ip not in request_history:
                request_history[ip] = []

            # Clean old requests
            now = datetime.now()
            cutoff = now - timedelta(seconds=window)
            request_history[ip] = [t for t in request_history[ip] if t > cutoff]

            # Check rate limit
            if len(request_history[ip]) >= max_requests:
                return jsonify({"msg": "Rate limit exceeded. Try again later."}), 429

            # Add current request
            request_history[ip].append(now)

            return f(*args, **kwargs)

        return decorated_function

    return decorator


# Register JWT callbacks
@jwt.token_in_blocklist_loader
def token_in_blocklist_callback(jwt_header, jwt_payload):
    """Check if token is in the blacklist"""
    return check_token_in_blacklist(jwt_payload["jti"])


@jwt.unauthorized_loader
def unauthorized_callback(reason):
    jwt_logger.warning(f"Unauthorized request: {reason}")
    return jsonify({"msg": f"Unauthorized: {reason}"}), 401


@jwt.invalid_token_loader
def invalid_token_callback(reason):
    jwt_logger.warning(f"Invalid token: {reason}")
    return jsonify({"msg": f"Invalid token: {reason}"}), 401


@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    jwt_logger.warning(f"Expired token: {jwt_payload}")
    return jsonify({"msg": "Token has expired"}), 401


@jwt.needs_fresh_token_loader
def token_not_fresh_callback(jwt_header, jwt_payload):
    jwt_logger.warning(f"Token not fresh: {jwt_payload}")
    return jsonify({"msg": "Fresh token required"}), 401


@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    jwt_logger.warning(f"Revoked token: {jwt_payload}")
    return jsonify({"msg": "Token has been revoked"}), 401


# Auth routes
@auth.route('/register', methods=['POST'])
@rate_limit(10, 300)  # Lower rate limit for registration
@validate_request_json(required_fields=['username', 'email', 'password'])
def register():
    """Register a new user"""
    route_logger.info("Register endpoint called")
    data = request.get_json()
    response, status = register_user(data)
    return jsonify(response), status


@auth.route('/login', methods=['POST'])
@rate_limit(20, 300)  # Lower rate limit for auth endpoints
@validate_request_json(required_fields=['username', 'password'])
def login():
    """Login a user"""
    route_logger.info("Login endpoint called")
    data = request.get_json()
    response, status = login_user(data)
    return jsonify(response), status


@auth.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Logout a user by blacklisting their tokens"""
    route_logger.info("Logout endpoint called")
    jwt_payload = get_jwt()
    response, status = logout_user(jwt_payload)
    return jsonify(response), status


@auth.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh an access token using a refresh token"""
    route_logger.info("Token refresh endpoint called")
    user_id = get_jwt_identity()
    response, status = refresh_access_token(user_id)
    return jsonify(response), status


@auth.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    """Example protected endpoint requiring authentication"""
    user_id = get_jwt_identity()
    route_logger.info(f"Protected endpoint called by user: {user_id}")
    return jsonify({"msg": "This is a protected endpoint", "user_id": user_id}), 200
