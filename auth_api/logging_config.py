import os
import logging
from flask import request, g
import time
import json
from functools import wraps

# Create logs directory if it doesn't exist
os.makedirs('logs', exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/app.log'),
        logging.StreamHandler()
    ]
)

# Create loggers
request_logger = logging.getLogger('request')
auth_logger = logging.getLogger('auth')
db_logger = logging.getLogger('db')
service_logger = logging.getLogger('service')


def log_request():
    """Log basic details about the incoming request."""
    # Don't log requests for static files
    if request.path.startswith('/static'):
        return

    # Start timer for request duration
    g.start_time = time.time()

    # Log only basic request details, no sensitive content
    request_data = {
        'method': request.method,
        'path': request.path,
        'remote_addr': request.remote_addr,
    }

    request_logger.info(f"Request received: {json.dumps(request_data)}")


def log_response(response):
    """Log minimal details about the outgoing response."""
    # Don't log responses for static files
    if request.path.startswith('/static'):
        return response

    # Calculate request duration
    duration = time.time() - g.get('start_time', time.time())

    # Log minimal response details
    response_data = {
        'status_code': response.status_code,
        'duration_ms': round(duration * 1000, 2)
    }

    log_level = logging.INFO if response.status_code < 400 else logging.ERROR
    request_logger.log(log_level, f"Response sent: {json.dumps(response_data)}")

    return response


def log_function(func):
    """Decorator to log function calls with minimal information (no parameters)."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        # Log function entry without arguments
        service_logger.debug(f"Calling {func.__name__}")

        try:
            # Call the function
            result = func(*args, **kwargs)

            # Log function exit with minimal information
            if isinstance(result, tuple) and len(result) == 2 and isinstance(result[1], int):
                # For functions returning (response, status_code)
                status_code = result[1]
                log_level = logging.INFO if status_code < 400 else logging.ERROR
                service_logger.log(log_level, f"{func.__name__} returned status {status_code}")
            else:
                service_logger.debug(f"{func.__name__} returned successfully")

            return result
        except Exception as e:
            # Log exceptions without sensitive data
            service_logger.exception(f"Exception in {func.__name__}: {str(e)}")
            raise

    return wrapper


def setup_logging(app):
    """Configure logging for the Flask application."""

    # Register before_request handler
    @app.before_request
    def before_request():
        log_request()

    # Register after_request handler
    app.after_request(log_response)

    # Log application startup
    app.logger.info(f"Application started with environment: {app.config['ENV']}")

    return app
