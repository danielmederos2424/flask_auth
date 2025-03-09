from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
from .config import Config

db = SQLAlchemy()
jwt = JWTManager()


def create_app(test_config=None):
    app = Flask(__name__)

    # Load the default configuration
    app.config.from_object(Config)

    # Load the test configuration if passed
    if test_config:
        app.config.update(test_config)

    # Setup CORS
    CORS(app, resources={r"/*": {"origins": app.config.get('CORS_ORIGINS', '*')}})

    # Fix for running behind proxy server
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    # Initialize extensions
    db.init_app(app)
    jwt.init_app(app)

    with app.app_context():
        # Setup logging
        from .logging_config import setup_logging
        setup_logging(app)

        # Register error handlers
        from .error_handlers import register_error_handlers
        register_error_handlers(app)

        # Add security headers
        @app.after_request
        def add_security_headers(response):
            response.headers['Content-Security-Policy'] = "default-src 'self'"
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'SAMEORIGIN'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            return response

        # Import here to avoid circular imports
        from .initialize_db import initialize_database

        # Initialize database with all required structures
        initialize_database()

    from .routes import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    # Log application ready
    app.logger.info("Authentication API is ready to serve requests with enhanced security")

    return app
