import logging
from flask import jsonify, request
from werkzeug.exceptions import HTTPException
from jwt.exceptions import PyJWTError, InvalidTokenError
from flask_jwt_extended.exceptions import JWTExtendedException

# Get logger
logger = logging.getLogger('error')


def register_error_handlers(app):
    """Register error handlers for the application."""

    @app.errorhandler(400)
    def handle_bad_request(e):
        logger.warning(f"400 Bad Request: {str(e)}")
        return jsonify({"msg": str(e) or "Bad request"}), 400

    @app.errorhandler(401)
    def handle_unauthorized(e):
        logger.warning(f"401 Unauthorized: {str(e)}")
        return jsonify({"msg": str(e) or "Unauthorized"}), 401

    @app.errorhandler(403)
    def handle_forbidden(e):
        logger.warning(f"403 Forbidden: {str(e)}")
        return jsonify({"msg": str(e) or "Forbidden"}), 403

    @app.errorhandler(404)
    def handle_not_found(e):
        logger.warning(f"404 Not Found: {str(e)}")
        return jsonify({"msg": str(e) or "Resource not found"}), 404

    @app.errorhandler(429)
    def handle_too_many_requests(e):
        logger.warning(f"429 Too Many Requests: {str(e)}")
        return jsonify({"msg": str(e) or "Too many requests"}), 429

    @app.errorhandler(500)
    def handle_server_error(e):
        logger.error(f"500 Server Error: {str(e)}")
        return jsonify({"msg": "Internal server error"}), 500

    @app.errorhandler(JWTExtendedException)
    def handle_jwt_extended_error(e):
        logger.warning(f"JWT Error: {str(e)}")
        return jsonify({"msg": str(e)}), 401

    @app.errorhandler(PyJWTError)
    def handle_pyjwt_error(e):
        logger.warning(f"PyJWT Error: {str(e)}")
        return jsonify({"msg": "Invalid token"}), 401

    @app.errorhandler(InvalidTokenError)
    def handle_invalid_token_error(e):
        logger.warning(f"Invalid Token Error: {str(e)}")
        return jsonify({"msg": "Invalid token"}), 401

    @app.errorhandler(Exception)
    def handle_generic_exception(e):
        if isinstance(e, HTTPException):
            logger.warning(f"HTTP Exception {e.code}: {str(e)}")
            return jsonify({"msg": str(e)}), e.code

        logger.exception(f"Unhandled Exception: {str(e)}")
        return jsonify({"msg": "An unexpected error occurred"}), 500
