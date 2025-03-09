# Flask Authentication API

A simple and secure Flask API for user authentication with JWT tokens.

## Features

- User registration and login
- JWT-based authentication
- Token refresh functionality
- Logout with token blacklisting
- Input validation and sanitization
- Rate limiting
- Comprehensive error handling
- Logging
- Secure password hashing
- Security headers

## Getting Started

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Installation

1. Clone this repository:
   ```bash
   git clone <repository-url>
   cd flask-auth-api
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up environment variables (optional):
   ```bash
   cp .env.example .env
   # Edit .env file with your configuration
   ```

### Running the API

```bash
python run.py
```

The API will be available at http://localhost:5000

## API Endpoints

### Authentication

- `POST /register` - Register a new user
  - Request: `{ "username": "user", "email": "user@example.com", "password": "Password123" }`
  - Response: `{ "msg": "User registered successfully", "user": {...}, "access_token": "...", "refresh_token": "..." }`

- `POST /login` - Login a user
  - Request: `{ "username": "user", "password": "Password123" }`
  - Response: `{ "msg": "Login successful", "user": {...}, "access_token": "...", "refresh_token": "..." }`

- `POST /logout` - Logout a user (requires authentication)
  - Response: `{ "msg": "Successfully logged out" }`

- `POST /refresh` - Refresh an access token (requires refresh token)
  - Response: `{ "msg": "Token refreshed", "access_token": "..." }`

### Example Protected Endpoint

- `GET /protected` - Example protected endpoint (requires authentication)
  - Response: `{ "msg": "This is a protected endpoint", "user_id": 1 }`

## Authentication

Authentication is required for protected endpoints. Include the JWT token in the Authorization header:

```
Authorization: Bearer <your-jwt-token>
```

## Validation Rules

- **Username**: Alphanumeric characters and underscores only
- **Email**: Standard email format
- **Password**: At least 8 characters, including at least one letter and one number

## Running Tests

```bash
pytest
```

For more details, see [tests/README.md](tests/README.md)

## Deployment

For production deployment:

1. Use a production WSGI server like Gunicorn:
   ```bash
   pip install gunicorn
   gunicorn 'auth_api:create_app()'
   ```

2. Set secure values for environment variables:
   - `SECRET_KEY`
   - `JWT_SECRET_KEY`
   - `DATABASE_URL` (for a production database)

3. Consider using a reverse proxy like Nginx

## Built With

- [Flask](https://flask.palletsprojects.com/) - Web framework
- [Flask-JWT-Extended](https://flask-jwt-extended.readthedocs.io/) - JWT authentication
- [SQLAlchemy](https://www.sqlalchemy.org/) - Database ORM
- [Werkzeug](https://werkzeug.palletsprojects.com/) - Utilities

## License

This project is licensed under the MIT License - see the LICENSE file for details