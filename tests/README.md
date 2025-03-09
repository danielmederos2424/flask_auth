# Authentication API Test Suite

This directory contains automated tests for the Authentication API.

## Running Tests

To run all tests:

```bash
pytest
```

To run specific test files:

```bash
pytest tests/test_auth.py
pytest tests/test_validation.py
```

To run with verbose output:

```bash
pytest -v
```

## Test Coverage

These tests cover:

- **Authentication**: User registration, login, logout, and JWT token validation
- **Validation**: Input validation for usernames, emails, passwords, and JSON data
- **Services**: Backend service functions that process authentication requests
- **Security**: Token blacklisting and refresh token functionality

## Test Structure

- `conftest.py`: Contains test fixtures and setup code
- `test_auth.py`: Tests for authentication endpoints
- `test_validation.py`: Tests for validation utilities
- `test_services.py`: Tests for service layer functions

## Prerequisites

Install the required testing packages:

```bash
pip install pytest pytest-flask
```

## Notes

- The tests use an in-memory SQLite database to isolate test data
- Each test runs with a fresh database instance