from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Boolean
from . import db


class User(db.Model):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(255), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    is_active = Column(Boolean, default=True)

    def __repr__(self):
        return f'<User {self.username}>'


class TokenBlacklist(db.Model):
    __tablename__ = 'token_blacklist'
    id = Column(Integer, primary_key=True)
    jti = Column(String(36), nullable=False, unique=True)
    token_type = Column(String(10), nullable=False)
    user_id = Column(Integer, nullable=False)
    revoked = Column(Boolean, nullable=False, default=True)
    expires = Column(DateTime, nullable=False)

    def __repr__(self):
        return f'<TokenBlacklist {self.jti}>'
