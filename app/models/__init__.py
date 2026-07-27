from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

from app.models.user import User
from app.models.log import Log
from app.models.incident import Incident

__all__ = ['db', 'User', 'Log', 'Incident']
