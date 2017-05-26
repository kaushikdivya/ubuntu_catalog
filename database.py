from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy.engine.url import URL

import settings


def db_connect():
    """Perform database connection using databse settings from settings.py
    Returns sqlalchemy engine instance"""
    engine = create_engine(URL(**settings.DATABASE))
    return engine


def create_base(engine):
    Base = declarative_base()
    Base.metadata.bind = engine
    return Base





