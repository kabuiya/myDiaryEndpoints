
import os


class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'a_default_secret_key_if_not_set_locally')
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    DATABASE_URL = os.getenv('DATABASE_URL')


class TestingConfig(Config):
    DEBUG = True
    DATABASE_URL = os.getenv('TEST_DATABASE_URL', 'sqlite:///test.db')


class ProductionConfig(Config):
    DEBUG = False
