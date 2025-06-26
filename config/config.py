
import os


class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'a_default_secret_key_if_not_set_locally')
    FLASK_ENV = os.getenv('FLASK_ENV', 'testing')
    DATABASE_URL = os.getenv('DATABASE_URL')


class TestingConfig(Config):
    DEBUG = True
    DATABASE_URL = os.getenv('TEST_DATABASE_URL', 'postgresql://mydiary_user:your_secure_local_password@localhost'
                                                  ':5432/mydiary_db')


class ProductionConfig(Config):
    DEBUG = False
