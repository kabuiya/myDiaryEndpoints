from dotenv import load_dotenv
import os

load_dotenv()


class Config(object):
    DEBUG = False
    CSRF_ENABLED = True
    SECRET_KEY = os.getenv('SECRET_KEY')


class TestingConfig(Config):
    DEBUG = True
    TESTING = True
    DB_NAME = os.getenv('pDB_NAME')
    DB_USER = os.getenv('pDB_USER')
    DB_PASSWORD = os.getenv('pDB_PASSWORD')
    DB_HOST = '127.0.0.1'
    DB_PORT = int(os.getenv('DB_PORT', 5432))


class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    DB_NAME = os.getenv('DB_NAME')
    DB_USER = os.getenv('DB_USER')
    DB_PASSWORD = os.getenv('DB_PASSWORD')
    DB_HOST = os.getenv('DB_HOST')
    DB_PORT = int(os.getenv('DB_PORT', 5433))
