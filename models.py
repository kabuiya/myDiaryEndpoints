
# models.py
import psycopg2
from flask import current_app


def get_db_connection():
    db_url = current_app.config.get('DATABASE_URL')

    if not db_url:
        print("Error: DATABASE_URL is not set in Flask configuration.")
        return None

    try:
        conn = psycopg2.connect(db_url)
        return conn
    except psycopg2.Error as e:
        print(f"Database connection failed: {e}")
        return None


def initialize_database():
    """
    Initializes the database connection and creates tables if they don't exist.
    This function will be called within the Flask application context.
    """
    db_url = current_app.config.get('DATABASE_URL')

    if not db_url:
        print("Error: DATABASE_URL is not set in Flask configuration. Cannot initialize database.")
        raise ValueError("DATABASE_URL environment variable is not set.")

    conn = None  # Initialize connection to None
    try:

            conn = psycopg2.connect(db_url)
            cursor = conn.cursor()
            cursor.execute("DROP TABLE IF EXISTS BLACKLIST;")
            cursor.execute("DROP TABLE IF EXISTS ENTRIES;")
            cursor.execute("DROP TABLE IF EXISTS USERS;")
            print("Attempting to create database tables if they do not exist...")

            cursor.execute(
                        '''CREATE TABLE IF NOT EXISTS USERS
                            (ID SERIAL PRIMARY KEY     NOT NULL,
                            USERNAME        VARCHAR(10)    UNIQUE NOT NULL,
                            EMAIL_ADDRESS    TEXT  UNIQUE NOT NULL,
                            PASSWORD_HASH        TEXT NOT NULL
                            );''')
            cursor.execute(
                        '''CREATE TABLE IF NOT EXISTS ENTRIES
                            (ID SERIAL PRIMARY KEY     NOT NULL,
                            CONTENT          TEXT      NOT NULL,
                            DATE             DATE DEFAULT CURRENT_DATE,
                            OWNER         INT      references USERS(ID) ON DELETE CASCADE
                            );''')
            cursor.execute(
                        '''CREATE TABLE IF NOT EXISTS BLACKLIST
                            (TOKEN          TEXT      NOT NULL
                            );''')

            conn.commit()
            cursor.close()

            print("Database initialization complete: Tables checked/created successfully.")

    except psycopg2.Error as e:
        print(f"PostgreSQL connection or query error: {e}")

        raise
    except Exception as e:
        print(f"An unexpected error occurred during database initialization: {e}")
        raise
    finally:
        if conn:
            conn.close()
            print("Database connection closed.")
