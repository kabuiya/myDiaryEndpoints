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

    conn = None
    try:
        conn = psycopg2.connect(db_url)
        cursor = conn.cursor()
        print("Attempting to create database tables if they do not exist...")



        cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(80) UNIQUE NOT NULL, -- THIS LINE WAS THE PROBLEM
                        email VARCHAR(120) UNIQUE NOT NULL,
                        password_hash VARCHAR(128) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """)
        cursor.execute("""
                    CREATE TABLE IF NOT EXISTS diary_entries (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER NOT NULL,
                        title VARCHAR(255) NOT NULL,
                        content TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                    );
                """)
        cursor.execute(
                    '''CREATE TABLE IF NOT EXISTS BLACKLIST
                        (TOKEN          TEXT      NOT NULL
                        );''')

        conn.commit()
        cursor.close()

        print("Database initialization complete: Tables checked/created successfully.")

    except psycopg2.Error as e:
        print(f"PostgreSQL connection or query error: {e}")

        if conn:
            conn.rollback()
        raise
    except Exception as e:
        print(f"An unexpected error occurred during database initialization: {e}")
        raise
    finally:
        if conn:
            conn.close()
            print("Database connection closed.")

