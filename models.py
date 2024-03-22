import psycopg2
from flask import current_app
import os


def get_db_connection():
    if current_app.config['FLASK_ENV'] == 'testing':
        return psycopg2.connect(
            dbname='circle_test',
            user='postgres',
            password='',
            host='localhost',
            port='5432'

        )
    elif current_app.config['FLASK_ENV'] == 'production':
        return psycopg2.connect(
            dbname=current_app.config.get('DB_NAME'),
            user=current_app.config.get('DB_USER'),
            password=current_app.config.get('DB_PASSWORD'),
            host=current_app.config.get('DB_HOST'),
            port=current_app.config.get('DB_PORT')
        )
    else:
        raise ValueError("Unknown FLASK_ENV")


def initialize_database():
    conn = get_db_connection()
    cur = conn.cursor()
    # USER table
    cur.execute(
        '''CREATE TABLE IF NOT EXISTS USERS
            (ID SERIAL PRIMARY KEY     NOT NULL,
            USERNAME        VARCHAR(10)    UNIQUE NOT NULL,
            EMAIL_ADDRESS    TEXT  UNIQUE NOT NULL,
            PASSWORD_HASH        TEXT NOT NULL
            );''')
    # diary entry table
    cur.execute(
        '''CREATE TABLE IF NOT EXISTS ENTRIES
            (ID SERIAL PRIMARY KEY     NOT NULL,
            CONTENT          TEXT      NOT NULL,
            DATE             DATE DEFAULT CURRENT_DATE,
            OWNER         INT      references USERS(ID) ON DELETE CASCADE
            );''')
    cur.execute(
        '''CREATE TABLE IF NOT EXISTS BLACKLIST
            (TOKEN          TEXT      NOT NULL
            );''')

    conn.commit()

    if current_app.config['FLASK_ENV'] == 'testing':
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            '''
                 DELETE FROM  USERS WHERE USERNAME = %s;
                ''',
            (os.getenv('register_name'),)
        )
        cur.execute(
            '''
                 DELETE FROM  ENTRIES WHERE OWNER = %s;
                ''',
            (os.getenv('owner'),)
        )
    cur.close()  # Close curso  # Close connection
    return conn


