from functools import wraps
import datetime
import bcrypt
import jwt
import psycopg2.errors
from flask import request, jsonify, Blueprint, current_app
from flask.cli import load_dotenv
from validate_email import validate_email
from models import initialize_database, get_db_connection

load_dotenv()
views_bp = Blueprint('views', __name__)


# ------------------------- TOKEN UTILITIES -------------------------

def check_blacklist(token):
    """Check if the JWT token is blacklisted."""
    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute("SELECT TOKEN FROM BLACKLIST WHERE TOKEN = %s;", (token,))
        return cur.fetchone() is not None


def token_required(funct):
    """JWT auth decorator with token validation and user extraction."""

    @wraps(funct)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'message': 'Missing authorization token'}), 401
        try:
            token = auth_header.split()[1]
            if check_blacklist(token):
                return jsonify({'message': 'Token has expired or been blacklisted'}), 401
            payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            user_id = payload.get('user_id')
            username = payload.get('username')
            if not user_id or not username:
                return jsonify({'message': 'Invalid token payload'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        return funct(user_id, *args, **kwargs)

    return wrapper


def hashed_pass(plaintext_password):
    """Hash plaintext password using bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(plaintext_password.encode('utf-8'), salt)


def check_password(plaintext, hashed_password_hex):
    """Check if given plaintext matches stored bcrypt hash."""
    hashed_password_bytes = bytes.fromhex(hashed_password_hex[2:])
    return bcrypt.checkpw(plaintext.encode('utf-8'), hashed_password_bytes)


# ------------------------- AUTHENTICATION -------------------------

@views_bp.route("/api/v1/register", methods=['POST'])
def user_registration():
    """Register a new user."""
    data = request.get_json()
    required = ['email_address', 'username', 'password']
    if not all(key in data and data[key] for key in required):
        return jsonify({'error': 'All fields are required'}), 400

    email = data['email_address']
    username = data['username']
    password = data['password']

    if not validate_email(email):
        return jsonify({'error': 'Invalid email address'}), 400

    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute('SELECT COUNT(*) FROM USERS WHERE EMAIL_ADDRESS = %s', (email,))
        if cur.fetchone()[0] > 0:
            return jsonify({'error': 'Email already exists'}), 400

        cur.execute('SELECT COUNT(*) FROM USERS WHERE USERNAME = %s', (username,))
        if cur.fetchone()[0] > 0:
            return jsonify({'error': 'Username already exists'}), 400

        try:
            cur.execute('''
                INSERT INTO USERS (USERNAME, EMAIL_ADDRESS, PASSWORD_HASH)
                VALUES (%s, %s, %s)
            ''', (username, email, hashed_pass(password)))
            conn.commit()
            return jsonify({'message': 'Registration successful'}), 200
        except psycopg2.errors.StringDataRightTruncation:
            return jsonify({'error': 'Username is too long'}), 400


@views_bp.route("/api/v1/login", methods=['POST'])
def login():
    """Authenticate user and issue JWT."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute('SELECT ID, PASSWORD_HASH, USERNAME FROM USERS WHERE USERNAME = %s', (username,))
        user = cur.fetchone()
        if not user:
            return jsonify({'error': 'User does not exist'}), 400
        user_id, hashed_pw, _ = user

        if not check_password(password, hashed_pw):
            return jsonify({'error': 'Incorrect password'}), 400

        token = jwt.encode({
            'user_id': user_id,
            'username': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }, current_app.config['SECRET_KEY'])

        return jsonify({'message': 'Login successful', 'token': token}), 200


@views_bp.route("/api/v1/logout", methods=['POST'])
@token_required
def user_logout(user_id):
    """Blacklist the JWT token."""
    token = request.headers.get('Authorization').split()[1]
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO BLACKLIST (TOKEN) VALUES (%s)", (token,))
        conn.commit()
        return jsonify({'message': 'Successfully logged out'}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500


# ------------------------- PROFILE -------------------------

@views_bp.route("/api/v1/profile", methods=['GET'])
@token_required
def user_profile(user_id):
    """Get current user's profile."""
    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute('SELECT EMAIL_ADDRESS, USERNAME FROM USERS WHERE ID = %s', (user_id,))
        user = cur.fetchone()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        return jsonify({'email_address': user[0], 'username': user[1]}), 200


@views_bp.route("/api/v1/profile/update", methods=['PUT'])
@token_required
def update_profile(user_id):
    """Update profile for authenticated user."""
    data = request.get_json()
    email = data.get('email_address')
    username = data.get('username')

    if not username or not email or not validate_email(email):
        return jsonify({'error': 'Valid username and email are required'}), 400

    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute('SELECT COUNT(*) FROM USERS WHERE USERNAME = %s AND ID != %s', (username, user_id))
        if cur.fetchone()[0] > 0:
            return jsonify({'error': 'Username already taken'}), 400

        cur.execute('SELECT COUNT(*) FROM USERS WHERE EMAIL_ADDRESS = %s AND ID != %s', (email, user_id))
        if cur.fetchone()[0] > 0:
            return jsonify({'error': 'Email already in use'}), 400

        cur.execute('UPDATE USERS SET USERNAME = %s, EMAIL_ADDRESS = %s WHERE ID = %s',
                    (username, email, user_id))
        conn.commit()
        return jsonify({'message': 'Profile updated successfully'}), 200


@views_bp.route("/api/v1/del_account", methods=['DELETE'])
@token_required
def account_delete(user_id):
    """Delete the current user's account."""
    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute('DELETE FROM USERS WHERE ID = %s', (user_id,))
        conn.commit()
    return jsonify({'message': 'Account deleted'}), 200


# ------------------------- ENTRIES -------------------------

@views_bp.route("/api/v1/add_entries", methods=['POST'])
@token_required
def post_entries(user_id):
    """Add a diary entry."""
    data = request.get_json()
    content = data.get('content')
    if not content:
        return jsonify({'error': 'Content is required'}), 400

    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute('INSERT INTO ENTRIES (CONTENT, OWNER) VALUES (%s, %s) RETURNING ID',
                    (content, user_id))
        entry_id = cur.fetchone()[0]
        conn.commit()
    return jsonify({'message': 'Entry added', 'entry_id': entry_id}), 200


@views_bp.route("/api/v1/get_entries", methods=['GET'])
@token_required
def get_entries(user_id):
    """Get all entries for the authenticated user."""
    conn = initialize_database()
    with conn.cursor() as cur:
        cur.execute('SELECT ID, CONTENT, ENTRY_DATE FROM ENTRIES WHERE OWNER = %s', (user_id,))
        entries = cur.fetchall()
    return jsonify({'entries': entries}), 200


@views_bp.route("/api/v1/get_entry/<int:entry_id>", methods=['GET'])
@token_required
def get_entry(user_id, entry_id):
    """Get a specific diary entry."""
    conn = initialize_database()
    with conn.cursor() as cur:
        cur.execute('SELECT * FROM ENTRIES WHERE ID = %s AND OWNER = %s', (entry_id, user_id))
        entry = cur.fetchone()
        if not entry:
            return jsonify({'message': 'Entry not found'}), 404
        return jsonify({'entry': {
            'id': entry[0],
            'content': entry[1],
            'date': entry[2],
            'owner': entry[3]
        }}), 200


@views_bp.route("/api/v1/update_entry/<int:entry_id>", methods=['PUT'])
@token_required
def update_entry(user_id, entry_id):
    """Update a specific diary entry."""
    data = request.get_json()
    content = data.get('content')
    if not content:
        return jsonify({'error': 'Content is required'}), 400

    conn = initialize_database()
    with conn.cursor() as cur:
        cur.execute('SELECT COUNT(*) FROM ENTRIES WHERE ID = %s AND OWNER = %s', (entry_id, user_id))
        if cur.fetchone()[0] == 0:
            return jsonify({'message': 'Entry not found or unauthorized'}), 404
        cur.execute('UPDATE ENTRIES SET CONTENT = %s WHERE ID = %s', (content, entry_id))
        conn.commit()
    return jsonify({'message': 'Entry updated'}), 200


@views_bp.route("/api/v1/delete_entry/<int:entry_id>", methods=['DELETE'])
@token_required
def delete_entry(user_id, entry_id):
    """Delete a diary entry."""
    conn = initialize_database()
    with conn.cursor() as cur:
        cur.execute('SELECT COUNT(*) FROM ENTRIES WHERE ID = %s AND OWNER = %s', (entry_id, user_id))
        if cur.fetchone()[0] == 0:
            return jsonify({'message': 'Entry not found or unauthorized'}), 404
        cur.execute('DELETE FROM ENTRIES WHERE ID = %s', (entry_id,))
        conn.commit()
    return jsonify({'message': 'Entry deleted'}), 200
