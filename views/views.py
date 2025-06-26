from functools import wraps
import datetime
import bcrypt
import jwt
import psycopg2.errors
from flask import request, jsonify, Blueprint, current_app
from flask.cli import load_dotenv
from validate_email import validate_email
from models import get_db_connection

load_dotenv()


views_bp = Blueprint('views', __name__)

def check_blacklist(token):
    """
    Checks if the given JWT token is present in the BLACKLIST table.
    Returns True if blacklisted, False otherwise.
    """
    conn = None
    try:
        conn = get_db_connection()
        if not conn:

            print("Error: Database connection failed in check_blacklist.")
            return True # Treat as blacklisted if DB is unreachable to be safe
        with conn.cursor() as cur:
            cur.execute("SELECT TOKEN FROM BLACKLIST WHERE TOKEN = %s;", (token,))
            return cur.fetchone() is not None
    except Exception as e:
        print(f"Error checking blacklist: {e}")
        return True # On error, assume blacklisted for security
    finally:
        if conn:
            conn.close()


def token_required(funct):
    """
    Decorator to ensure a valid JWT token is provided in the Authorization header.
    Validates the token, checks blacklist, and passes user_id to the decorated function.
    """
    @wraps(funct)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'message': 'Missing authorization token'}), 401
        try:
            token = auth_header.split()[1]
            # Check if token is blacklisted before decoding
            if check_blacklist(token):
                return jsonify({'message': 'Token has expired or been blacklisted'}), 401

            payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            user_id = payload.get('user_id')
            username = payload.get('username') # Although not used here, good to keep
            if not user_id or not username:
                return jsonify({'message': 'Invalid token payload'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        except IndexError:
            return jsonify({'message': 'Token format is incorrect'}), 401
        except Exception as e:
            print(f"Token validation error: {e}")
            return jsonify({'message': 'An error occurred during token validation'}), 500

        return funct(user_id, *args, **kwargs)

    return wrapper


def hashed_pass(plaintext_password):
    """Hashes a plaintext password using bcrypt."""
    salt = bcrypt.gensalt()
    # bcrypt.hashpw expects bytes
    return bcrypt.hashpw(plaintext_password.encode('utf-8'), salt).hex() # Store as hex string


def check_password(plaintext, hashed_password_hex):
    """
    Checks if a given plaintext password matches a stored bcrypt hash.
    The stored hash is assumed to be a hex string.
    """
    try:

        hashed_password_bytes = bytes.fromhex(hashed_password_hex)
        return bcrypt.checkpw(plaintext.encode('utf-8'), hashed_password_bytes)
    except Exception as e:
        print(f"Error checking password: {e}")
        return False # Return False on any error during password check


@views_bp.route("/api/v1/register", methods=['POST'])
def user_registration():
    """Register a new user."""
    data = request.get_json()

    email = data.get('email')
    username = data.get('username')
    password = data.get('password')

    required = ['email', 'username', 'password'] # Updated required fields
    if not all(data.get(key) for key in required): # Check if all required fields have values
        return jsonify({'error': 'All fields (email, username, password) are required'}), 400

    if not validate_email(email):
        return jsonify({'error': 'Invalid email address'}), 400

    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500

        with conn.cursor() as cur:
            # Check if email already exists (using 'email' column name)
            cur.execute('SELECT COUNT(*) FROM users WHERE email = %s', (email,))
            if cur.fetchone()[0] > 0:
                return jsonify({'error': 'Email already exists'}), 400

            # Check if username already exists
            cur.execute('SELECT COUNT(*) FROM users WHERE username = %s', (username,))
            if cur.fetchone()[0] > 0:
                return jsonify({'error': 'Username already exists'}), 400

            # Insert new user (using 'email' column name)
            cur.execute('''
                INSERT INTO users (username, email, password_hash)
                VALUES (%s, %s, %s)
            ''', (username, email, hashed_pass(password)))
            conn.commit()
            return jsonify({'message': 'Registration successful'}), 201 # Changed to 201 for resource creation
    except psycopg2.errors.StringDataRightTruncation:
        if conn: conn.rollback()
        return jsonify({'error': 'Input data too long for one of the fields (e.g., username or email)'}), 400
    except psycopg2.errors.UniqueViolation as e:
        if conn: conn.rollback()
        # This catches duplicate key errors more generically, though specific checks above are good
        return jsonify({'error': 'Username or email already exists'}), 409 # Conflict status code
    except Exception as e:
        if conn: conn.rollback()
        print(f"An unexpected error occurred during registration: {e}")
        return jsonify({'error': f'An unexpected error occurred: {e}'}), 500
    finally:
        if conn:
            conn.close()


@views_bp.route("/api/v1/login", methods=['POST'])
def login():
    """Authenticates user and issues JWT."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500

        with conn.cursor() as cur:
            # Fetch user by username
            cur.execute('SELECT id, password_hash, username FROM users WHERE username = %s', (username,))
            user = cur.fetchone()
            if not user:
                return jsonify({'error': 'User does not exist'}), 400

            user_id, hashed_pw_hex, retrieved_username = user # Unpack all fetched values

            # Check password
            if not check_password(password, hashed_pw_hex):
                return jsonify({'error': 'Incorrect password'}), 400

            # Generate JWT
            token = jwt.encode({
                'user_id': user_id,
                'username': retrieved_username, # Use username from DB
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
            }, current_app.config['SECRET_KEY'], algorithm='HS256') # Specify algorithm

            return jsonify({'message': 'Login successful', 'token': token}), 200
    except Exception as e:
        print(f"An unexpected error occurred during login: {e}")
        return jsonify({'error': f'An unexpected error occurred: {e}'}), 500
    finally:
        if conn:
            conn.close()


@views_bp.route("/api/v1/logout", methods=['POST'])
@token_required
def user_logout(user_id): # user_id is passed by the decorator but not used in logout logic
    """Blacklists the JWT token."""
    token = None
    auth_header = request.headers.get('Authorization')
    if auth_header and len(auth_header.split()) > 1:
        token = auth_header.split()[1]

    if not token:
        return jsonify({'message': 'No token provided for logout'}), 400

    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500

        with conn.cursor() as cur:
            cur.execute("INSERT INTO BLACKLIST (TOKEN) VALUES (%s)", (token,))
        conn.commit()
        return jsonify({'message': 'Successfully logged out'}), 200
    except Exception as e:
        if conn: conn.rollback()
        print(f"Error during logout: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()


@views_bp.route("/api/v1/profile", methods=['GET'])
@token_required
def user_profile(user_id):
    """Gets current user's profile."""
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500

        with conn.cursor() as cur:
            # Select 'email' directly
            cur.execute('SELECT email, username FROM users WHERE id = %s', (user_id,))
            user = cur.fetchone()
            if not user:
                return jsonify({'error': 'User not found'}), 404
            # Return 'email' in the response
            return jsonify({'email': user[0], 'username': user[1]}), 200
    except Exception as e:
        print(f"Error fetching user profile: {e}")
        return jsonify({'error': f'An unexpected error occurred: {e}'}), 500
    finally:
        if conn:
            conn.close()


@views_bp.route("/api/v1/profile/update", methods=['PUT'])
@token_required
def update_profile(user_id):
    """Updates profile for authenticated user."""
    data = request.get_json()
    email = data.get('email') # Changed from email_address to email
    username = data.get('username')

    if not username or not email or not validate_email(email):
        return jsonify({'error': 'Valid username and email are required'}), 400

    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500

        with conn.cursor() as cur:
            # Check for duplicate username excluding current user
            cur.execute('SELECT COUNT(*) FROM users WHERE username = %s AND id != %s', (username, user_id))
            if cur.fetchone()[0] > 0:
                return jsonify({'error': 'Username already taken'}), 400

            # Check for duplicate email excluding current user (using 'email' column name)
            cur.execute('SELECT COUNT(*) FROM users WHERE email = %s AND id != %s', (email, user_id))
            if cur.fetchone()[0] > 0:
                return jsonify({'error': 'Email already in use'}), 400

            # Update user profile (using 'email' column name)
            cur.execute('UPDATE users SET username = %s, email = %s WHERE id = %s',
                        (username, email, user_id))
            conn.commit()
            return jsonify({'message': 'Profile updated successfully'}), 200
    except Exception as e:
        if conn: conn.rollback()
        print(f"Error updating profile: {e}")
        return jsonify({'error': f'An unexpected error occurred: {e}'}), 500
    finally:
        if conn:
            conn.close()


@views_bp.route("/api/v1/del_account", methods=['DELETE'])
@token_required
def account_delete(user_id):
    """Deletes the current user's account."""
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        with conn.cursor() as cur:
            cur.execute('DELETE FROM users WHERE id = %s', (user_id,))
            conn.commit()
        return jsonify({'message': 'Account deleted successfully'}), 200
    except Exception as e:
        if conn: conn.rollback()
        print(f"Error deleting account: {e}")
        return jsonify({'error': f'An unexpected error occurred: {e}'}), 500
    finally:
        if conn:
            conn.close()


@views_bp.route("/api/v1/add_entries", methods=['POST'])
@token_required
def post_entries(user_id):
    """Adds a diary entry."""
    data = request.get_json()
    title = data.get('title') # Added title based on schema
    content = data.get('content')

    if not title or not content: # Title is now required
        return jsonify({'error': 'Title and content are required'}), 400

    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500

        with conn.cursor() as cur:
            # Updated INSERT statement for diary_entries
            cur.execute('INSERT INTO diary_entries (user_id, title, content) VALUES (%s, %s, %s) RETURNING id',
                        (user_id, title, content))
            entry_id = cur.fetchone()[0]
            conn.commit()
        return jsonify({'message': 'Entry added', 'entry_id': entry_id}), 201 # 201 Created
    except Exception as e:
        if conn: conn.rollback()
        print(f"Error adding entry: {e}")
        return jsonify({'error': f'An unexpected error occurred: {e}'}), 500
    finally:
        if conn:
            conn.close()


@views_bp.route("/api/v1/get_entries", methods=['GET'])
@token_required
def get_entries(user_id):
    """Gets all diary entries for the authenticated user."""
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500

        with conn.cursor() as cur:
            # Updated SELECT to match diary_entries columns
            cur.execute('SELECT id, title, content, created_at, updated_at FROM diary_entries WHERE user_id = %s '
                        'ORDER BY created_at DESC', (user_id,))
            entries_data = cur.fetchall()

        # Format entries into a list of dictionaries for better JSON output
        entries_list = []
        for entry in entries_data:
            entries_list.append({
                'id': entry[0],
                'title': entry[1],
                'content': entry[2],
                'created_at': entry[3].isoformat() if entry[3] else None, # Format datetime to ISO string
                'updated_at': entry[4].isoformat() if entry[4] else None
            })
        return jsonify({'entries': entries_list}), 200
    except Exception as e:
        print(f"Error retrieving entries: {e}")
        return jsonify({'error': f'An unexpected error occurred: {e}'}), 500
    finally:
        if conn:
            conn.close()


@views_bp.route("/api/v1/get_entry/<int:entry_id>", methods=['GET'])
@token_required
def get_entry(user_id, entry_id):
    """Gets a specific diary entry."""
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500

        with conn.cursor() as cur:
            # Select specific entry by ID and user_id
            cur.execute('SELECT id, title, content, created_at, updated_at FROM diary_entries WHERE id = %s AND '
                        'user_id = %s', (entry_id, user_id))
            entry = cur.fetchone()
            if not entry:
                return jsonify({'message': 'Entry not found or unauthorized'}), 404

            # Format the single entry
            formatted_entry = {
                'id': entry[0],
                'title': entry[1],
                'content': entry[2],
                'created_at': entry[3].isoformat() if entry[3] else None,
                'updated_at': entry[4].isoformat() if entry[4] else None
            }
            return jsonify({'entry': formatted_entry}), 200
    except Exception as e:
        print(f"Error retrieving specific entry: {e}")
        return jsonify({'error': f'An unexpected error occurred: {e}'}), 500
    finally:
        if conn:
            conn.close()


@views_bp.route("/api/v1/update_entry/<int:entry_id>", methods=['PUT'])
@token_required
def update_entry(user_id, entry_id):
    """Updates a specific diary entry."""
    data = request.get_json()
    title = data.get('title') # Added title
    content = data.get('content')

    if not title or not content:
        return jsonify({'error': 'Title and content are required'}), 400

    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500

        with conn.cursor() as cur:
            # Check if entry exists and belongs to the user
            cur.execute('SELECT COUNT(*) FROM diary_entries WHERE id = %s AND user_id = %s', (entry_id, user_id))
            if cur.fetchone()[0] == 0:
                return jsonify({'message': 'Entry not found or unauthorized'}), 404

            # Update content and updated_at timestamp
            cur.execute('UPDATE diary_entries SET title = %s, content = %s, updated_at = CURRENT_TIMESTAMP WHERE id = '
                        '%s', (title, content, entry_id))
            conn.commit()
        return jsonify({'message': 'Entry updated successfully'}), 200
    except Exception as e:
        if conn: conn.rollback()
        print(f"Error updating entry: {e}")
        return jsonify({'error': f'An unexpected error occurred: {e}'}), 500
    finally:
        if conn:
            conn.close()


@views_bp.route("/api/v1/delete_entry/<int:entry_id>", methods=['DELETE'])
@token_required
def delete_entry(user_id, entry_id):
    """Deletes a diary entry."""
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500

        with conn.cursor() as cur:
            # Check if entry exists and belongs to the user
            cur.execute('SELECT COUNT(*) FROM diary_entries WHERE id = %s AND user_id = %s', (entry_id, user_id))
            if cur.fetchone()[0] == 0:
                return jsonify({'message': 'Entry not found or unauthorized'}), 404

            # Delete the entry
            cur.execute('DELETE FROM diary_entries WHERE id = %s', (entry_id,))
            conn.commit()
        return jsonify({'message': 'Entry deleted successfully'}), 200
    except Exception as e:
        if conn: conn.rollback()
        print(f"Error deleting entry: {e}")
        return jsonify({'error': f'An unexpected error occurred: {e}'}), 500
    finally:
        if conn:
            conn.close()

