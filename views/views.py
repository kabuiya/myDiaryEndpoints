from functools import wraps
import datetime
import bcrypt
import jwt
import psycopg2.errors
from flask import request, jsonify, Blueprint, current_app
from flask.cli import load_dotenv
from validate_email import validate_email
from models import initialize_database

load_dotenv()
views_bp = Blueprint('views', __name__)


# blacklisted token
def check_blacklist(token):
    """
    checking if the token is blacklisted.
    :param token:
    :return: return none if the token is not in blacklist
    """

    conn = initialize_database()
    with conn.cursor() as cur:
        cur.execute("SELECT TOKEN FROM BLACKLIST WHERE TOKEN = %s;", (token,))
        tkn = cur.fetchone()
        return tkn is not None


# authorization middleware
def token_required(funct):
    """
        A decorator function to ensure that a valid JWT token is present in the request headers.

        This decorator extracts the JWT token from the 'Authorization' header,
        decodes and verifies it, and then passes the extracted user_id to the
        decorated function.

        Args:
            funct (callable): The function to be decorated.

        Returns:
            callable: The wrapped function.

        Raises:
            jwt.ExpiredSignatureError: If the token has expired.
            jwt.InvalidTokenError: If the token is invalid.

        Returns:
            Response: JSON response indicating the success or failure of the token validation.

        """

    @wraps(funct)
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Missing authorization token'}), 401

        try:
            token = token.split()[1]
            payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            user_id = payload.get('user_id')  # Extract user_id from the JWT payload
            user_name = payload.get('username')
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        if user_id is None or user_name is None:
            return jsonify({'message': 'Unauthorized access'}), 401
        if check_blacklist(request.headers.get('Authorization').split()[1]):
            return jsonify({'message': 'Token has already expired, please log in again'})
        return funct(user_id, *args, **kwargs)  # Pass user_id to the wrapped function

    return wrapper


@views_bp.route("/api/v1/register", methods=['POST'])
def user_registration():
    """
      Register a new user.

      This endpoint handles user registration by accepting a JSON payload with
      the user's email address, username, and password. It checks if the email
      and username are unique in the database and if the email address is valid.
      If all conditions are met, the user is added to the database with a hashed
      password.

      Returns:
          Response: A JSON response indicating the success or failure of the registration process.

      Raises:
          ValueError: If the JSON payload is missing any required fields.
      """

    data = request.get_json()
    if 'email_address' in data and 'username' in data and 'password' in data:
        if (data.get('email_address') != '') and (data.get('username') != '') and (data.get('password') != ''):
            email = data['email_address']
            username = data['username']
            plaintext_password = data['password']

            # Get database connection
            conn = initialize_database()
            cur = conn.cursor()

            try:

                # Check if email already exists in db
                cur.execute('''SELECT COUNT(*) FROM USERS WHERE EMAIL_ADDRESS = %s''', (email,))
                email_exists = cur.fetchone()[0] > 0

                # Check if username already exists in the database
                cur.execute('''SELECT COUNT(*) FROM USERS WHERE USERNAME = %s''', (username,))
                username_exists = cur.fetchone()[0] > 0

                if email_exists and username_exists:
                    return jsonify({'error': {'details': 'username and email already exist'}}), 400
                elif username_exists:
                    return jsonify({'error': {'username': 'username already exists'}}), 400
                elif email_exists:
                    return jsonify({'error': {'email': 'email already exists'}}), 400

                elif validate_email(email):
                    hashed_password = hashed_pass(plaintext_password)
                    # Add user to db
                    cur.execute('''INSERT INTO USERS (USERNAME, EMAIL_ADDRESS, PASSWORD_HASH)
                                    VALUES (%s, %s, %s)''', (username, email, hashed_password))
                    conn.commit()
                    return jsonify({'message': {'success': 'Registration successful'}}), 200
                else:
                    return jsonify({'error': {'email': 'Invalid email address'}}), 400
            except psycopg2.errors.StringDataRightTruncation:
                return jsonify({'error': {'username': 'Username is too long'}}), 400
            finally:
                # Close cursor and connection
                cur.close()
                conn.close()
        return jsonify({'error': {'details': 'cannot use null values'}}), 400
    return jsonify({'error': {'details': 'All fields must be filled'}}), 400


def hashed_pass(plaintext_password):
    """
        Hashes the given plaintext password using bcrypt.

        This func takes a plaintext password as input, generates a salt using bcrypt,
        and then hashes the password using the salt. The resulting hashed password is returned.

        Args:
            plaintext_password (str): The plaintext password to be hashed.

        Returns:
            bytes: The hashed password as a bytes object.

        """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(plaintext_password.encode('utf-8'), salt)
    return hashed_password


@views_bp.route("/api/v1/login", methods=['POST'])
def login():
    """
     Log in a user.

     This endpoint handles user login by accepting a JSON payload with the user's
     username and password. It checks if the username exists in the database, verifies
     the password, and generates a JWT token if the credentials are valid.

     Returns:
         Response: A JSON response indicating the success or failure of the login process.

     """

    data = request.get_json()

    if 'username' in data and 'password' in data:
        if (data.get('username') != '') and (data.get('password') != ''):
            username = data['username']
            password = data['password']
            conn = initialize_database()  # Establish database connection
            with conn.cursor() as cur:
                cur.execute(
                    '''
                    SELECT ID, PASSWORD_HASH, USERNAME FROM USERS WHERE USERNAME = %s;
                     ''',
                    (username,)
                )
                user_data = cur.fetchone()
                if user_data:
                    user_id, hashed_password, username = user_data
                    if check_password(password, hashed_password):
                        token = jwt.encode(
                            {'user_id': user_id, 'username': username,
                             'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
                            current_app.config['SECRET_KEY'])
                        return jsonify({'message': {'success': 'successfully, logged in', 'token': token}}), 200
                        # return jsonify({'success': 'successfully, logged in', 'token': token}), 200
                    return jsonify({'Error': {'password': 'wrong password'}}), 400
                return jsonify({'Error': {'details': 'user doesnt exist'}}), 400
        return jsonify({'Error': {'details': 'username and password are required'}}), 400
    return jsonify({'Error': {'details': 'login details cannot be empty'}}), 400


def check_password(passwd, hashed_password_hex):
    hashed_password_bytes = bytes.fromhex(hashed_password_hex[2:])
    return bcrypt.checkpw(passwd.encode('utf-8'), hashed_password_bytes)


@views_bp.route("/api/v1/logout", methods=['POST'])
@token_required
def user_logout(user_id):
    """
        Log out a user.

        This endpoint handles user logout by blacklisting the JWT token used for authentication.
        The token is added to the blacklist table in the database to prevent further usage.

        Args:
            user_id (int): The ID of the user whose token is being blacklisted.

        Returns:
            Response: A JSON response indicating the success or failure of the logout process.

        Raises:
            DatabaseError: If an error occurs while interacting with the database.

        """
    # Get database connection
    conn = initialize_database()
    try:
        with conn.cursor() as curr:
            # Insert the blacklisted token
            curr.execute(
                '''
                INSERT INTO BLACKLIST (TOKEN)
                VALUES (%s)
                ''',
                (request.headers.get('Authorization').split()[1],)
            )
        # Commit the transaction
        conn.commit()
        # Return success response
        return jsonify({'message': 'successfully logged out'}), 200
    except Exception as e:
        # Handle database errors
        conn.rollback()  # Rollback transaction in case of error
        return jsonify({'error': str(e)}), 500


@views_bp.route("/api/v1/profile", methods=['GET'])
@token_required
def user_profile(user_id):
    """
        Retrieve user profile details.

        This endpoint retrieves the profile details (email address and username) of the authenticated user
        identified by the provided user ID.

        Args:
            user_id (int): The ID of the authenticated user.

        Returns:
            Response: A JSON response containing the user's profile details.

        """
    conn = initialize_database()
    with conn.cursor() as cur:
        cur.execute(
            '''
            SELECT EMAIL_ADDRESS, USERNAME FROM USERS WHERE ID = %s;
             ''',
            (user_id,)
        )
        user_data = cur.fetchone()
        cur.close()
        conn.close()
    return jsonify({'details': user_data})


@views_bp.route("/api/v1/profile/update", methods=['PUT'])
@token_required
def update_profile(user_id):
    """
        Update user profile details.

        This endpoint updates the profile details (username and email address) of the authenticated user
        identified by the provided user ID. The updated details are provided in a JSON payload in the PUT request.

        Args:
            user_id (int): The ID of the authenticated user.

        Returns:
            Response: A JSON response indicating the success or failure of the profile update process.

        """
    data = request.get_json()
    if data:
        if 'username' in data and 'email_address' in data and validate_email(data['email_address']):
            if data['username'] != '' and data['email_address'] != '':
                email = data['email_address']
                username = data['username']

                # Get database connection
                conn = initialize_database()
                cur = conn.cursor()

                try:
                    # Check if the new username already exists for other users
                    cur.execute('''SELECT COUNT(*) FROM USERS WHERE USERNAME = %s AND ID != %s''', (username, user_id,))
                    username_exists = cur.fetchone()[0] > 0

                    if username_exists:
                        return jsonify({'error': 'username already exists'}), 400

                    # Check if the new email address already exists for other users
                    cur.execute('''SELECT COUNT(*) FROM USERS WHERE EMAIL_ADDRESS = %s AND ID != %s''',
                                (email, user_id))
                    email_exists = cur.fetchone()[0] > 0

                    if email_exists:
                        return jsonify({'error': 'email already exists'}), 400

                    # Update user profile
                    cur.execute('''UPDATE USERS SET USERNAME = %s, EMAIL_ADDRESS = %s WHERE ID = %s''',
                                (username, email, user_id,))
                    conn.commit()

                    return jsonify({'message': 'details successfully updated'}), 200
                except Exception as e:
                    # Handle database errors
                    return jsonify({'error': str(e)}), 500
                finally:
                    # Close cursor and connection
                    cur.close()
                    conn.close()

            return jsonify({'error': 'Username and email must not be empty'}), 400

        return jsonify({'error': 'Username or email is missing or email address is invalid'}), 400

    return jsonify({'error': 'Cannot update with null values'}), 400


# delete user account
@views_bp.route("/api/v1/del_account", methods=['DELETE'])
@token_required
def account_delete(user_id):
    """
      Delete user account.

      This endpoint deletes the account of the authenticated user identified by the provided user ID.

      Args:
          user_id (int): The ID of the authenticated user.

      Returns:
          Response: A JSON response indicating the success or failure of the account deletion process.

      """
    conn = initialize_database()
    cur = conn.cursor()
    cur.execute(
        '''
        DELETE FROM  USERS  WHERE ID = %s;
        ''',
        (user_id,)
    )
    conn.commit()
    return jsonify({'message': 'delete account'}), 200


# POST ENTRIES
@views_bp.route("/api/v1/add_entries", methods=['POST'])
@token_required
def post_entries(user_id):
    """
    Add new entry.

    This endpoint adds a new entry to the database with the provided content, associated with the authenticated user.

    Args:
        user_id (int): The ID of the authenticated user.

    Returns:
        Response: A JSON response indicating the success or failure of the entry addition process.

    """
    data = request.get_json()
    if data['content'] != '':
        conn = initialize_database()
        with conn.cursor() as cur:
            cur.execute(
                '''
                INSERT INTO ENTRIES (CONTENT, OWNER)
                VALUES (%s, %s) RETURNING ID
                ''',
                (data['content'], user_id)
            )
            entry_id = cur.fetchone()[0]
            conn.commit()
        return jsonify({'success': 'successfully added', 'entry_id': entry_id}), 200
    return jsonify({'Error': 'diary entry details must be available'}), 400


# get entries of specific user
@views_bp.route("/api/v1/get_entries", methods=['GET'])
@token_required
def get_entries(user_id):
    """
       Retrieve user entries.

       This endpoint retrieves all entries associated with the authenticated user identified by the provided user ID.

       Args:
           user_id (int): The ID of the authenticated user.

       Returns:
           Response: A JSON response containing the user's entries.

       """
    with initialize_database().cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM USERS WHERE ID = %s ;",
                    (user_id,))

        if cur.fetchone()[0] == 0:
            return jsonify({'message': 'UNAUTHORIZED ACCESS! USER DOESNT EXIST'}), 404
        cur.execute(
            '''
            SELECT * FROM ENTRIES WHERE OWNER = %s;
             ''',
            (user_id,)
        )
        user_data = cur.fetchall()
        cur.close()
    return jsonify({'user_entries': user_data})


# get specific entry
@views_bp.route("/api/v1/get_entry/<int:entry_id>", methods=['GET'])
@token_required
def get_entry(user_id, entry_id):
    """
    Retrieve a specific user entry.

    This endpoint retrieves a specific entry associated with the authenticated user identified by the provided
    user ID and the given entry ID.

    Args:
        user_id (int): The ID of the authenticated user.
        entry_id (int): The ID of the entry to retrieve.

    Returns:
        Response: A JSON response containing the specified user entry.

    """
    with initialize_database().cursor() as cur:
        cur.execute(
            '''
            SELECT * FROM ENTRIES WHERE OWNER = %s and ID = %s;
             ''',
            (user_id, entry_id,)
        )
        user_data = cur.fetchone()
        if user_data:
            entry = {
                'id': user_data[0],
                'content': user_data[1],
                'date': user_data[2],
                'owner': user_data[3]
            }

            return jsonify({'user_entry': entry})
        else:
            return jsonify({'message': 'not found'})


# update an entry
@views_bp.route("/api/v1/update_entry/<int:entry_id>", methods=['PUT'])
@token_required
def update_entry(user_id, entry_id):
    """
        Update user entry.

        This endpoint updates a specific entry associated with the authenticated user identified by the provided
        user ID and the given entry ID with the new content provided in the JSON payload.

        Args:
            user_id (int): The ID of the authenticated user.
            entry_id (int): The ID of the entry to update.

        Returns:
            Response: A JSON response indicating the success or failure of the entry update process.

        """
    data = request.get_json()
    if data:
        content = data['content']
        if content:
            conn = initialize_database()
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM ENTRIES WHERE ID = %s AND OWNER = %s", (entry_id, user_id))
                if cur.fetchone()[0] == 0:
                    return jsonify({'message': 'Entry does not exist or you are not authorized to update it'}), 404
                cur.execute(
                    '''
                     UPDATE ENTRIES SET CONTENT = %s, OWNER = %s  WHERE ID = %s;
                    ''',
                    (content, user_id, entry_id,)
                )
                conn.commit()
            return jsonify({'message': 'content successfully updated', 'content': content}), 200
        return jsonify({'message': 'content cannot be null'}), 400
    return jsonify({'message': 'cannot update with empty details '}), 400


# delete entry
@views_bp.route("/api/v1/delete_entry/<int:entry_id>", methods=['DELETE'])
@token_required
def delete_entry(user_id, entry_id):
    """
       Delete user entry.

       This endpoint deletes a specific entry associated with the authenticated user identified by the provided
       user ID and the given entry ID.

       Args:
           user_id (int): The ID of the authenticated user.
           entry_id (int): The ID of the entry to delete.

       Returns:
           Response: A JSON response indicating the success or failure of the entry deletion process.

       """
    conn = initialize_database()
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM ENTRIES WHERE ID = %s AND OWNER = %s", (entry_id, user_id))
        if cur.fetchone()[0] == 0:
            return jsonify({'message': 'Entry does not exist or you are not authorized to delete it'}), 404
        cur.execute(
            '''
                 DELETE FROM  ENTRIES  WHERE ID = %s;
                ''',
            (entry_id,)
        )
        conn.commit()
        cur.close()
        conn.close()
    return jsonify({'message': 'content successfully deleted'}), 200
