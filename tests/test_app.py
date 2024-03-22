"""
Test suite for the Flask API.

This module contains unit tests to verify the functionality of the endpoints implemented in the Flask API.

The tests cover various scenarios such as user registration, login, profile management, entry creation, retrieval, and deletion.

Each test method simulates different API requests and checks the responses received from the server.

Note: These tests require a properly configured environment with access to the database and appropriate environment variables set.
"""

import os
import unittest
import sys
import os

# Add the parent directory of run.py to the Python path

from dotenv import load_dotenv

from models import get_db_connection
from run import create_app


class TestApp(unittest.TestCase):

    def setUp(self):
        load_dotenv()
        self.app = create_app()
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.client = self.app.test_client()
        self.data = {'username': os.getenv('register_name'), 'email_address': os.getenv('reg_email'),
                     'password': os.getenv('test_password')}
        self.data1 = {'username': os.getenv('t_name'), 'email_address': os.getenv('t_email'),
                      'password': os.getenv('test_password')}
        self.data2 = {'username': os.getenv('name'), 'email_address': os.getenv('email'),
                      'password': os.getenv('test_password')}

    def tearDown(self):
        self.app_context.pop()

    # REGISTER
    def test_success_registration(self):
        self.response = self.client.post('/api/v1/register', json=self.data)
        self.assertEqual(self.response.status_code, 200)
        self.assertIn(b'Registration successful', self.response.data)

    def test_email_validity(self):
        register_data = {'username': 'mony', 'email_address': 'invalidemail', 'password': 'password'}
        self.response = self.client.post('/api/v1/register', json=register_data)
        self.assertEqual(self.response.status_code, 400)
        self.assertIn(b'Invalid email address', self.response.data)

    #
    def test_already_existingEmail(self):
        self.response = self.client.post('/api/v1/register', json=self.data2)
        self.assertEqual(self.response.status_code, 400)
        self.assertIn(b'email already exists', self.response.data)

    def test_already_existingUsername(self):
        register_data = {'username': os.getenv('name'), 'email_address': 'existingusername@gmail.com',
                         'password': os.getenv('test_password')}
        self.response = self.client.post('/api/v1/register', json=register_data)
        self.assertEqual(self.response.status_code, 400)
        self.assertIn(b'username already exists', self.response.data)

    def test_already_existingUsernameEmail(self):
        register_data = {'username': os.getenv('name'), 'email_address': os.getenv('email'),
                         'password': 'password'}
        self.response = self.client.post('/api/v1/register', json=register_data)
        self.assertEqual(self.response.status_code, 400)
        self.assertIn(b'username and email already exist', self.response.data)

    def test_missing_credential(self):
        register_data = {'email_address': 'nousername@gmail.com', 'password': 'nousername'}
        self.response = self.client.post('/api/v1/register', json=register_data)
        self.assertEqual(self.response.status_code, 400)
        self.assertIn(b'All fields must be filled', self.response.data)

    # login
    def test_invalid_login_Username(self):
        login_data = {'username': 'user_name', 'password': os.getenv('test_password')}
        self.response = self.client.post('/api/v1/login', json=login_data)
        self.assertEqual(self.response.status_code, 400)
        self.assertIn(b'invalid username! User not found', self.response.data)

    def test_invalid_password(self):
        login_data = {'username': os.getenv('name'), 'password': 'invalid_password'}
        self.response = self.client.post('/api/v1/login', json=login_data)
        self.assertEqual(self.response.status_code, 400)
        self.assertIn(b'wrong password', self.response.data)

    def test_nologin_credentials(self):
        login_data = {}
        self.response = self.client.post('/api/v1/login', json=login_data)
        self.assertEqual(self.response.status_code, 400)
        self.assertIn(b'login details must be available', self.response.data)

    def test_missing_login_credential(self):
        login_data = {'username': 'username'}  # missing pswd
        self.response = self.client.post('/api/v1/login', json=login_data)
        self.assertEqual(self.response.status_code, 400)
        self.assertIn(b'username and password are required', self.response.data)

    def test_login_success(self):
        response = self.client.post('/api/v1/login',
                                    json={'username': os.getenv('name'), 'password': os.getenv('test_password')})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn('successfully, logged in', data['message'])
        self.assertEqual(data, {'message': 'successfully, logged in', 'token': data['token']})
        self.assertIn('token', data)

    # create a token required test
    # wit authorization token
    def test_get_profile(self):
        response = self.client.post('/api/v1/login',
                                    json={'username': os.getenv('name'), 'password': os.getenv('test_password')})
        data = response.get_json()
        valid_tkn = 'Bearer ' + str(data['token'])
        self.response = self.client.get('/api/v1/profile', headers={'Authorization': valid_tkn})
        self.assertEqual(self.response.json, {"details": ['anitah@gmail.com', 'maryanita']})

    # no token if user isnt logged in
    def test_without_token(self):
        self.response = self.client.get('/api/v1/profile', headers={'Authorization': ''})
        self.assertEqual(self.response.json, {'message': 'Missing authorization token'})

    # invalid token
    def test_invalid_token(self):
        tk = ' Bearer vhjeiuhjnwesuihjkui'
        self.response = self.client.get('/api/v1/profile', headers={'Authorization': tk})
        self.assertEqual(self.response.json, {'message': 'Invalid token'})

    # expired   token
    def test_expired_token(self):
        expired_tkn = os.getenv('expired_token')
        self.response = self.client.get('/api/v1/profile', headers={'Authorization': expired_tkn})
        self.assertEqual(self.response.json, {'message': 'Token has expired'})
        self.assertEqual(self.response.status_code, 401)

    # blacklisted token
    def test_blacklisted_token(self):
        # first login
        self.response = self.client.post('/api/v1/login',
                                         json={'username': 'username', 'password': os.getenv('test_password')})
        data = self.response.get_json()
        blacklisted_tk = 'Bearer ' + str(data['token'])
        # logout
        self.response = self.client.post('/api/v1/logout', headers={'Authorization': blacklisted_tk})
        # after logogut token be blacklisted
        # get profile with blacklisetd tkn
        self.response = self.client.get('/api/v1/profile', headers={'Authorization': blacklisted_tk})
        self.assertEqual(self.response.json, {'message': 'Token has already expired, please log in again'})

    # test profile update
    # exsting username
    # add other tests
    def test_profile_update(self):
        update_with = {'username': os.getenv('t_name'), 'email_address': os.getenv('t_email')}
        # logged in
        self.response = self.client.post('/api/v1/login',
                                         json={'username': os.getenv('t_name'), 'password': os.getenv('test_password')})
        data = self.response.get_json()
        tk = 'Bearer ' + str(data['token'])
        # access profile
        response = self.client.put('/api/v1/profile/update', headers={'Authorization': tk}, json=update_with)
        # response = self.client.post('/api/v1/profile/update', json =update_with)
        self.assertEqual(response.get_json(), {'message': 'details successfully updated'})

    # already exsting username
    def test_profile_update_with_existing_Username(self):
        update_with = {'username': os.getenv('name'), 'email_address': os.getenv('t_email')}
        # logged in
        self.response = self.client.post('/api/v1/login',
                                         json={'username': os.getenv('t_name'), 'password': os.getenv('test_password')})
        data = self.response.get_json()
        tk = 'Bearer ' + str(data['token'])
        # access profile
        response = self.client.put('/api/v1/profile/update', headers={'Authorization': tk}, json=update_with)
        # response = self.client.post('/api/v1/profile/update', json =update_with)
        self.assertEqual(response.get_json(), {'error': 'username already exists'})
        self.assertEqual(response.status_code, 400)

    # already exsting email
    def test_profile_update_with_existing_email(self):
        update_with = {'username': os.getenv('t_name'), 'email_address': os.getenv('email')}
        # logged in
        self.response = self.client.post('/api/v1/login',
                                         json={'username': os.getenv('t_name'), 'password': os.getenv('test_password')})
        data = self.response.get_json()
        tk = 'Bearer ' + str(data['token'])
        # access profile
        response = self.client.put('/api/v1/profile/update', headers={'Authorization': tk}, json=update_with)
        self.assertEqual(response.get_json(), {'error': 'email already exists'})
        self.assertEqual(response.status_code, 400)

    # logout tests
    def test_logout(self):
        self.response = self.client.post('/api/v1/login',
                                         json={'username': os.getenv('name'), 'password': os.getenv('test_password')})
        data = self.response.get_json()
        tk = 'Bearer ' + str(data['token'])
        self.response = self.client.post('/api/v1/logout', headers={'Authorization': tk})
        self.assertEqual(self.response.get_json(), {'message': 'successfully logged out'})
        self.assertEqual(self.response.status_code, 200)

    # test user add entries
    def test_post_entries(self):
        post_dt = {'content': 'two months of coding'}
        self.response = self.client.post('/api/v1/login',
                                         json={'username': os.getenv('t_name'), 'password': os.getenv('test_password')})
        data = self.response.get_json()
        tk = 'Bearer ' + str(data['token'])
        response = self.client.post('/api/v1/add_entries', headers={'Authorization': tk}, json=post_dt)
        self.assertEqual(response.get_json(), {'message': 'successfully added'})
        self.assertEqual(response.status_code, 200)
        # if no data

    # TEST GET ENTRIES
    def test_get_entries(self):
        self.response = self.client.post('/api/v1/login',
                                         json={'username': os.getenv('t_name'), 'password': os.getenv('test_password')})
        data = self.response.get_json()
        tk = 'Bearer ' + str(data['token'])
        response = self.client.get('/api/v1/get_entries', headers={'Authorization': tk})
        self.assertEqual(response.status_code, 200)
        self.assertIn('user_entries', response.get_json())


if __name__ == '__main__':
    unittest.main()
