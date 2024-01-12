import unittest
import json
from flask import Flask
from main import app, db

class AppTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        with app.app_context():
            db.create_all()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def register_user(self, data):
        response = self.app.post('/register', json=data)
        return response

    def login_user(self, data):
        response = self.app.post('/login', json=data)
        return response

    def request_password_reset(self, data):
        response = self.app.post('/reset-password', json=data)
        return response

    def reset_password_with_token(self, data, reset_token):
        reset_url = f'/reset-password?token={reset_token}'
        response = self.app.post(reset_url, json=data)
        return response

    def test_register_login(self):
        # Test user registration and login
        registration_data = {
            'first_name': 'Sagar',
            'last_name': 'Mishra',
            'email': 'sagar.mishra@gmail.com',
            'phone_number': '+1234567890',
            'password': 'securepassword',
            'role': 'employee'
        }

        # Register user
        registration_response = self.register_user(registration_data)
        self.assertEqual(registration_response.status_code, 200)

        # Login user
        login_data = {
            'phone_number': '+1234567890',
            'otp': '123456'  # You may need to replace this with the actual OTP
        }
        login_response = self.login_user(login_data)
        self.assertEqual(login_response.status_code, 200)

    def test_password_reset(self):
        # Test password reset request and reset with token
        registration_data = {
            'first_name': 'akash',
            'last_name': 'Gupta',
            'email': 'akash.gupta@gmail.com',
            'phone_number': '+9876543210',
            'password': 'strongpassword',
            'role': 'employee'
        }

        # Register user
        registration_response = self.register_user(registration_data)
        self.assertEqual(registration_response.status_code, 200)

        # Request password reset
        reset_request_data = {
            'email': 'ahkash.gupta@gmail.com'
        }
        reset_request_response = self.request_password_reset(reset_request_data)
        self.assertEqual(reset_request_response.status_code, 200)

        # Extract reset token from the email (mock implementation)
        reset_token = 'mock_reset_token'

        # Reset password with token
        reset_data = {
            'new_password': 'newstrongpassword'
        }
        reset_response = self.reset_password_with_token(reset_data, reset_token)
        self.assertEqual(reset_response.status_code, 200)

    def test_invalid_login(self):
        # Test invalid login with wrong OTP
        invalid_login_data = {
            'phone_number': '+1234567890',
            'otp': 'invalidotp'
        }
        invalid_login_response = self.login_user(invalid_login_data)
        self.assertEqual(invalid_login_response.status_code, 401)

if __name__ == '__main__':
    unittest.main()
