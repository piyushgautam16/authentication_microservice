
# Authentication Microservice

This is an authentication microservice designed to handle user registration, OTP-based login, password reset, and account information update. It uses Flask for the web framework, SQLAlchemy for database interactions, Flask-JWT-Extended for JSON Web Token (JWT) authentication, Flask-Bcrypt for password hashing, and Twilio for sending OTP via SMS.

## Table of Contents

- [Setup](#setup)
- [Configuration](#configuration)
- [Running the Microservice](#running-the-microservice)
- [API Endpoints](#api-endpoints)
- [Testing](#testing)

## Setup

1. Clone the repository:
   git clone https://github.com/your-username/authentication-microservice.git
   cd authentication-microservice
2. Create a virtual environment and activate it:
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate

## Configuration
Open main.py in a text editor.

Update the following configuration variables:

JWT_SECRET_KEY: Set your JWT secret key.
SQLALCHEMY_DATABASE_URI: Set the database URI.
TWILIO_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER: Set your Twilio credentials.
SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD: Set your SMTP server details for sending emails.
Save the changes.

Running the Microservice
Run the microservice with the following command:

python main.py

The microservice will be accessible at http://127.0.0.1:5000/.

API Endpoints

User Registration:
POST /register

Example request body:
{
  "first_name": "Akash",
  "last_name": "Gupta",
  "email": "akash.gupta@gmail.com",
  "phone_number": "+1234567890",
  "password": "secure_password",
  "role": "employee"
}

Send OTP via SMS:
POST /send-otp

Example request body:
{
  "phone_number": "+1234567890"
}

OTP-based Login:
POST /login

Example request body:
{
  "phone_number": "+1234567890",
  "otp": "123456"
}
Reset Password:
POST /reset-password

Example request body:
{
  "email": "john.doe@example.com"
}

Update Account:
PUT /update-account
Example request body:
{
  "first_name": "John",
  "last_name": "Doe",
  "phone_number": "+1234567890",
  "password": "new_secure_password"
}


Testing

Run the test cases with the following command:
python -m unittest tests.py
