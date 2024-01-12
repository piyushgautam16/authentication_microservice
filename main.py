from flask import Flask, request, jsonify
import random
import pyotp
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt  
from email.mime.text import MIMEText
import smtplib
import re
from twilio.rest import Client


app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['TWILIO_SID'] = 'your_twilio_sid'
app.config['TWILIO_AUTH_TOKEN'] = 'your_twilio_auth_token'
app.config['TWILIO_PHONE_NUMBER'] = 'your_twilio_phone_number'
app.config['BCRYPT_LOG_ROUNDS'] = 12  
bcrypt = Bcrypt(app)  
jwt = JWTManager(app)
db = SQLAlchemy(app)
twilio_client = Client(app.config['TWILIO_SID'], app.config['TWILIO_AUTH_TOKEN'])


# Define roles
ROLES = {
    'admin': 0,
    'manager': 1,
    'employee': 2
}

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(15), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    reset_token = db.Column(db.String(50), unique=True, nullable=True)

# Function to generate a random user ID (replace with a more secure method)
def generate_user_id():
    return str(random.randint(1000, 9999))

# Function to validate email format
def is_valid_email(email):
    email_pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    
    if re.match(email_pattern, email):
        return True
    else:
        return False

def is_valid_phone(phone_number):
    phone_pattern = r'^\+[1-9]\d{1,14}$'
    
    if re.match(phone_pattern, phone_number):
        return True
    else:
        return False

# Function to send OTP via email 
def send_otp_email(to, otp):
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    smtp_username = 'your_email@gmail.com'
    smtp_password = 'your_email_password'

    message = MIMEText(f'Your OTP is: {otp}')
    message['Subject'] = 'OTP for Authentication'
    message['From'] = 'your_email@gmail.com'
    message['To'] = to

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail('your_email@gmail.com', [to], message.as_string())

# Function to generate OTP
def generate_otp(otp_secret):
    totp = pyotp.TOTP(otp_secret)
    return totp.now()

# Function to validate OTP
def validate_otp(otp, otp_secret):
    totp = pyotp.TOTP(otp_secret)
    return otp == totp.now()

# Endpoint for user registration
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        # Validate required fields
        required_fields = ['first_name', 'last_name', 'email', 'phone_number', 'password', 'role']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing {field} field in the request'}), 400

        # Validate email format
        if not is_valid_email(data['email']):
            return jsonify({'error': 'Invalid email address'}), 400

        # Validate phone number format
        if not is_valid_phone(data['phone_number']):
            return jsonify({'error': 'Invalid phone number'}), 400

        # Validate role
        if data['role'] not in ROLES:
            return jsonify({'error': 'Invalid role'}), 400
        
        # Hash the password
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

        # Generate OTP
        otp_secret = pyotp.random_base32()
        otp = generate_otp(otp_secret)

        # Save user data to the database
        user = User(
            first_name=data['first_name'],
            last_name=data['last_name'],
            email=data['email'],
            phone_number=data['phone_number'],
            password=hashed_password,  
            otp_secret=otp_secret,
            role=data['role']
        )
        db.session.add(user)
        db.session.commit()

        # Send OTP via email
        send_otp_email(data['email'], otp)

        return jsonify({'message': 'Registration successful. Check your email for OTP.'})
    except Exception as e:
        return jsonify({'error': f'Error during registration: {str(e)}'}), 500

# Endpoint for sending OTP via SMS
@app.route('/send-otp', methods=['POST'])
def send_otp_sms():
    try:
        data = request.json
        required_fields = ['phone_number']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing {field} field in the request'}), 400

        user = User.query.filter_by(phone_number=data['phone_number']).first()
        if user:
            send_otp_sms_twilio(data['phone_number'], user.otp_secret)
            return jsonify({'message': 'OTP sent successfully'})
        return jsonify({'error': 'Invalid phone number'}), 404
    except Exception as e:
        return jsonify({'error': f'Error during OTP generation: {str(e)}'}), 500

# Endpoint for OTP-based login
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        required_fields = ['phone_number', 'otp']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing {field} field in the request'}), 400

        user = User.query.filter_by(phone_number=data['phone_number']).first()
        if user and validate_otp(data['otp'], user.otp_secret):
            access_token = create_access_token(identity={'user_id': user.id, 'role': user.role})
            return jsonify({'message': 'Login successful', 'access_token': access_token})
        return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'error': f'Error during login: {str(e)}'}), 500

# Function to generate a random user ID
def generate_user_id():
    return str(random.randint(1000, 9999))

# Function to send OTP via SMS using Twilio
def send_otp_sms_twilio(phone_number, otp_secret):
    totp = pyotp.TOTP(otp_secret)
    otp = totp.now()
    message_body = f'Your OTP is: {otp}'
    message = twilio_client.messages.create(
        body=message_body,
        from_=app.config['TWILIO_PHONE_NUMBER'],
        to=phone_number
    )

# Function to validate OTP
def validate_otp(otp, otp_secret):
    totp = pyotp.TOTP(otp_secret)
    return totp.verify(otp)

# Endpoint for password reset
@app.route('/reset-password', methods=['POST'])
def reset_password_request():
    try:
        data = request.json
        # Validate required fields
        required_fields = ['email']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing {field} field in the request'}), 400

        # Find user by email
        user = User.query.filter_by(email=data['email']).first()
        if user:
            # Generate a unique reset token
            reset_token = str(random.randint(100000, 999999))

            # Save the reset token to the user in the database (you need a new column for reset_token)
            user.reset_token = reset_token
            db.session.commit()

            # Send reset email
            reset_link = f'http://127.0.0.1:5000/reset-password/{reset_token}'
            send_email(user.email, 'Password Reset', f'Click the link to reset your password: {reset_link}')
            return jsonify({'message': 'Password reset email sent'})
        return jsonify({'error': 'Invalid user'}), 401
    except Exception as e:
        return jsonify({'error': f'Error during password reset request: {str(e)}'}), 500

# Endpoint to handle password reset with token
@app.route('/reset-password/<reset_token>', methods=['POST'])
def reset_password_with_token(reset_token):
    try:
        data = request.json
        # Validate required fields
        required_fields = ['password']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing {field} field in the request'}), 400

        # Find user by reset token
        user = User.query.filter_by(reset_token=reset_token).first()
        if user:
            # Hash the new password
            hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

            # Update user's password and reset token
            user.password = hashed_password
            user.reset_token = None
            db.session.commit()

            return jsonify({'message': 'Password reset successful'})
        return jsonify({'error': 'Invalid reset token'}), 401
    except Exception as e:
        return jsonify({'error': f'Error during password reset: {str(e)}'}), 500

# Endpoint for account information update
@app.route('/update-account', methods=['PUT'])
@jwt_required()
def update_account():
    try:
        current_user = get_jwt_identity()
        user_id = current_user['user_id']
        data = request.json
        # Validate required fields
        required_fields = ['first_name', 'last_name', 'phone_number', 'password']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing {field} field in the request'}), 400

        # Find user by user_id
        user = User.query.filter_by(id=user_id).first()
        if user:
            # Update user account information
            user.first_name = data['first_name']
            user.last_name = data['last_name']
            user.phone_number = data['phone_number']
            if 'password' in data:
                user.password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
            db.session.commit()
            return jsonify({'message': 'Account updated successfully'})
        return jsonify({'error': 'Invalid user'}), 401
    except Exception as e:
        return jsonify({'error': f'Error during account update: {str(e)}'}), 500

# Function to send email
def send_email(to, subject, message):
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    smtp_username = 'your_email@gmail.com'
    smtp_password = 'your_email_password'

    msg = MIMEText(message)
    msg['Subject'] = subject
    msg['From'] = 'your_email@gmail.com'
    msg['To'] = to

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail('your_email@gmail.com', [to], msg.as_string())

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  
    app.run(debug=True)
