from flask import Flask, request, jsonify, render_template
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import os
import random
import logging
from dotenv import load_dotenv

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

load_dotenv()

app = Flask(__name__)
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
app.config['SENDGRID_API_KEY'] = os.getenv("SENDGRID_API_KEY")

# Log configuration (make sure to mask sensitive information)
logger.info(f"MONGO_URI: {'*' * len(os.getenv('MONGO_URI'))}")
logger.info(f"SENDGRID_API_KEY: {'*' * len(os.getenv('SENDGRID_API_KEY'))}")

mongo = PyMongo(app)
bcrypt = Bcrypt(app)

def send_otp(email, otp):
    try:
        message = Mail(
            from_email='your_verified_sender@example.com',
            to_emails=email,
            subject='Your OTP',
            html_content=f'<strong>Your OTP is: {otp}</strong>')
        sg = SendGridAPIClient(app.config['SENDGRID_API_KEY'])
        response = sg.send(message)
        logger.info(f"OTP sent successfully to {email}. Status code: {response.status_code}")
    except Exception as e:
        logger.error(f"Failed to send OTP to {email}. Error: {str(e)}")
        raise

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        phone = data.get('phone')
        password = data.get('password')
        email = data.get('email')

        logger.info(f"Received registration request for email: {email}")

        if not phone or not password or not email:
            return jsonify({"error": "Missing required fields"}), 400

        if mongo.db.users.find_one({"phone": phone}):
            return jsonify({"error": "Phone number already registered"}), 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        otp = str(random.randint(100000, 999999))

        user = {
            "phone": phone,
            "password": hashed_password,
            "email": email,
            "email_verified": False,
            "otp": otp
        }

        result = mongo.db.users.insert_one(user)
        logger.info(f"User inserted with ID: {result.inserted_id}")

        send_otp(email, otp)

        return jsonify({"message": "User registered. Please verify your email.", "otp": otp}), 201
    except Exception as e:
        logger.error(f"Error in registration process: {str(e)}")
        return jsonify({"error": "An error occurred during registration"}), 500

@app.route('/verify_email', methods=['POST'])
def verify_email():
    try:
        data = request.json
        email = data.get('email')
        otp = data.get('otp')

        user = mongo.db.users.find_one({"email": email})
        if not user:
            return jsonify({"error": "User not found"}), 404

        if user['otp'] != otp:
            return jsonify({"error": "Invalid OTP"}), 400

        mongo.db.users.update_one({"email": email}, {"$set": {"email_verified": True}})
        logger.info(f"Email verified successfully for {email}")
        return jsonify({"message": "Email verified successfully"}), 200
    except Exception as e:
        logger.error(f"Error in email verification process: {str(e)}")
        return jsonify({"error": "An error occurred during email verification"}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        phone = data.get('phone')
        password = data.get('password')

        user = mongo.db.users.find_one({"phone": phone})
        if not user:
            return jsonify({"error": "User not found"}), 404

        if not bcrypt.check_password_hash(user['password'], password):
            return jsonify({"error": "Invalid password"}), 400

        if not user['email_verified']:
            return jsonify({"error": "Email not verified", "email": user['email']}), 403

        logger.info(f"User logged in successfully: {phone}")
        return jsonify({"message": "Login successful"}), 200
    except Exception as e:
        logger.error(f"Error in login process: {str(e)}")
        return jsonify({"error": "An error occurred during login"}), 500

@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    try:
        data = request.json
        email = data.get('email')

        user = mongo.db.users.find_one({"email": email})
        if not user:
            return jsonify({"error": "User not found"}), 404

        if user['email_verified']:
            return jsonify({"error": "Email already verified"}), 400

        new_otp = str(random.randint(100000, 999999))
        mongo.db.users.update_one({"email": email}, {"$set": {"otp": new_otp}})

        send_otp(email, new_otp)

        return jsonify({"message": "New OTP sent successfully", "otp": new_otp}), 200
    except Exception as e:
        logger.error(f"Error in resending OTP: {str(e)}")
        return jsonify({"error": "An error occurred while resending OTP"}), 500

if __name__ == '__main__':
    app.run(debug=True)

