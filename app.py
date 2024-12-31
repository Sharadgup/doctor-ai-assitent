from flask import Flask, request, jsonify, render_template
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import os
import random
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

def send_otp(email, otp):
    msg = Message('Your OTP', sender='noreply@example.com', recipients=[email])
    msg.body = f'Your OTP is: {otp}'
    mail.send(msg)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    phone = data.get('phone')
    password = data.get('password')
    email = data.get('email')

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

    mongo.db.users.insert_one(user)
    send_otp(email, otp)

    return jsonify({"message": "User registered. Please verify your email."}), 201

@app.route('/verify_email', methods=['POST'])
def verify_email():
    data = request.json
    email = data.get('email')
    otp = data.get('otp')

    user = mongo.db.users.find_one({"email": email})
    if not user:
        return jsonify({"error": "User not found"}), 404

    if user['otp'] != otp:
        return jsonify({"error": "Invalid OTP"}), 400

    mongo.db.users.update_one({"email": email}, {"$set": {"email_verified": True}})
    return jsonify({"message": "Email verified successfully"}), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    phone = data.get('phone')
    password = data.get('password')

    user = mongo.db.users.find_one({"phone": phone})
    if not user:
        return jsonify({"error": "User not found"}), 404

    if not bcrypt.check_password_hash(user['password'], password):
        return jsonify({"error": "Invalid password"}), 400

    if not user['email_verified']:
        return jsonify({"error": "Email not verified"}), 403

    return jsonify({"message": "Login successful"}), 200

if __name__ == '__main__':
    app.run(debug=True)

