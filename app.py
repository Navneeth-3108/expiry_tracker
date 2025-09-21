# ============================================================================
# IMPORTS
# ============================================================================
import os
import random
import bcrypt
import schedule
import time
import pytz
from threading import Thread
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask import Flask, render_template, request, session
from pymongo import MongoClient
from flask_mail import Mail, Message

# ============================================================================
# APP CONFIGURATION
# ============================================================================
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Load environment variables from .env file
load_dotenv()

# Email Configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = bool(os.getenv('MAIL_USE_TLS'))
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
mail = Mail(app)

# Database Configuration
client = MongoClient(os.getenv('MONGO_URI'))
dbusers = client["AccountsDB"]
usercollection = dbusers["User_details"]
dbproducts = client["ProductsDB"]

# ============================================================================
# MAIN ROUTES - Home and Authentication
# ============================================================================

@app.route('/')
def show_form():
    return render_template('index.html')

@app.route('/login', methods=['GET','POST'])
def handle_form():
    email = request.form['email']
    password = request.form['password'].encode('utf-8')
    user = usercollection.find_one({"Email": email})
    
    if user and bcrypt.checkpw(password, user["Password"]):
        session['phone'] = user["Phone"]
        session['name'] = user['Username']
        session['email'] = user['Email']
        
        # Collection named after user's phone number
        productcollection = dbproducts[f"{user['Phone']}"] 
        products = list(productcollection.find())
        
        return render_template('welcome.html', name=user['Username'], entries=products)
    else:
        return render_template('index.html', error="Invalid email or password",perror = True)

@app.route('/login-page', methods=['POST'])
def home():
    return render_template('index.html',perror = False)

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return render_template('index.html', message="Logged out successfully",perror = False)

# ============================================================================
# USER REGISTRATION ROUTES
# ============================================================================

@app.route('/signup', methods=['GET','POST'])
def signup():
    return render_template('create.html')

@app.route('/create', methods=['GET','POST'])
def create_user():
    username = request.form['username']
    email = request.form['email']
    phone = request.form['phone']
    password = request.form['password'].encode('utf-8')
    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
    
    if not phone.isdigit() or len(phone) != 10:
        return render_template('create.html', error="Please enter a valid 10-digit phone number")
    if usercollection.find_one({"Email": email}):
        return render_template('create.html', error="Email already exists")
    elif usercollection.find_one({"Phone": int(phone)}):
        return render_template('create.html', error="Phone number already exists")
    elif usercollection.find_one({"Username": username}):
        return render_template('create.html', error="Username already exists")
    
    otp = random.randint(100000, 999999)
    session['otp'] = otp
    session['email'] = email
    session['username'] = username
    session['phone'] = phone
    session['password'] = hashed_password
    
    msg = Message(
        subject="Email Verification",
        sender=app.config['MAIL_USERNAME'],
        recipients=[session['email']],
        body=f"Hi {username},\n\nThank you for signing up! Your OTP for email verification is: {otp}\n\nPlease use this OTP to complete your registration.\n\n"
    )
    mail.send(msg)
    return render_template('otp.html')

@app.route('/otp', methods=['POST'])
def verify_signup_otp():
    entered_otp = request.form['otp']
    if 'otp' in session and entered_otp == str(session['otp']):
        usercollection.insert_one({
            "Username": session['username'],
            "Email": session['email'],
            "Phone": int(session['phone']),
            "Password": session['password']
        })
        session.pop('otp', None)
        session.pop('email', None)
        session.pop('username', None)
        session.pop('phone', None)
        session.pop('password', None)
        return render_template('index.html', message="User created successfully. Please login.", perror=False)
    else:
        return render_template('otp.html', error="Invalid OTP. Please try again.")

@app.route('/resend', methods=['POST'])
def resend_signup_otp():
    if 'email' in session and 'username' in session:
        otp = random.randint(100000, 999999)
        session['otp'] = otp
        msg = Message(
            subject="Email Verification",
            sender=app.config['MAIL_USERNAME'],
            recipients=[session['email']],
            body=f"Hi {session['username']},\n\nYour OTP for email verification is: {otp}\n\nPlease use this OTP to complete your registration.\n\n"
        )
        mail.send(msg)
        return render_template('otp.html', message="OTP resent successfully.")
    else:
        return render_template('create.html', error="Session expired. Please try again.")

# ============================================================================
# PASSWORD RESET ROUTES
# ============================================================================

@app.route('/forget', methods=['GET','POST'])
def forget_password():
    return render_template('forget.html')

@app.route('/check', methods=['POST'])
def check_user():
    email = request.form['email']
    user = usercollection.find_one({"Email": email})
    if user:
        session['email'] = email
        session['username'] = user['Username']
        username = user['Username']
        otp = random.randint(100000, 999999)
        session['otp'] = otp
        msg = Message(
            subject="Password Reset for Expiry Tracker",
            sender=app.config['MAIL_USERNAME'],
            recipients=[email],
            body=f"Hi {username},\n\nYour OTP for Password Reset is: {otp}\n\nPlease use this OTP to change your password.\n\n"
        )
        mail.send(msg)
        return render_template('pwotp.html')
    else:
        return render_template('forget.html', error="Email not found. Please check your email address.")

@app.route('/pwotp', methods=['POST'])
def verify_pw_otp():
    entered_otp = request.form['otp']
    if 'otp' in session and entered_otp == str(session['otp']):
        user = usercollection.find_one({"Email": session['email']})
        if not user:
            return render_template('forget.html', error="Session expired. Please try again.")
        session.pop('otp', None)
        return render_template('reset.html')
    else:
        return render_template('pwotp.html', error="Invalid OTP. Please try again.")

@app.route('/reset', methods=['POST'])
def reset_password():
    password1 = request.form['password1']
    password2 = request.form['password2']
    if password1 == password2:
        hashed_password = bcrypt.hashpw(password1.encode('utf-8'), bcrypt.gensalt())
        username = session.get('username')
        email = session.get('email')
        if username and email:
            usercollection.update_one({"Username": username}, {"$set": {"Password": hashed_password}})
            session.pop('username', None)
            session.pop('email', None)
            return render_template('index.html', message="Password updated successfully", perror=False)
        else:
            return render_template('forget.html', error="Session expired. Please try again.")
    else:
        return render_template('reset.html', error="Passwords do not match")

@app.route('/pwresend', methods=['POST'])
def resend_pw_otp():
    if 'email' in session and 'username' in session:
        username = session['username']
        otp = random.randint(100000, 999999)
        session['otp'] = otp
        msg = Message(
            subject="Password Reset",
            sender=app.config['MAIL_USERNAME'],
            recipients=[session['email']],
            body=f"Hi {username},\n\nYour OTP for Password Reset is: {otp}\n\nPlease use this OTP to change your password.\n\n"
        )
        mail.send(msg)
        return render_template('pwotp.html', message="OTP resent successfully.")
    else:
        return render_template('forget.html', error="Session expired. Please try again.")

# ============================================================================
# Disabling and Enabling Notifications
# ============================================================================

@app.route('/enable-notification', methods=['POST'])
def enable_notification():
    if not session.get('phone'):
        return render_template('index.html', error="Session Expired. Please login again.", perror = False)
    product_name = request.form['product_name']
    productscollection = dbproducts[f"{session['phone']}"]
    productscollection.update_one({"product_name": product_name}, {"$set": {"notification": "on"}})
    entries=list(productscollection.find())
    return render_template('welcome.html', name=session['name'], entries=entries, message="Notification setting updated.")

@app.route('/disable-notification', methods=['POST'])
def disable_notification():
    if not session.get('phone'):
        return render_template('index.html', error="Session Expired. Please login again.", perror = False)
    product_name = request.form['product_name']
    productscollection = dbproducts[f"{session['phone']}"]
    productscollection.update_one({"product_name": product_name}, {"$set": {"notification": "off"}})
    entries=list(productscollection.find())
    return render_template('welcome.html', name=session['name'], entries=entries, message="Notification setting updated.")

# ============================================================================
# Scheduler
# ============================================================================

def schedule_notifications():
    today = datetime.now(pytz.utc).date()
    two_weeks_from_now = today + datetime.timedelta(days=14)
    users = dbproducts.list_collection_names()
    for user_phone in users:
        productscollection = dbproducts[user_phone]
        products = productscollection.find({"notification": "on"})
        user_details = usercollection.find_one({"Phone": int(user_phone)})
        if not user_details:
            continue
        expiring_products = []
        for product in products:
            expiry_date = product.get('expiry_date')
            if expiry_date:
                expiry_date_obj = datetime.datetime.strptime(expiry_date, '%Y-%m-%d').date()
                if today <= expiry_date_obj <= two_weeks_from_now:
                    expiring_products.append(product)
        if expiring_products:
            #yet to be done
            pass
            

def run_scheduler():
    schedule.every().day.at("09:00").do(schedule_notifications)

    while True:
        schedule.run_pending()
        time.sleep(1)

# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    scheduler_thread = Thread(target=run_scheduler)
    scheduler_thread.daemon = True
    scheduler_thread.start()
    app.run(debug=True)