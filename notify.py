import os
import pytz
from datetime import datetime, timedelta
from dotenv import load_dotenv
from pymongo import MongoClient
from flask_mail import Mail, Message
from twilio.rest import Client
import bcrypt

# Load environment variables from .env file
load_dotenv()

# Email Configuration
MAIL_SERVER = os.getenv('MAIL_SERVER')
MAIL_PORT = int(os.getenv('MAIL_PORT'))
MAIL_USE_TLS = bool(os.getenv('MAIL_USE_TLS'))
MAIL_USERNAME = os.getenv('MAIL_USERNAME')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')

# Flask-Mail setup (standalone, not using Flask app context)
from flask import Flask
app = Flask(__name__)
app.config['MAIL_SERVER'] = MAIL_SERVER
app.config['MAIL_PORT'] = MAIL_PORT
app.config['MAIL_USE_TLS'] = MAIL_USE_TLS
app.config['MAIL_USERNAME'] = MAIL_USERNAME
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
mail = Mail(app)

# Twilio setup
account_sid = os.getenv('account_sid')
auth_token = os.getenv('auth_token')
twilio_client = Client(account_sid, auth_token)
twilio_number = os.getenv('twilio_number')
twilio_whatsapp_number = os.getenv('twilio_whatsapp_number')

# Database setup
client = MongoClient(os.getenv('MONGO_URI'))
dbusers = client["AccountsDB"]
usercollection = dbusers["User_details"]
dbproducts = client["ProductsDB"]

def send_expiry_notifications():
    today = datetime.now(pytz.utc).date()
    two_weeks_from_now = today + timedelta(days=14)
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
                expiry_date_obj = datetime.strptime(expiry_date, '%Y-%m-%d').date()
                if today <= expiry_date_obj <= two_weeks_from_now:
                    expiring_products.append(product)
        if expiring_products:
            for product in expiring_products:
                # Email notification
                with app.app_context():
                    msg = Message(
                        subject="Product Expiration Reminder",
                        sender=MAIL_USERNAME,
                        recipients=[user_details['Email']],
                        body=f"\n\nYour product '{product['product_name']}' is expiring on {product['expiry_date']}.\n\nPlease take the necessary action.\n\n"
                    )
                    mail.send(msg)
                # SMS notification
                twilio_client.messages.create(
                    body=f"Your product '{product['product_name']}' is expiring on {product['expiry_date']}. Please take the necessary action.",
                    from_=twilio_number,
                    to=f"+91{user_details['Phone']}"
                )
                # WhatsApp notification
                twilio_client.messages.create(
                    body=f"Your product '{product['product_name']}' is expiring on {product['expiry_date']}. Please take the necessary action.",
                    from_=twilio_whatsapp_number,
                    to=f"whatsapp:+91{user_details['Phone']}"
                )

if __name__ == "__main__":
    send_expiry_notifications()
