from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
import requests
import os
from dotenv import load_dotenv
from datetime import datetime
import json
import re
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from email.mime.text import MIMEText
import base64
import pickle
from google.auth.transport.requests import Request

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

# Gmail API configuration
SCOPES = ['https://www.googleapis.com/auth/gmail.send']
GMAIL_SENDER = os.getenv('GMAIL_SENDER')
CLIENT_SECRETS_FILE = os.getenv('GOOGLE_CLIENT_SECRETS_FILE')
TOKEN_PICKLE_FILE = 'token.pickle'
REDIRECT_URI = 'http://localhost:5000/oauth2callback'

def get_gmail_service():
    """Get Gmail API service instance"""
    creds = None
    if os.path.exists(TOKEN_PICKLE_FILE):
        with open(TOKEN_PICKLE_FILE, 'rb') as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                CLIENT_SECRETS_FILE, 
                SCOPES,
                redirect_uri=REDIRECT_URI
            )
            creds = flow.run_local_server(
                host='localhost',
                port=5000,
                authorization_prompt_message='Please wait...',
                success_message='Authorization completed! You can close this window.',
                open_browser=True
            )
        with open(TOKEN_PICKLE_FILE, 'wb') as token:
            pickle.dump(creds, token)

    return build('gmail', 'v1', credentials=creds)

@app.route('/finnhub-stocks')
@login_required
def finnhub_stocks():
    return render_template('finnhub_stocks.html')

def send_email(to_email, subject, body_html):
    """Send email using Gmail API"""
    try:
        service = get_gmail_service()
        message = MIMEText(body_html, 'html')
        message['to'] = to_email
        message['from'] = GMAIL_SENDER
        message['subject'] = subject

        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
        service.users().messages().send(userId='me', body={'raw': raw_message}).execute()
        return True
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False

def send_welcome_email(user_email):
    """Send welcome email with current deals and offers"""
    subject = "Welcome to Price Tracker - Latest Deals & Offers!"
    body_html = f"""
    <html>
        <body>
            <h2>Welcome to Price Tracker!</h2>
            <p>Dear valued customer,</p>
            <p>Thank you for logging in to Price Tracker. Here are some exciting deals we've found for you:</p>
            <ul>
                <li><strong>Electronics:</strong> Up to 30% off on latest gadgets</li>
                <li><strong>Fashion:</strong> Buy 2 Get 1 Free on selected items</li>
                <li><strong>Home & Kitchen:</strong> Clearance sale - Up to 50% off</li>
            </ul>
            <p>Start tracking your favorite products now and never miss a price drop!</p>
            <p>Best regards,<br>Price Tracker Team</p>
        </body>
    </html>
    """
    return send_email(user_email, subject, body_html)

def send_price_alert(user_email, product_name, current_price, product_url):
    """Send price alert email using Gmail API"""
    subject = f"Price Drop Alert - {product_name}"
    body_html = f"""
    <html>
        <body>
            <h2>Price Drop Alert!</h2>
            <p>Good news! The price of <strong>{product_name}</strong> has dropped to <strong>₹{current_price:.2f}</strong>!</p>
            <p><a href="{product_url}">Click here to check it out</a></p>
            <p>Don't miss this opportunity to save!</p>
            <p>Best regards,<br>Price Tracker Team</p>
        </body>
    </html>
    """
    return send_email(user_email, subject, body_html)

# MailerLite API key
MAILERLITE_API_KEY = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiI0IiwianRpIjoiZWM2ZTg0NjNmZjNlYjFmYjY5Yzc1ZDE1YWVhZTFlZDczZGQ4NWM0N2IzMDVmMDgyNWRlMThiYzAyYWEzNzAyZmRhM2JlZjE2OTlhNjA0OGMiLCJpYXQiOjE3NDIzOTUxNDYuODUzOTI4LCJuYmYiOjE3NDIzOTUxNDYuODUzOTMsImV4cCI6NDg5ODA2ODc0Ni44NDk4ODMsInN1YiI6IjE0MDkyMTYiLCJzY29wZXMiOltdfQ.KXYCe_Xpd6HxZVKzaSWZ4Ch1uKOhj-Rz68Qqzd8IHwlowXE4uODVnub2E5ZTLY4epd09AJUmnBq1PvsC0UMbIMvVZotUqC3dlDoIdmhs4GhMT-kK2hhOmtc9dTUPYlERB4pioI1zRq92LZFgVDrxrQzjZt6OnVi6xjC6pLHOKvUUcOaxnXsupDBm3WaeSSvTMyTOPVdtfCNeOhAx1hXI5h5lspvALrTVOPKQe4Ftxu7CzrclSkgy44zzVp3ZJo9GNXb5ESUld4IkDl_piMyAnvPNKwA0IDf6yiz_stbDPDkWqt4-LSDc7ngU3LnwyCG7ueLXEL9yqdj2oXjF1EwMMsPHYOuSExUfRlKUTPI228DVEIXX4EMwUmX2VJgNSE2R9NpSRxJSwzH-XogKLJypCmY7_TXmU77wO9EZ5H4kHjd-rU-6BFkHEwa7dda6-j_-_OuLDOYswBgaDEE4whUcBGxUGkvOPscoehUs4iixNVRpKCuOKYJhrRCNeMxtO-xMTRvlr1F8KuXSkme6llNyy6S9P0LsgnOXsz0FiNCLySsq92oem9JKoprV9WQtyeLbKLGBHpwNnjLAErU18_psblKdDUEUmXrL8kxqAqalgp7UHuvz50X27GKwqkVc9wwOwcHDSpGa3-77ZEamTQIY4XUVl7FFTAoF3vCymEh9eaE"

RAINFOREST_API_KEY = os.getenv('RAINFOREST_API_KEY')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    tracked_products = db.relationship('TrackedProduct', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Price tracking model
class TrackedProduct(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_name = db.Column(db.String(200), nullable=False)
    product_url = db.Column(db.String(500), nullable=False)
    target_price = db.Column(db.Float, nullable=False)
    current_price = db.Column(db.Float, nullable=False)
    source = db.Column(db.String(20), default='amazon')
    price_history = db.Column(db.Text, default='[]')  # JSON string of price history
    last_checked = db.Column(db.DateTime, default=datetime.utcnow)
    notify_on_drop = db.Column(db.Boolean, default=True)

def extract_asin(url):
    pattern = r'/dp/([A-Z0-9]{10})'
    match = re.search(pattern, url)
    return match.group(1) if match else None

def get_amazon_product_details(asin):
    url = "https://api.rainforestapi.com/request"
    params = {
        'api_key': RAINFOREST_API_KEY,
        'type': 'product',
        'amazon_domain': 'amazon.in',
        'asin': asin
    }
    
    try:
        response = requests.get(url, params=params)
        data = response.json()
        
        if 'product' in data:
            return {
                'name': data['product'].get('title', ''),
                'price': float(data['product'].get('buybox_price', {}).get('value', 0)),
                'currency': data['product'].get('buybox_price', {}).get('currency', 'INR'),
            }
    except Exception as e:
        print(f"Error fetching product details: {e}")
    
    return None

def check_prices():
    with app.app_context():
        products = TrackedProduct.query.filter_by(notify_on_drop=True).all()
        for product in products:
            if product.source == 'amazon' and product.product_url:
                asin = extract_asin(product.product_url)
                if asin:
                    details = get_amazon_product_details(asin)
                    if details:
                        new_price = details['price']
                        if new_price < product.current_price:
                            user = User.query.get(product.user_id)
                            send_price_alert(user.email, product.product_name, new_price, product.product_url)
                        product.current_price = new_price
                        db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    products = []
    if request.method == 'POST':
        query = request.form.get('query')
        api_key = os.getenv('GOOGLE_SHOPPING_API_KEY')
        url = f"https://serpapi.com/search.json?engine=google_shopping&q={query}&gl=in&api_key={api_key}"
        
        try:
            response = requests.get(url)
            data = response.json()
            products = data.get('shopping_results', [])
            
            # Convert price strings to float for sorting
            def extract_price(product):
                price_str = product.get('price', '0')
                # Remove currency symbol and convert to float
                try:
                    # Remove currency symbol and commas, then convert to float
                    price = float(price_str.replace('₹', '').replace(',', '').strip())
                except (ValueError, AttributeError):
                    price = float('inf')  # Put items with invalid prices at the end
                return price
            
            # Sort products by price
            products.sort(key=extract_price)
        except Exception as e:
            print(f"Error fetching products: {e}")
    return render_template('search.html', products=products)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            
            # Send welcome email with current deals
            send_welcome_email(user.email)
            flash('Logged in successfully. Check your email for latest deals!')
            return redirect(url_for('home'))
        
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/track-price', methods=['GET', 'POST'])
@login_required
def track_price():
    if request.method == 'POST':
        product_url = request.form.get('product_url')
        target_price = float(request.form.get('target_price'))
        
        if 'amazon' in product_url.lower():
            asin = extract_asin(product_url)
            if asin:
                details = get_amazon_product_details(asin)
                if details:
                    product = TrackedProduct(
                        user_id=current_user.id,
                        product_name=details['name'],
                        product_url=product_url,
                        target_price=target_price,
                        current_price=details['price']
                    )
                    db.session.add(product)
                    db.session.commit()
                    flash('Product added to tracking successfully!')
                else:
                    flash('Unable to fetch product details. Please check the URL.')
            else:
                flash('Invalid Amazon URL. Please provide a valid product URL.')
        else:
            flash('Currently only Amazon India products are supported.')
            
    tracked_products = TrackedProduct.query.filter_by(user_id=current_user.id).all()
    return render_template('track_price.html', products=tracked_products)

@app.route('/delete-tracker/<int:product_id>')
@login_required
def delete_tracker(product_id):
    product = TrackedProduct.query.get_or_404(product_id)
    if product.user_id == current_user.id:
        db.session.delete(product)
        db.session.commit()
        flash('Product tracking removed.')
    return redirect(url_for('track_price'))

# Initialize the scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(func=check_prices, trigger="interval", hours=1)
scheduler.start()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)