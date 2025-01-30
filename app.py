from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from apscheduler.schedulers.background import BackgroundScheduler
import requests
import os
from dotenv import load_dotenv
from datetime import datetime
import json
import re

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASSWORD')

RAINFOREST_API_KEY = os.getenv('RAINFOREST_API_KEY')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

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

def send_price_alert(user_email, product_name, current_price, product_url):
    msg = Message('Price Drop Alert!',
                 sender=app.config['MAIL_USERNAME'],
                 recipients=[user_email])
    msg.body = f'''The price of {product_name} has dropped to {current_price}!
    Check it out here: {product_url}'''
    mail.send(msg)

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
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        
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
    