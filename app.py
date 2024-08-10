from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import firebase_admin
from firebase_admin import credentials, auth, firestore
from google.oauth2.id_token import verify_oauth2_token
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from werkzeug.security import generate_password_hash, check_password_hash
from backend.OptionsAccount import OptionsAccount
import yfinance as yf
import requests
import time


# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'RohanJeffreyLemonadeChains'

# Initialize Firebase Admin SDK
try:
    cred = credentials.Certificate('lemonadechainskey.json')
    firebase_admin.initialize_app(cred)
    print("Firebase Admin SDK initialized successfully.")
except Exception as e:
    print(f"Error initializing Firebase Admin SDK: {e}")

db = firestore.client()

# Firebase configuration for client-side
firebase_config = {
  "apiKey": "AIzaSyBbld0c61K7UzFmOREUEgFwoI2guhDo1tk",
  "authDomain": "lemonadechains-4be7a.firebaseapp.com",
  "projectId": "lemonadechains-4be7a",
  "storageBucket": "lemonadechains-4be7a.appspot.com",
  "messagingSenderId": "722754044363",
  "appId": "1:722754044363:web:0ef83d8265e2aa1db5764e",
  "measurementId": "G-2TMBXQ8VVB"
}

GOOGLE_CLIENT_SECRETS_FILE = "authentication_client_secret.json"
flow = Flow.from_client_secrets_file(
    GOOGLE_CLIENT_SECRETS_FILE,
    scopes=['https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile', 'openid'],
    redirect_uri= 'https://127.0.0.1:5000/callback'
)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    return render_template('login.html')

@app.route('/google-login')
def google_login():
    authorization_url, state = flow.authorization_url()
    session['state'] = state
    return redirect(authorization_url)

@app.route('/google-signup')
def google_signup():
    authorization_url, state = flow.authorization_url(prompt='consent')  # Ensure consent is asked for sign-up
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    try:
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        request_session = Request()
        id_info = verify_oauth2_token(id_token=credentials.id_token, request=request_session, audience=flow.client_config['client_id'])

        user_id = id_info.get('sub')
        email = id_info.get('email')

        # Check if user already exists
        user_ref = db.collection('users').document(user_id)

        # Check if the get() method is callable

        user_doc = user_ref.get()

        # Debugging exists() check
        print(f"Is exists callable? {callable(user_doc.exists)}")
        print(f"Document exists: {user_doc.exists}")

        if user_doc.exists:
            user_dict = user_doc.to_dict()

            # Load the user's OptionsAccount
            options_account_data = user_dict
            options_account = OptionsAccount(
                username=options_account_data['name'], 
                password='default_password',  # Since it's a Google login, we don't use this password
                initial_balance=options_account_data['balance'],
                risk_free_rate=options_account_data['risk_free_rate'],
                volatility=options_account_data['volatility']
            )
            options_account.positions = options_account_data.get('positions', {})
        else:
            # Create user in Firebase Auth and Firestore
            user = auth.create_user(
                uid=user_id,
                email=email,
                password=generate_password_hash('default_password')  # Use a default password
            )
            
            # Initialize an OptionsAccount for the new user
            options_account = OptionsAccount(username=id_info.get('name'), password='default_password')

            # Store the new user and their OptionsAccount in Firestore
            user_ref.set({
                'email': email,
                'name': id_info.get('name'),
                'password': generate_password_hash('default_password'),
                'balance': options_account.balance,
                'risk_free_rate': options_account.r,
                'volatility': options_account.sigma,
                'positions': {}  # Initialize with empty positions
            })
            
            flash('User signed up successfully with Google', 'success')
    
        # Store the OptionsAccount object in the session
        session['user_id'] = user_id
        session['email'] = email
        session['name'] = id_info.get('name')
        session['options_account'] = options_account.to_dict()  # Ensure it's a dictionary in the session
        
        return redirect(url_for('homepage'))

    except Exception as e:
        print(f"Exception occurred: {e}")
        flash(str(e), 'danger')
        return redirect(url_for('login'))



@app.route('/signin', methods=['POST'])
def signin():
    email = request.form['email']
    password = request.form['password']
    try:
        user = auth.get_user_by_email(email)
        user_ref = db.collection('users').document(user.uid)
        user_doc = user_ref.get()
        if user_doc.exists:
            user_dict = user_doc.to_dict()
            stored_password = user_dict.get('password')

            if check_password_hash(stored_password, password):
                session['user_id'] = user.uid
                session['email'] = email
                session['name'] = user_dict.get('name')
                options_account_data = user_dict
                options_account = OptionsAccount.from_dict(options_account_data)
                session['options_account'] = options_account.to_dict()

                flash(f'User {email} signed in successfully', 'success')
                return redirect(url_for('homepage'))
            else:
                flash('Invalid password', 'danger')
        else:
            print("Document does not exist")
            flash('User record not found', 'danger')
    except Exception as e:
        print(f"Exception occurred: {e}")
        flash(str(e), 'danger')

    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        try:
            user = auth.create_user(email=email, password=password)
            
            # Initialize an OptionsAccount for the new user
            options_account = OptionsAccount(username=name, password=password)

            # Add user and OptionsAccount to Firestore
            user_ref = db.collection('users').document(user.uid)
            user_ref.set({
                'email': email,
                'name': name,
                'password': hashed_password,
                'balance': options_account.balance,
                'risk_free_rate': options_account.r,
                'volatility': options_account.sigma,
                'positions': {}  # Store positions as an empty dict initially
            })
            
            flash('User created successfully', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(str(e), 'danger')
    return render_template('signup.html')

@app.route('/homepage')
def homepage():
    if 'user_id' not in session:
        flash('You are not logged in', 'danger')
        return redirect(url_for('login'))
    return render_template('homepage.html')




"""
@app.route('/search_ticker')
def search_ticker():
    query = request.args.get('query')
    print(f"Received query: {query}")  # Log the received query
    
    if not query:
        return jsonify([])

    try:
        # Attempt to fetch ticker info using yfinance
        ticker = yf.Ticker(query)
        stock_info = ticker.info

        if not stock_info or 'symbol' not in stock_info or 'shortName' not in stock_info:
            print(f"No valid stock info found for query: {query}")  # Log if no valid info is found
            return jsonify([])

        # Log and return the result
        print(f"Found ticker: {stock_info['symbol']} - {stock_info['shortName']}")
        return jsonify([{
            'symbol': stock_info['symbol'],
            'name': stock_info['shortName']
        }])
    
    except Exception as e:
        print(f"Error fetching ticker data: {e}")  # Log any exceptions
        return jsonify([])  # Return an empty list if an error occurs
"""

@app.route('/get_stock_price')
def get_stock_price():
    ticker = request.args.get('ticker')
    
    if not ticker:
        return jsonify({'error': 'Ticker symbol is required'}), 400
    
    try:
        # Fetch stock data using yfinance
        stock = yf.Ticker(ticker)
        
        # Get the current price
        current_price = stock.history(period="1d")['Close'].iloc[-1]
        
        # Get the last 5 days of closing prices for the chart
        history = stock.history(period="5d")['Close'].tolist()

        return jsonify({
            'price': round(current_price, 2),  # Return the current price rounded to 2 decimal places
            'prices': [round(price, 2) for price in history]  # Return the last 5 closing prices
        })
    except Exception as e:
        print(f"Error fetching stock data: {e}")
        return jsonify({'error': 'Failed to fetch stock data'}), 500


@app.route('/search_ticker')
def search_ticker():
    query = request.args.get('query')
    print(f"Received query: {query}")
    
    if not query:
        return jsonify([])

    try:
        # Use custom headers to mimic a browser request
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
        }
        
        response = requests.get(f"https://query2.finance.yahoo.com/v1/finance/search?q={query}", headers=headers)

        if response.status_code == 429:
            print("Rate limited by Yahoo Finance API. Please slow down your requests.")
            return jsonify({"error": "Too many requests, please try again later."})

        if response.status_code != 200:
            print(f"Error: Received status code {response.status_code}")
            return jsonify([])

        # Parse the response as JSON
        search_results = response.json()

        results = []
        for result in search_results.get('quotes', []):
            if 'symbol' in result and 'shortname' in result and result.get('quoteType') == 'EQUITY':
                results.append({
                    'symbol': result['symbol'],
                    'name': result['shortname']
                })
            if len(results) >= 10:
                break

        return jsonify(results)
    
    except Exception as e:
        print(f"Error fetching search results: {e}")
        return jsonify([])


@app.route('/add_to_watchlist', methods=['POST'])
def add_to_watchlist():
    data = request.json
    ticker = data.get('ticker')

    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'})

    user_id = session['user_id']
    user_ref = db.collection('users').document(user_id)
    user_doc = user_ref.get()

    if user_doc.exists:
        user_data = user_doc.to_dict()
        watchlist = user_data.get('watchlist', [])

        if ticker not in watchlist:
            watchlist.append(ticker)
            user_ref.update({'watchlist': watchlist})
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Ticker already in watchlist'})

    return jsonify({'success': False, 'message': 'User record not found'})


@app.route('/simulator')
def simulator():
    if 'user_id' not in session:
        flash('You are not logged in', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    user_ref = db.collection('users').document(user_id)
    user_doc = user_ref.get()

    if user_doc.exists:
        user_data = user_doc.to_dict()
        watchlist = user_data.get('watchlist', [])
        return render_template('simulator.html', watchlist=watchlist)
    else:
        flash('User record not found', 'danger')
        return redirect(url_for('login'))

@app.route('/lemonadelearn')
def lemonade_learn():
    return render_template('lemonadelearn.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        user_id = session['user_id']
        options_account_data = session.get('options_account')

        if options_account_data:
            # Convert the dictionary back into an OptionsAccount object
            options_account = OptionsAccount.from_dict(options_account_data)
            
            # Save OptionsAccount details back to Firestore
            user_ref = db.collection('users').document(user_id)
            user_ref.update({
                'balance': options_account.balance,
                'positions': options_account.positions,
                # Other fields like 'risk_free_rate', 'volatility' can also be updated if changed
            })
        
        # Clear the session
        session.pop('user_id', None)
        session.pop('email', None)
        session.pop('name', None)
        session.pop('options_account', None)
        
        flash('You have been logged out.', 'success')
    
    return redirect(url_for('login'))




@app.route('/users')
def users():
    try:
        users_ref = db.collection('users')
        docs = users_ref.stream()
        users_list = []
        for doc in docs:
            users_list.append(doc.to_dict())
        return render_template('users.html', users=users_list)
    except Exception as e:
        flash(str(e), 'danger')
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc')







