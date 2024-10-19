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
from backend.OptionsManager import OptionsManager
import pandas as pd
import numpy as np
from datetime import datetime, timezone
import re
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import atexit
import os

# Initialize Flask app
app = Flask(__name__, static_folder='static')
app.secret_key = 'RohanJeffreyLemonadeChains'




# Initialize Firebase Admin SDK
try:
    cred = credentials.Certificate('lemonadechainskey.json')
    firebase_admin.initialize_app(cred)
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

if 'HEROKU' in os.environ:
    domain = 'https://lemonadechains-38f57839ac55.herokuapp.com/'
else:
    domain = 'http://127.0.0.1:5000'  # Local development domain


GOOGLE_CLIENT_SECRETS_FILE = "authentication_client_secret.json"
flow = Flow.from_client_secrets_file(
    GOOGLE_CLIENT_SECRETS_FILE,
    scopes=['https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile', 'openid'],
    redirect_uri= f'{domain}/callback'
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
        session['balance'] = options_account_data['balance']
        
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
                session['balance'] = options_account_data['balance']

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
            if 'symbol' in result and 'shortname' in result and result.get('quoteType') in ['EQUITY', 'ETF']:
                results.append({
                    'symbol': result['symbol'],
                    'name': result['shortname'],
                    'type': result['quoteType']
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

@app.route('/remove_from_watchlist', methods=['POST'])
def remove_from_watchlist():
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

        if ticker in watchlist:
            watchlist.remove(ticker)
            user_ref.update({'watchlist': watchlist})
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Ticker not in watchlist'})

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
        stockpositions = user_data.get('stockpositions', {})  # Fetch stock positions
        positions = user_data.get('positions', {})  # Fetch options positions
        strategies = user_data.get('strategies', [])  # Fetch strategies
        # Get the OptionsAccount from the session
        options_account_data = session.get('options_account')
        if options_account_data:
            options_account = OptionsAccount.from_dict(options_account_data)
            options_account.signed_in = True  # Ensure the account is considered signed in
            options_account.strategies = strategies
            portfolio_value = options_account.get_portfolio_value()
            balance = options_account.balance
            session['balance'] = balance  # Store balance in session
        else:
            portfolio_value = user_data.get('balance', 0)  # Fallback to user's balance if no OptionsAccount
            session['balance'] = portfolio_value  # Store balance in session

        return render_template('simulator.html', watchlist=watchlist, portfolio_value=portfolio_value, balance=balance, stockpositions=stockpositions, positions=positions, strategies=strategies)
    else:
        flash('User record not found', 'danger')
        return redirect(url_for('login'))

@app.route('/stock/<string:ticker>')
def stock_detail(ticker):
    if 'user_id' not in session:
        flash('You are not logged in', 'danger')
        return redirect(url_for('login'))

    try:
        stock = yf.Ticker(ticker)
        stock_info = stock.info
        
        if not stock_info or 'symbol' not in stock_info:
            flash(f"No data found for ticker {ticker}", 'danger')
            return redirect(url_for('simulator'))
        
        # Fetch stock data for the chart
        history = stock.history(period="1mo")['Close'].tolist()

        # Fetch the user's watchlist and stock positions
        user_id = session['user_id']
        user_ref = db.collection('users').document(user_id)
        user_doc = user_ref.get()

        if user_doc.exists:
            user_data = user_doc.to_dict()
            watchlist = user_data.get('watchlist', [])
            # Check if the user owns the stock and get the quantity
            positions = user_data.get('positions', {})
            if ticker in positions:
                user_owns_stock = True
                user_stock_quantity = positions[ticker]
            else:
                user_owns_stock = False
                user_stock_quantity = 0
        else:
            watchlist = []
            user_owns_stock = False
            user_stock_quantity = 0

        return render_template('stock_detail.html', 
                               ticker=stock_info['symbol'], 
                               name=stock_info['longName'] if 'longName' in stock_info else stock_info['shortName'], 
                               description=stock_info.get('longBusinessSummary', 'No description available.'),
                               prices=history,
                               watchlist=watchlist,
                               user_owns_stock=user_owns_stock,
                               user_stock_quantity=user_stock_quantity)

    except Exception as e:
        flash(f"Error fetching stock data: {e}", 'danger')
        return redirect(url_for('simulator'))

    
@app.route('/etf/<string:ticker>')
def etf_detail(ticker):
    if 'user_id' not in session:
        flash('You are not logged in', 'danger')
        return redirect(url_for('login'))

    try:
        etf = yf.Ticker(ticker)
        etf_info = etf.info
        
        if not etf_info or 'symbol' not in etf_info:
            flash(f"No data found for ticker {ticker}", 'danger')
            return redirect(url_for('simulator'))
        
        # Fetch ETF data for the chart
        history = etf.history(period="1mo")['Close'].tolist()

        # Fetch the user's watchlist
        user_id = session['user_id']
        user_ref = db.collection('users').document(user_id)
        user_doc = user_ref.get()

        if user_doc.exists:
            user_data = user_doc.to_dict()
            watchlist = user_data.get('watchlist', [])
        else:
            watchlist = []

        return render_template('etf_detail.html', 
                               ticker=etf_info['symbol'], 
                               name=etf_info['longName'] if 'longName' in etf_info else etf_info['shortName'], 
                               description=etf_info.get('longBusinessSummary', 'No description available.'),
                               prices=history,
                               watchlist=watchlist)

    except Exception as e:
        flash(f"Error fetching ETF data: {e}", 'danger')
        return redirect(url_for('simulator'))




@app.route('/options/<ticker>')
def options_detail(ticker):
    if 'user_id' not in session:
        flash('You are not logged in', 'danger')
        return redirect(url_for('login'))

    # Fetch available expiration dates for the ticker
    options_manager = OptionsManager()
    ticker_data = yf.Ticker(ticker)
    expiration_dates = ticker_data.options

    return render_template('options_detail.html', ticker=ticker, expiration_dates=expiration_dates)


@app.route('/get_options_data', methods=['POST'])
def get_options_data():
    data = request.json
    ticker = data.get('ticker')
    expiration_date = data.get('expiration_date')
    strike_price_range = data.get('strike_price_range')
    option_type_filter = data.get('option_type')


    if not ticker or not expiration_date:
        return jsonify({'error': 'Ticker and expiration date are required'}), 400

    options_manager = OptionsManager()
    try:
        chain_data = options_manager.getChainData(ticker, expiration_date)
        calls = chain_data.calls
        puts = chain_data.puts

        print(f"Calls: {calls.shape}, Puts: {puts.shape}")

        calls['impliedVolatility'] = calls['impliedVolatility'].apply(lambda x: round(x * 100, 2) if x is not None else x)
        puts['impliedVolatility'] = puts['impliedVolatility'].apply(lambda x: round(x * 100, 2) if x is not None else x)

        # Apply filtering
        if strike_price_range:
            min_strike, max_strike = strike_price_range
            calls = calls[(calls['strike'] >= min_strike) & (calls['strike'] <= max_strike)]
            puts = puts[(puts['strike'] >= min_strike) & (puts['strike'] <= max_strike)]

        if option_type_filter == 'call':
            puts = pd.DataFrame()  # Empty DataFrame for puts
        elif option_type_filter == 'put':
            calls = pd.DataFrame()  # Empty DataFrame for calls

        # Replace NaN values with None (JSON-compatible null)
        calls = calls.replace({np.nan: None})
        puts = puts.replace({np.nan: None})

        # Convert implied volatility to percentage
        

        calls_data = calls.to_dict(orient='records')
        puts_data = puts.to_dict(orient='records')

        print(f"Filtered Calls: {len(calls_data)}, Filtered Puts: {len(puts_data)}")

        return jsonify({'calls': calls_data, 'puts': puts_data})

    except Exception as e:
        print(f"Error fetching options data: {e}")
        return jsonify({'error': 'Failed to fetch options data'}), 500

@app.route('/get_option_profit_data', methods=['POST'])
def get_option_profit_data():
    data = request.json
    contract_symbol = data.get('ticker')
    strike = float(data.get('strike'))
    expiration_date = data.get('expiration')
    option_type = data.get('type').lower() if data.get('type') else None

    print(f"Received option data: Ticker: {contract_symbol}, Strike: {strike}, Expiration: {expiration_date}, Type: {option_type}")


    # Extract the actual stock ticker from the contract symbol
    ticker_match = re.match(r"([A-Z]+)\d+[C|P]", contract_symbol)
    if ticker_match:
        ticker = ticker_match.group(1)  # This extracts only the ticker part, e.g., "GOOGL"
    else:
        return jsonify({'error': f'Invalid contract symbol format: {contract_symbol}'}), 400

    # Log the received data explicitly
    print(f"Received data - Ticker: {ticker}, Strike: {strike}, Expiration: {expiration_date}, Type: {option_type}")

    if option_type not in ['call', 'put']:
        return jsonify({'error': 'Invalid option type. Use "call" or "put".'}), 400

    # Convert the expiration date
    expiration_date = datetime.strptime(expiration_date, "%m/%d/%Y, %I:%M:%S %p")

    # Retrieve the options account from the session
    options_account_data = session.get('options_account')
    if not options_account_data:
        return jsonify({'error': 'No options account found in session.'}), 400

    options_account = OptionsAccount.from_dict(options_account_data)
    options_account.signed_in = True

    try:
        # Use the OptionsAccount function to calculate the profit/loss data
        profit_loss_data = options_account.plot_single_profit_loss_data(ticker, expiration_date, option_type, strike)

        print(f"Generated profit/loss data for {ticker}: {profit_loss_data}")

        # Return the processed data as JSON
        return jsonify(profit_loss_data)

    except Exception as e:
        print(f"Error generating profit/loss data: {e}")
        return jsonify({'error': f'Error generating profit/loss data: {e}'}), 500


@app.route('/lemonadelearn')
def lemonadelearn_redirect():
    return redirect(url_for('lemonadelearn', article_number=1))

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


"""
@app.route('/trade_option', methods=['POST'])
def trade_option():
    data = request.json
    full_ticker = data.get('ticker')  # This is the full option contract ticker
    strike = float(data.get('strike'))
    expiration_date = datetime.strptime(data.get('expiration'), "%m/%d/%Y, %I:%M:%S %p")
    option_type = data.get('type').lower()
    quantity = int(data.get('quantity'))
    action = data.get('action').lower()

    print(f"Processing trade: {action} {quantity} {option_type} options for {full_ticker} at strike {strike} expiring on {expiration_date}")

    # Improved extraction of underlying ticker using regex
    match = re.match(r"([A-Z]+)(\d+)(C|P)(\d+)", full_ticker)
    if match:
        underlying_ticker = match.group(1)
    else:
        print("Could not parse the option ticker symbol")
        return jsonify({'error': 'Invalid option ticker symbol'}), 400

    print(f"Extracted underlying ticker: {underlying_ticker}")

    if 'user_id' not in session:
        return jsonify({'error': 'User not logged in'}), 400

    options_account_data = session.get('options_account')
    if not options_account_data:
        print("No options account found in session.")
        return jsonify({'error': 'No options account found in session.'}), 400

    options_account = OptionsAccount.from_dict(options_account_data)
    options_account.signed_in = True

    try:
        if action == 'buy':
            success, message = options_account.buy_option(underlying_ticker, expiration_date, option_type, strike, quantity)
        elif action == 'sell':
            option_key = f"{option_type}_{strike}"
            success, message = options_account.sell_option(underlying_ticker, expiration_date, option_type, strike, quantity)
        else:
            return jsonify({'error': 'Invalid action'}), 400

        if not success:
            print(f"Trade error: {message}")
            return jsonify({'error': message}), 400

        # Update the session and Firestore with the modified options account
        session['options_account'] = options_account.to_dict()
        session['balance'] = options_account.balance  # Update balance in session

        user_ref = db.collection('users').document(session['user_id'])
        user_ref.update({
            'balance': options_account.balance,
            'positions': options_account.positions,
            'stockpositions': options_account.stockpositions
        })

        print(f"Trade successful: {action} {quantity} {option_type} options for {underlying_ticker}")
        return jsonify({'success': True, 'balance': options_account.balance})

    except Exception as e:
        print(f"Error processing trade: {e}")
        return jsonify({'error': 'Failed to process trade'}), 500
    

@app.route('/buy_stock', methods=['POST'])
def buy_stock():
    data = request.json
    ticker = data.get('ticker')
    quantity = int(data.get('quantity'))

    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'User not logged in'}), 400

    options_account_data = session.get('options_account')
    if not options_account_data:
        return jsonify({'success': False, 'error': 'No options account found in session.'}), 400

    options_account = OptionsAccount.from_dict(options_account_data)
    options_account.signed_in = True

    success, message = options_account.buy_stock(ticker, quantity)

    if not success:
        return jsonify({'success': False, 'error': message}), 400

    # Update the session and Firestore with the modified options account
    session['options_account'] = options_account.to_dict()
    session['balance'] = options_account.balance

    user_ref = db.collection('users').document(session['user_id'])
    user_ref.update({
        'balance': options_account.balance,
        'stockpositions': options_account.stockpositions,
        'positions': options_account.positions
    })

    return jsonify({'success': True, 'balance': options_account.balance})

@app.route('/sell_stock', methods=['POST'])
def sell_stock():
    data = request.json
    ticker = data.get('ticker')
    quantity = int(data.get('quantity'))

    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'User not logged in'}), 400

    options_account_data = session.get('options_account')
    if not options_account_data:
        return jsonify({'success': False, 'error': 'No options account found in session.'}), 400

    options_account = OptionsAccount.from_dict(options_account_data)
    print(f"Data gotten right from session: {options_account.stockpositions}")
    options_account.signed_in = True

    success, message = options_account.sell_stock(ticker, quantity)

    if not success:
        return jsonify({'success': False, 'error': message}), 400

    # Update the session and Firestore with the modified options account
    session['options_account'] = options_account.to_dict()
    session['balance'] = options_account.balance

    user_ref = db.collection('users').document(session['user_id'])
    user_ref.update({
        'balance': options_account.balance,
        'stockpositions': options_account.stockpositions,
        'positions': options_account.positions
    })

    return jsonify({'success': True, 'balance': options_account.balance})
"""

def update_firestore_with_options_account():
    """Helper function to update Firestore with the current options account data."""
    if 'user_id' in session and 'options_account' in session:
        user_id = session['user_id']
        options_account_data = session['options_account']
        
        # Prepare the data to update in Firestore
        update_data = {
            'balance': options_account_data['balance'],
            'positions': options_account_data['positions'],
            'stockpositions': options_account_data['stockpositions']
        }
        
        # Log the data being sent to Firestore
        print(f"Updating Firestore for user {user_id} with data: {update_data}")
        
        # Update Firestore with the new data
        user_ref = db.collection('users').document(user_id)
        user_ref.update(update_data)
    else:
        print("No user ID or options account in session to update Firestore.")


@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    data = request.json
    cart = session.get('cart', [])

    print(f"Add to Cart - Received Data: {data}")  # Debug: log incoming data
    # Check if it's a strategy
    if data.get('type') == 'strategy':
        strategy_name = data.get('name')
        if not strategy_name:
            print("Add to Cart Error: Strategy name is missing")  # Debug: Strategy name missing
            return jsonify({'success': False, 'message': 'Strategy name is required'}), 400

        # Ensure the strategy has a 'contracts' key
        strategy_data = {
            'type': 'strategy',
            'name': strategy_name,
            'contracts': data.get('strategy', [])
        }
        print(f"Adding Strategy: {strategy_data}")  # Debug: log strategy data
        cart.append(strategy_data)
    
    # Check if it's an option, stock, or other individual item
    elif data.get('type') == 'option' or data.get('type') == 'stock' or data.get('type') == 'etf':
        print(f"Adding non-strategy item to cart: {data}")  # Debug: log non-strategy items
        cart.append(data)
    
    # If the type is missing or unrecognized
    else:
        print("Error: Unrecognized item type")  # Debug
        return jsonify({'success': False, 'message': 'Unrecognized item type'}), 400

    session['cart'] = cart
    print(f"Updated Cart in Session: {session['cart']}")  # Debug: log updated cart

    return jsonify({'success': True})

@app.route('/remove_from_cart', methods=['POST'])
def remove_from_cart():
    data = request.json
    cart = session.get('cart', [])

    print(f"Remove from Cart - Received Data: {data}")  # Debug: log incoming data

    # Check if it's a strategy being removed
    if data.get('type') == 'strategy':
        strategy_name = data.get('name')
        print(f"Attempting to remove strategy: {strategy_name}")  # Debug: log strategy name
        session['cart'] = [item for item in cart if item.get('type') != 'strategy' or item.get('name') != strategy_name]
    # Otherwise, it's an individual item
    else:
        print(f"Attempting to remove non-strategy item: {data['contract']} with action {data['action']}")  # Debug
        session['cart'] = [item for item in cart if item.get('contract') != data.get('contract') or item.get('action') != data.get('action')]

    print(f"Updated Cart after Removal: {session['cart']}")  # Debug: log updated cart

    return jsonify({'success': True})


@app.route('/cart')
def view_cart():
    cart = session.get('cart', [])
    return render_template('cart.html', cart=cart)

@app.route('/confirm_trades', methods=['POST'])
def confirm_trades():
    cart = session.get('cart', [])
    options_account_data = session.get('options_account')
    if not options_account_data:
        print("Confirm Trades Error: No options account found in session")  # Debug
        return jsonify({'success': False, 'error': 'No options account found in session.'})

    options_account = OptionsAccount.from_dict(options_account_data)
    options_account.signed_in = True

    user_id = session['user_id']
    user_ref = db.collection('users').document(user_id)
    user_doc = user_ref.get()
    user_data = user_doc.to_dict()

    # Ensure the user has a strategies field; if not, create an empty list
    strategies = user_data.get('strategies', [])

    print(f"Processing cart: {cart}")  # Debug: log cart content

    for item in cart:
        print(f"Processing item: {item}")  # Debug: log each item being processed
        if item['type'] == 'option':
            # Process options trades (buy/sell)
            expiration_date = datetime.strptime(item['expiration'], "%m/%d/%Y, %I:%M:%S %p")
            option_type = 'call' if 'C' in item['contract'] else 'put'
            quantity = int(item.get('quantity', 1))
            strike_price = float(item['strike'])
            ticker = item['contract'][:-15]

            print(f"Processing Option: {ticker}, {strike_price}, {option_type}, {quantity}, {expiration_date}")  # Debug

            
            if item['action'] == 'buy':
                success, message = options_account.buy_option(ticker, expiration_date, option_type, strike_price, quantity)
            elif item['action'] == 'sell':
                success, message = options_account.sell_option(ticker, expiration_date, option_type, strike_price, quantity)
            else:
                success, message = False, "Invalid action for option"
            

        elif item['type'] == 'stock' or item['type'] == 'etf':
            # Handle stock trades
            print(f"Processing Stock/ETF: {item['contract']}, {item['action']}, {item['quantity']}")  # Debug
            quantity = int(item.get('quantity', 1))
            if item['action'] == 'buy':
                success, message = options_account.buy_stock(item['contract'], quantity)
            elif item['action'] == 'sell':
                success, message = options_account.sell_stock(item['contract'], quantity)
            else:
                success, message = False, "Invalid action for stock"

        elif item['type'] == 'strategy':
            print(f"Processing strategy: {item['name']}")  # Debug: log strategy name
            strategy_contracts = []

            # Process each contract in the strategy

            balance_change = 0

            for contract in item['contracts']:
                expiration_date = datetime.strptime(contract['expiration'], "%m/%d/%Y, %I:%M:%S %p")
                option_type = contract['option_type']
                strike_price = float(contract['strike'])
                ticker = contract['contract'][:-15]

                print(f"Processing Strategy Contract: {ticker}, {strike_price}, {option_type}")  # Debug
                
                """
                What was causing issues before was this paragraph, causing contracts to go both in individual positions and strategies.
                if contract['action'] == 'buy':
                    success, message = options_account.buy_option(ticker, expiration_date, option_type, strike_price, 1)
                elif contract['action'] == 'sell':
                    success, message = options_account.sell_option(ticker, expiration_date, option_type, strike_price, 1)
                else:
                    success, message = False, "Invalid action for option"
                """

                options_manager_instance = OptionsManager()

                single_change = options_manager_instance.calculateOptionPrice(ticker, strike_price, expiration_date, option_type, options_account.get_risk_free_rate())

                balance_change += single_change


                # Add contract to the strategy contracts list
                strategy_contracts.append(contract)

            
            # After processing, add the strategy to the user's strategies list
            strategies.append({
                'name': item['name'],
                'contracts': strategy_contracts
            })

            options_account.change_balance(-1 * balance_change)

    # Save updates
    session['options_account'] = options_account.to_dict()
    print(f"Session updated with new options account: {session['options_account']}")  # Debug

    # Update Firestore with the new strategies list
    update_data = {
        'balance': options_account.balance,
        'positions': options_account.positions,
        'stockpositions': options_account.stockpositions,
        'strategies': strategies  # Add the strategies list to the user's document
    }
    
    user_ref.update(update_data)
    print(f"Firestore updated with new strategies: {strategies}")

    session.pop('cart', None)  # Clear the cart after confirming trades
    print(f"Cart cleared after trade confirmation")  # Debug

    return jsonify({'success': True})


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
    

@app.route('/get_combined_strategy_profit_data', methods=['POST'])
def get_combined_strategy_profit_data():
    
    strategy = request.json  # This will be a list of selected options contracts for the strategy
    print(f"Received strategy data: {strategy}")  # Debug: log incoming strategy data


    if not strategy:
        return jsonify({'error': 'No strategy provided'}), 400

    try:
        # Retrieve the options account from session
        options_account_data = session.get('options_account')
        if not options_account_data:
            print("Error: No options account found in session.")  # Debugging
            return jsonify({'error': 'No options account found in session.'}), 400
        
        options_account = OptionsAccount.from_dict(options_account_data)
        options_account.signed_in = True

        # Call the function to calculate combined strategy profit/loss
        print("Calling plot_combined_profit_loss with strategy data...")  # Debugging before calculation
        stock_price_range, cumulative_profits, breakeven_points, max_profit, max_loss = options_account.plot_combined_profit_loss(strategy)

        print(f"Combined strategy data calculated: Stock Price Range: {stock_price_range}, Cumulative Profits: {cumulative_profits}")  # Debugging


        # Return the data to the frontend
        return jsonify({
            'stock_price_range': stock_price_range.tolist(),
            'cumulative_profits': cumulative_profits.tolist(),
            'breakeven_points': breakeven_points,  # Return breakeven points
            'max_profit': f"${max_profit:.2f}",
            'max_loss': f"${max_loss:.2f}"
        })

    except Exception as e:
        print(f"Error calculating combined strategy profit/loss: {e}")
        return jsonify({'error': f"Error calculating combined strategy profit/loss: {e}"}), 500

@app.route('/reset_cart')
def reset_cart():
    session['cart'] = []  # Clear the cart by resetting it to an empty list
    return jsonify({'success': True, 'message': 'Cart has been reset'})



@app.route('/clear_positions', methods=['GET'])
def clear_positions():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'}), 400

    try:
        # Retrieve the OptionsAccount from the session
        options_account_data = session.get('options_account')
        if not options_account_data:
            return jsonify({'success': False, 'message': 'No options account found in session.'}), 400

        # Recreate the OptionsAccount object
        options_account = OptionsAccount.from_dict(options_account_data)
        
        # Clear stockpositions and positions
        options_account.stockpositions.clear()
        options_account.positions.clear()
        options_account.strategies = []

        # Update the session data
        session['options_account'] = options_account.to_dict()

        # Update Firestore with cleared positions
        user_id = session['user_id']
        user_ref = db.collection('users').document(user_id)
        user_ref.update({
            'stockpositions': options_account.stockpositions,
            'positions': options_account.positions,
            'strategies': options_account.strategies
        })

        return jsonify({'success': True, 'message': 'Positions cleared successfully'})

    except Exception as e:
        print(f"Error clearing positions: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/sell_stock', methods=['POST'])
def sell_stock():
    data = request.json
    ticker = data.get('ticker')
    quantity = int(data.get('quantity'))

    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'User not logged in'})

    options_account_data = session.get('options_account')
    if not options_account_data:
        return jsonify({'success': False, 'error': 'No options account found in session.'})

    options_account = OptionsAccount.from_dict(options_account_data)
    options_account.signed_in = True

    success, message = options_account.sell_stock(ticker, quantity)

    if not success:
        return jsonify({'success': False, 'error': message})

    # Update the session and Firestore with the modified options account
    session['options_account'] = options_account.to_dict()
    session['balance'] = options_account.balance

    user_ref = db.collection('users').document(session['user_id'])
    user_ref.update({
        'balance': options_account.balance,
        'stockpositions': options_account.stockpositions,
    })

    return jsonify({'success': True, 'balance': options_account.balance})


@app.route('/sell_option', methods=['POST'])
def sell_option():
    data = request.json
    ticker = data.get('ticker')
    strike = float(data.get('strike'))
    expiration = datetime.strptime(data.get('expiration'), "%m/%d/%Y, %I:%M:%S %p")
    option_type = data.get('type')
    quantity = int(data.get('quantity'))

    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'User not logged in'})

    options_account_data = session.get('options_account')
    if not options_account_data:
        return jsonify({'success': False, 'error': 'No options account found in session.'})

    options_account = OptionsAccount.from_dict(options_account_data)
    options_account.signed_in = True

    success, message = options_account.sell_option(ticker, expiration, option_type, strike, quantity)

    if not success:
        return jsonify({'success': False, 'error': message})

    # Update the session and Firestore with the modified options account
    session['options_account'] = options_account.to_dict()
    session['balance'] = options_account.balance

    user_ref = db.collection('users').document(session['user_id'])
    user_ref.update({
        'balance': options_account.balance,
        'positions': options_account.positions,
    })

    return jsonify({'success': True, 'balance': options_account.balance})


@app.route('/sell_strategy', methods=['POST'])
def sell_strategy():
    data = request.json
    strategy_name = data.get('strategy_name')

    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'User not logged in'}), 400

    # Retrieve the OptionsAccount and user data from the session and Firestore
    user_id = session['user_id']
    user_ref = db.collection('users').document(user_id)
    user_doc = user_ref.get()

    if not user_doc.exists:
        return jsonify({'success': False, 'error': 'User record not found'})

    user_data = user_doc.to_dict()
    options_account_data = session.get('options_account')
    if not options_account_data:
        return jsonify({'success': False, 'error': 'No options account found in session.'})

    options_account = OptionsAccount.from_dict(options_account_data)

    strategies = user_data.get('strategies', [])
    strategy_to_sell = None

    # Find the strategy to sell
    for strategy in strategies:
        if strategy['name'] == strategy_name:
            strategy_to_sell = strategy
            break

    if not strategy_to_sell:
        return jsonify({'success': False, 'error': 'Strategy not found'}), 400

    total_value = 0  # This will store the total value of the strategy

    # Calculate the value of each contract using the Black-Scholes model
    for contract in strategy_to_sell['contracts']:
        expiration_date = datetime.strptime(contract['expiration'], "%m/%d/%Y, %I:%M:%S %p")
        strike_price = float(contract['strike'])
        option_type = contract['option_type']
        ticker = contract['contract'][:-15]  # Extract the stock ticker

        # Calculate Black-Scholes value using the OptionsManager's method
        price = options_account.options_manager.calculateOptionPrice(
            ticker=ticker,
            strike_price=strike_price,
            expiration_date=expiration_date,
            option_type=option_type,
            r=options_account.r  # Risk-free rate from the OptionsAccount
        )

        if price is None:
            print(f"Failed to calculate option price for {ticker} at strike {strike_price}.")
            return jsonify({'success': False, 'error': 'Failed to calculate option price'}), 500

        total_value += price

    # Add the total value of the strategy to the user's balance
    options_account.balance += total_value

    # Remove the strategy from the user's list of strategies
    strategies = [strategy for strategy in strategies if strategy['name'] != strategy_name]

    # Update session and Firestore
    session['options_account'] = options_account.to_dict()
    session['balance'] = options_account.balance

    # Update Firebase
    user_ref.update({
        'balance': options_account.balance,
        'strategies': strategies
    })

    return jsonify({
        'success': True,
        'balance': options_account.balance,
        'message': f'Successfully sold strategy "{strategy_name}" for ${total_value:.2f}'
    })

@app.route('/test_portfolio_value')
def test_portfolio_value():
    options_account_data = session.get('options_account')
    print(options_account_data)
    options_account = OptionsAccount.from_dict(options_account_data)
    options_account.signed_in = True
    print(options_account.get_portfolio_value())
    return jsonify({'success': True, 'message': 'Portfolio Value has been gotten'})



def record_portfolio_value():
    """Record the portfolio value for the current session user and update Firestore."""
    try:
        # Retrieve the options account from session
        options_account_data = session.get('options_account')

        if not options_account_data:
            print("No options account found in session.")
            return

        # Reconstruct the OptionsAccount object from session data
        options_account = OptionsAccount.from_dict(options_account_data)
        options_account.signed_in = True

        # Get the user ID from the session
        user_id = session['user_id']
        user_ref = db.collection('users').document(user_id)
        user_doc = user_ref.get()
        user_data = user_doc.to_dict()

        # Load strategies for the user and assign to options account
        strategies = user_data.get('strategies', [])
        options_account.strategies = strategies

        # Calculate the portfolio value
        portfolio_value = options_account.get_portfolio_value()
        print(f"User ID: {user_id}, Portfolio Value: {portfolio_value}")

        # Create a timestamp for the portfolio value
        timestamp = datetime.utcnow()

        # Retrieve the current portfolio history from the user document
        portfolio_history = user_data.get('portfolio_history', [])

        # Append the new portfolio value and timestamp as a dictionary to the portfolio history
        portfolio_history.append({
            'portfolio_value': portfolio_value,
            'timestamp': timestamp
        })

        # Update the user document with the new portfolio history
        user_ref.update({
            'portfolio_history': portfolio_history,
            'latest_portfolio_value': portfolio_value,
            'last_updated': timestamp
        })

        print("Portfolio value recorded successfully in Firestore.")

    except Exception as e:
        print(f"Error recording portfolio value: {e}")




@app.route('/get_portfolio_history', methods=['GET'])
def get_portfolio_history():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'})

    user_id = session['user_id']
    user_ref = db.collection('users').document(user_id)
    user_doc = user_ref.get()

    if not user_doc.exists:
        return jsonify({'success': False, 'message': 'User record not found'})

    user_data = user_doc.to_dict()
    portfolio_history = user_data.get('portfolio_history', [])

    if not portfolio_history:
        return jsonify({'success': False, 'message': 'No portfolio history found.'})

    # Collect timestamps and portfolio values from the list of dictionaries
    timestamps = []
    portfolio_values = []

    for entry in portfolio_history:
        timestamps.append(entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S'))
        portfolio_values.append(entry['portfolio_value'])
    
    print("Timestamps: ", timestamps)
    print("Portfolio Values: ", portfolio_values)

    timestamps, portfolio_values = zip(*sorted(zip(timestamps, portfolio_values)))

    return jsonify({
        'timestamps': timestamps,
        'portfolio_values': portfolio_values
    })



@app.route('/lemonadelearn/<int:article_number>')
def lemonadelearn(article_number):
    articles = [
        {
            'title': 'Introduction',
            'content': '''
                <p>Welcome to LemonadeLearn!</p>
                <p>Here is where you will learn about how options work. Once done, you can head over to the simulator to test your knowledge in real time. Here at LemonadeChains, we believe that mistakes help you improve, and you can do just that in our simulator without having to worry about losing real money. We hope that once you’ve earned enough experience on our platform, you can apply that to the real world and make better financial decisions.</p>
                <p>LemonadeLearn will give you a strong foundational base on how options work theoretically, and we will also give you pointers on how to apply that knowledge in our simulator. This guide assumes that you have no knowledge of options, but we assume that you have a basic understanding of how the stock market works. If you aren’t confident in your stock market knowledge, click here.</p>
                <p>Let’s begin.</p>
            ''',
            'image': None
        },
        {
            'title': 'So, what is an option?',
            'content': '''
                <p>Let’s start simple.</p>
                <p>The foundational way for someone to make money in the stock market is to buy low and sell high. This type of thinking exists everywhere. Companies want to increase revenues and reduce costs. In movies, Wall Street traders buy stocks and watch as the line goes up. People think like this because it’s easy; you don’t have to have a degree to figure this out. If I buy LemonadeChains stock at $100, and I sell at $101, I’ve made $1. Buy low, sell high.</p>
                <p>A good way to picture this is with a profit and loss chart. On the x-axis, we plot the change in the stock’s price after we bought the stock, and on the y-axis we plot how much money we make.</p>
                <img src="{simple_pl_url}" alt="Simple PnL Chart" style="max-width: 100%; height: auto;">
                <p>Using the above points, we can get a PnL chart that looks like this:</p>
                <p>As we noted before, if I buy low and sell high, I make money. If I buy high and sell low, I lose money. From the graph, we can also see that we make money in proportion to how much the stock moves. If LemonadeChains stock goes up $1, then I pocket $1 when I sell.</p>
                <p>Buying and selling stocks the standard way works well when you think a stock will go up a lot and stay up. But what if I think the stock isn’t going to move at all? What if I think the stock will move a lot, but I don’t know which way it will move? What if I think the stock will go up just a little bit? What if I think the stock will go up a lot, but I notice that the stock is very risky?</p>
                <p>All of these questions can be answered with the flexibility of an options contract. An options contract will allow you to make money in different situations, not just when the stock goes up a lot.</p>
                <p>Think of an options contract as a contract. It is a piece of paper with several points written on it. When the buyer buys the contract, they “sign” the contract, and so does the seller when they sell the contract. By “signing” the contract, they both agree to the points written on the contract.</p>
                <p>The points on the contract are as follows:</p>
                <p>1. The buyer of the contract has the right but not the obligation to buy 100 shares of a certain stock at a predetermined price. The seller must provide the buyer with those shares at that price if the buyer exercises that right. If the buyer does not exercise that right – as they do not have the obligation to do so – the seller does not have to provide the shares.</p>
                <p>2. The contract will expire at a predetermined date. The buyer can exercise their right any time up until expiry.</p>
                <p>You can see now where options contracts get their pricing from. Similar to the stock market where if there’s more demand than supply for a stock the stock price will go up and vice versa, a contract’s price is also affected by supply and demand. If a lot of people want the right to buy a stock at a certain price, then the price will go up. If people don’t want that right, then the price will go down.</p>
                <p>Something that makes options contracts unique is its ability to expire. This is partly because no one would agree to a contract indefinitely, because someone could just wait a very long time until the stock finally goes above the agreed upon price. With a deadline in place, both sides will have a more equal approach. Different contracts have different expiry dates, which leads to different pricing and values.</p>
                <p>Using the above points, we can get a PnL chart that looks like this:</p>
                <img src="{capped_pl_url}" alt="Capped PnL Chart" style="max-width: 100%; height: auto;">
                <p>At first, this graph might feel intimidating. Why are my losses capped? Why do I lose money if the stock doesn’t move?</p>
                <p>Looking back to the above points we can make sense of the graph. First off, we paid a certain price for the contract. This automatically shifts the original stock chart down by the amount we paid.</p>
                <img src="{showing_stock_shift_url}" alt="Showing Shift Chart" style="max-width: 100%; height: auto;">
                <p>Since we have the right, but not the obligation to buy a stock at a certain price, we would never use that right if the stock price was below that value; we could just buy the stock at market price without the option. That means that if the stock goes down a ton, we will only lose the amount we paid for the contract.</p>
                <img src="{showing_option_loss_url}" alt="Showing Option Loss Chart" style="max-width: 100%; height: auto;">
                <p> 
                The point where the line turns from horizontal to positive slope is where the previously agreed to price is. At that point, it becomes more worth it to buy the stock at the agreed upon price than to buy at market price. If the price of the stock is just above the agreed upon price, you will still be losing money on this contract because the difference between the actual and agreed upon price is smaller than the price you paid for the contract in the first place. <br><br>

                At a certain point, the difference between actual and agreed upon price becomes greater than the amount of money that you paid for the contract, and you start making money. Each contract has a different point where you break even. <br><br>

                There are different ways for you to “make money” on an options contract. Similar to how you don’t actually “make money” until you sell a stock, there are multiple things that you can do to get a profit (or a loss) on your position. <br><br>

                The first way is to use your right to buy the shares at a certain price. Let’s say you bought a contract where you have the right to buy a stock at $100. The price now has risen to $200. You could use that right that was stated in your contract to buy the stock at $100, which is effectively a 50% discount. You can use this right anytime until your contract expires. <br><br>

                A similar method would be to wait until your contract expires, and then if the agreed upon price is below the current price, your contract will be automatically exercised and then sold. Using the previous example, instead of you owning shares at the purchased price of $100, you “buy” the shares at $100 and then immediately “sell” them at $200. Buy low, sell high. <br><br>

                Another way you can make money is by just selling the contract itself. Contracts are like pieces of paper that can be bought and sold. When you bought your contract, someone sold it to you. Likewise, if the price of the stock continues to rise and your right but not the obligation to buy the stock at a certain price becomes more valuable, you can sell it to someone else who wants to use that right. Buy low, sell high. <br><br>

                That’s the basic anatomy of an options contract.
                </p>
            '''.format(simple_pl_url=url_for('static', filename='images/simplePLChart.png'), capped_pl_url=url_for('static', filename='images/cappedPLChart.png'), showing_stock_shift_url=url_for('static', filename='images/showingStockShift.png'), showing_option_loss_url=url_for('static', filename='images/showingOptionLoss.png')), 
            'image': None
        },
        {
            'title': 'Options Terminology',
            'content': '''

            <p> 
            

In the last article, we went over the basic structure of an option. Now, we’ll go through the more professional terminology for what everything is. <br><br>

As we said before, an option is a contract that agrees to buy a stock at a certain price. The stock that you are agreeing on about the price is called the underlying asset. Think of it this way; you are trading a contract based on a stock, so the stock should be “under” that contract. <br><br>

The price you are agreeing to buy the stock at is called the strike price. You are “striking” a deal when you agree to the contract, so the price in the contract is part of the deal that you “struck”. <br><br>

The price that you are paying for the right but not the obligation to buy the underlying at the strike price is called the premium. In simple terms, the premium is the price you pay for the contract. <br><br>

The date the contract expires is called the expiry date. It’s similar to how your milk expires. Once that date is met, your contract goes bad. You lose the right to buy the underlying at the strike price. If you want to use your right to buy the underlying asset at the strike price, you can exercise your contract and buy the shares. On the expiry date, if your strike price is below the current price of the stock, your contract will be automatically exercised, and if you don’t have enough funds to buy the shares, the profit of the difference between current and strike price will be given to you. <br><br>

Another important distinction to know is the difference between Out of the money (OTM), In the money (ITM), and at the money (ATM). This gives a good descriptor of “where” your contract is. Out of the money means that your contract is currently worthless if it were to expire right now. The price of the underlying asset is below your strike price. It would be cheaper to buy the underlying at the market price than at your strike price. At the money is when the current market price of the stock is at the same price of your strike price. In the money means that if the contract were to expire now, your contract has value. The current market price is above your strike price. <br><br>

In our first article, we talked about how the contract was an agreement to buy shares of a stock at a certain price. In this contract, if the stock goes up, your contract will gain value. This type of contract is called a call options contract or just a call. There is another type of contract that works in a similar way, except that it profits when the stock goes down. This type of contract is called a put options contract or just a put. For put contracts, instead of agreeing to buy shares at a certain strike price, you are agreeing to sell shares at a certain strike price. You want the price of the underlying to go down. Think of it like sell high buy low instead of buy low sell high. <br><br>
            
            </p>
                
            ''',
            'image': None
        },
        {
            'title': 'Option Spreads',
            'content': '''
                <p>One of the most important concepts to understand in the stock market is risk. Someone might say that a stock is going to go up a million percent. The key word here is might. What if it doesn’t? What are you risking?</p>
                <p>As an investor and trader, it’s important to understand your risk as well as your reward. Even if you do extremely detailed research, there’s still a chance that something may not go your way. The best way to protect yourself against excessive risk is to hedge. Hedging is protecting yourself from losses by trading other securities to reduce losses. Think of it like insurance. The best hedge is when you buy a stock and short it at the same time. No matter what direction the stock moves, you will always make $0. You are incurring 0 risk. This is problematic though, as you want to make money. No matter what trade you make, as long as you are trying to make money, there is always the chance that you lose money.</p>
                <p>Stocks are pretty bad at protecting you from risk. Although there are ways to hedge against risk by purchasing multiple stocks, if you are only buying one stock, there isn’t much you can do to protect yourself. If the stock goes up a lot, then good job. If the stock goes down a lot, then you risk losing a substantial amount of money. Making money from just stocks is very one dimensional; if you think the stock is going to go up only a little bit, you won’t be able to make more money from that.</p>
                <p>Options give you a way to protect yourself and also allow you to profit with less risk in specific situations. We have already seen how a normal call option protects you from large losses, as you have the right, but not the obligation to buy the underlying at the strike price. These contracts can be combined together, to give you less risk and more profit. Each contract is called a leg, and the legs combine to form a strategy.</p>
                <p>A few common strategies are below, but we encourage you to use our simulator and build out these strategies yourselves to see how they work.</p>
                <p>Call debit spread:</p>
                <img src="{call_debit_url}" alt="Call Debit Chart" style="max-width: 100%; height: auto;">
                <p>This spread comes from buying a call and selling a call with a higher strike price. Based on the profit and loss chart, you can see your losses are capped and your gains are capped. If you think that a stock will only go up a certain amount in a certain timeframe, you don’t gain anything by buying a normal call, as you think the probability of the stock increasing a lot is very small. In this case, you sell the possibility of unlimited upside for “insurance” to protect some of your downside.</p>
                <p>Put debit spread:</p>
                <img src="{put_debit_url}" alt="Put Debit Chart" style="max-width: 100%; height: auto;">
                <p>Similar to the call debit spread, except this spread has you profiting when the stock goes down rather than up. Here, you are selling a put and buying a put with a higher strike price. If you think the underlying is going to go down a specified amount in a certain amount of time, again, there is no gain to buying a normal put contract, as the possibility of unlimited gains is pointless (to you). Instead, you sell that possibility for some “insurance” to protect yourself if the stock goes up.</p>
                <p>Long Strangle:</p>
                <img src="{long_straddle_url}" alt="Long Straddle Chart" style="max-width: 100%; height: auto;">
                <p>Looking at the profit and loss chart, we can see that you profit when the stock makes large moves in either direction. This strangle is made when buying a put and buying a call. If you know that a stock is going to move a lot, but you are not sure in which direction, this strangle gives you more flexibility to make a better trade.</p>
                <p>Short Strangle:</p>
                <img src="{short_straddle_url}" alt="Short Straddle Chart" style="max-width: 100%; height: auto;">
                <p>This is the opposite of the long strangle, as you profit if the stock doesn’t move. Here, you are selling a call and a put. If you think that the underlying is going to stay around the same range, you can profit using this strategy.</p>
                <p>Using these strategies, you can find unique ways to profit that aren’t possible with traditional stocks. Make sure to use the simulator to make your own strategies.</p>
            '''.format(call_debit_url=url_for('static', filename='images/callDebitSpread.png'), put_debit_url=url_for('static', filename='images/putDebitSpread.png'), long_straddle_url=url_for('static', filename='images/longStraddle.png'), short_straddle_url=url_for('static', filename='images/shortStraddle.png')),
            'image': None
        }
    ]

    # If article_number is out of range, redirect to the first article
    if article_number < 1:
        return redirect(url_for('lemonadelearn', article_number=1))
    
    if article_number > len(articles):
        return redirect(url_for('congratulations'))

    current_article = articles[article_number - 1]
    next_article_url = url_for('lemonadelearn', article_number=article_number + 1)
    previous_article_url = url_for('lemonadelearn', article_number=article_number - 1) if article_number > 1 else article_number

    progress = (article_number / len(articles)) * 100

    return render_template('lemonadelearn.html',
                           current_article_title=current_article['title'],
                           current_article_content=current_article['content'],
                           current_article_image=current_article['image'],
                           next_article_url=next_article_url,
                           previous_article_url=previous_article_url,
                           progress=progress)


@app.route('/congratulations')
def congratulations():
    return render_template('congratulations.html')

def remove_expired_options_and_strategies():
    # Get the options account from session
    options_account_data = session.get('options_account')

    if not options_account_data:
        print("No options account found in session.")
        return

    # Reconstruct the OptionsAccount object from session data
    options_account = OptionsAccount.from_dict(options_account_data)
    options_account.signed_in = True

    # Get current time in UTC and ensure it's timezone-aware
    current_time = datetime.now(timezone.utc)
    print(f"Current time (UTC): {current_time}")

    # Remove expired positions (single options) - assuming expiration_date is already a datetime object
    updated_positions = {}
    for contract, details in options_account.positions.items():
        expiration_date = details['expiration_date']
        print(f"Checking contract {contract} with expiration date {expiration_date}")
        if expiration_date > current_time:
            updated_positions[contract] = details
        else:
            print(f"Removing expired contract: {contract}, expiration date: {expiration_date}")

    options_account.positions = updated_positions

    # Remove expired strategies based on the expiration date of the first contract
    updated_strategies = []
    for strategy in options_account.strategies:
        first_contract_expiration = strategy['contracts'][0]['expiration']
        print(f"Checking strategy {strategy['name']} with first contract expiration date {first_contract_expiration}")
        if first_contract_expiration > current_time:
            updated_strategies.append(strategy)
        else:
            print(f"Removing expired strategy: {strategy['name']}, first contract expiration date: {first_contract_expiration}")

    options_account.strategies = updated_strategies

    # Update the session with the modified options account
    session['options_account'] = options_account.to_dict()

    # Optionally, save the changes to Firestore as well
    user_id = session.get('user_id')
    if user_id:
        user_ref = db.collection('users').document(user_id)
        user_ref.update({
            'positions': options_account.positions,
            'strategies': options_account.strategies
        })

    print("Expired contracts and strategies have been removed (if any).")
   

@app.route('/test_remove_expired')
def test_remove_expired():
    try:
        remove_expired_options_and_strategies()
        return jsonify({'success': True, 'message': 'Expired contracts and strategies removed.'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    

@app.route('/test_record_portfolio_value')
def test_record_portfolio_value():
    try:
        record_portfolio_value()
        return jsonify({'success': True, 'message': 'Portfolio values recorded for all users.'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})



def run_remove_expired_options_and_strategies():
    try:
        with app.app_context():
            print("Running remove_expired_options_and_strategies for all users...")

            # Fetch all users from Firestore
            users_ref = db.collection('users')
            users = users_ref.stream()

            current_time = datetime.now(timezone.utc)

            for user_doc in users:
                user_data = user_doc.to_dict()

                # Check if we can construct an OptionsAccount from available data
                if 'balance' in user_data and 'volatility' in user_data and 'risk_free_rate' in user_data:
                    # Dynamically create an OptionsAccount object if it doesn't exist
                    options_account = OptionsAccount(
                        username=user_data.get('name', 'Unknown'),
                        password=user_data.get('password', 'default_password'),
                        initial_balance=user_data.get('balance', 0),
                        risk_free_rate=user_data.get('risk_free_rate', 0.01),
                        volatility=user_data.get('volatility', 0.2)
                    )
                    options_account.positions = user_data.get('positions', {})
                    options_account.strategies = user_data.get('strategies', [])
                else:
                    print(f"Cannot create OptionsAccount for user: {user_doc.id}")
                    continue

                options_account.signed_in = True

                # Remove expired positions and strategies
                updated_positions = {}
                for contract, details in options_account.positions.items():
                    expiration_date = details['expiration_date']
                    if expiration_date > current_time:
                        updated_positions[contract] = details
                    else:
                        print(f"Removing expired contract: {contract}")

                options_account.positions = updated_positions

                # Remove expired strategies
                updated_strategies = []
                for strategy in options_account.strategies:
                    first_contract_expiration = strategy['contracts'][0]['expiration']
                    if first_contract_expiration > current_time:
                        updated_strategies.append(strategy)
                    else:
                        print(f"Removing expired strategy: {strategy['name']}")

                options_account.strategies = updated_strategies

                # Update the Firestore document with the new data
                user_ref = db.collection('users').document(user_doc.id)
                user_ref.update({
                    'positions': options_account.positions,
                    'strategies': options_account.strategies
                })

            print("Expired contracts and strategies removed successfully for all users.")
    except Exception as e:
        print(f"Error running remove_expired_options_and_strategies: {e}")


def run_record_portfolio_value():
    try:
        with app.app_context():
            print("Running record_portfolio_value for all users...")

            # Fetch all users from Firestore
            users_ref = db.collection('users')
            users = users_ref.stream()

            for user_doc in users:
                user_data = user_doc.to_dict()

                # Check if we can construct an OptionsAccount from available data
                if 'balance' in user_data and 'volatility' in user_data and 'risk_free_rate' in user_data:
                    # Dynamically create an OptionsAccount object if it doesn't exist
                    options_account = OptionsAccount(
                        username=user_data.get('name', 'Unknown'),
                        password=user_data.get('password', 'default_password'),
                        initial_balance=user_data.get('balance', 0),
                        risk_free_rate=user_data.get('risk_free_rate', 0.01),
                        volatility=user_data.get('volatility', 0.2)
                    )
                    options_account.positions = user_data.get('positions', {})
                    options_account.strategies = user_data.get('strategies', [])
                else:
                    print(f"Cannot create OptionsAccount for user: {user_doc.id}")
                    continue

                options_account.signed_in = True

                # Calculate the portfolio value
                portfolio_value = options_account.get_portfolio_value()

                # Create a timestamp for the portfolio value
                timestamp = datetime.utcnow()

                # Retrieve the current portfolio history from the user document
                portfolio_history = user_data.get('portfolio_history', [])

                # Append the new portfolio value and timestamp
                portfolio_history.append({
                    'portfolio_value': portfolio_value,
                    'timestamp': timestamp
                })

                # Update Firestore with the new portfolio history
                user_ref = db.collection('users').document(user_doc.id)
                user_ref.update({
                    'portfolio_history': portfolio_history,
                    'latest_portfolio_value': portfolio_value,
                    'last_updated': timestamp
                })

            print("Portfolio values recorded successfully for all users.")
    except Exception as e:
        print(f"Error recording portfolio value: {e}")


@app.route('/legal')
def legal():
    return render_template('legal.html')


if __name__ == '__main__':
    scheduler = BackgroundScheduler()
    scheduler.add_job(run_remove_expired_options_and_strategies, trigger='interval', minutes=1)
    scheduler.add_job(run_record_portfolio_value, trigger='interval', minutes=30)
    scheduler.start()
    app.run(ssl_context='adhoc')
 
