from flask import Flask, render_template, request, redirect, url_for, flash, session
import firebase_admin
from firebase_admin import credentials, auth, firestore
from google.oauth2.id_token import verify_oauth2_token
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from werkzeug.security import generate_password_hash, check_password_hash
from backend.OptionsAccount import OptionsAccount

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
        print(f"Type of user_ref: {type(user_ref)}")

        # Check if the get() method is callable
        print(f"Is get() callable? {callable(user_ref.get)}")

        user_doc = user_ref.get()
        print(f"Type of user_doc: {type(user_doc)}")

        # Debugging exists() check
        print(f"Is exists callable? {callable(user_doc.exists)}")
        print(f"Document exists: {user_doc.exists}")

        if user_doc.exists:
            print("Document exists method checked")
            user_dict = user_doc.to_dict()
            print(f"User Document Dictionary: {user_dict}")

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

@app.route('/simulator')
def simulator():
    if 'user_id' not in session:
        flash('You are not logged in', 'danger')
        return redirect(url_for('login'))
    
    # Retrieve the serialized OptionsAccount from the session and recreate the object
    options_account_data = session.get('options_account')
    if options_account_data:
        options_account = OptionsAccount.from_dict(options_account_data)
    
        # Example: Displaying balance
        flash(f"Current Balance: ${options_account.balance}", 'info')
    else:
        flash('OptionsAccount data not found in session.', 'danger')
    
    return render_template('simulator.html')



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







