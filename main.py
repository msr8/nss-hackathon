from flask import Flask, request, render_template, redirect, session, url_for
from flask_restful import Api, Resource
from flask_restful import request as request_api
from flask.wrappers import Response
from flask_cors import CORS
import secrets
import bcrypt
import json
import os
from typing import Any

DATA_DIR = os.path.join(os.path.dirname(__file__), 'DATA')
USERS_FP = os.path.join(DATA_DIR, 'users.json')


# Make sure the DATA directory exists
os.makedirs(DATA_DIR, exist_ok=True)

# Create the users JSON file if it doesn't exist
if not os.path.exists(USERS_FP):
    with open(USERS_FP, 'w') as f:
        json.dump({}, f)


app = Flask(__name__)
# CORS(app, supports_credentials=True)
api = Api(app)
app.secret_key = secrets.token_hex(16)

ERROR_CODES = {
    1551: 'Username already exists',
    1552: 'Username does not exist',
    1553: 'Incorrect password',
    1554: 'There cannot be whitespace(s) in the username',
}






# Hash a password using bcrypt
def hash_password(password) -> bytes:
    salt   = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

# Load user data from the JSON file
def load_users() -> dict[str, str]:
    with open(USERS_FP, 'r') as f:
        return json.load(f)

# Save user data to the JSON file
def save_users(users) -> None:
    with open(USERS_FP, 'w') as f:
        json.dump(users, f)







# Sign up route
class ApiSignup(Resource):
    def post(self) -> dict[str, Any]:
        # print( [i for i in request.form.items()] )
        # Get username and password given to us via POST request
        username = request.form['username']
        password = request.form['password']

        # Check if username already exists
        users = load_users()
        if username in users:
            print('oof')
            err_code = 1551
            return {'status': err_code, 'message': ERROR_CODES[err_code]}
        
        # Check if username has whitespace(s)
        if ' ' in username:
            err_code = 1554
            return {'status': err_code, 'message': ERROR_CODES[err_code]}

        # Hash the password and locally save it
        hashed_password = hash_password(password)  # Hash the password
        users[username] = hashed_password.decode() 
        save_users(users)

        # Make an empty JSON file for the user
        user_json_fp = os.path.join(DATA_DIR, f'{username}.json')
        with open(user_json_fp, 'w') as f:
            json.dump({}, f)

        # Store username in session
        session['username'] = username

        return {'status': 200, 'message': 'Success'}
api.add_resource(ApiSignup, '/api/signup')

@app.route('/signup', methods=['GET', 'POST'])
def page_signup() -> str:
    return render_template('signup.html')



# Login route
class ApiLogin(Resource):
    def post(self) -> dict[str, Any]:
        # Get username and password given to us via POST request
        username = request.form['username']
        password = request.form['password']

        # Check if username exists
        users = load_users()
        if username not in users:
            err_code = 1552
            return {'status': err_code, 'message': ERROR_CODES[err_code]}

        # Check if password is correct
        hashed_password = users[username]
        if not bcrypt.checkpw(password.encode(), hashed_password.encode()):
            err_code = 1553
            return {'status': err_code, 'message': ERROR_CODES[err_code]}

        # Store username in session
        session['username'] = username

        return {'status': 200, 'message': 'Success'}
api.add_resource(ApiLogin, '/api/login')


@app.route('/login', methods=['GET', 'POST'])
def page_login() -> str:
    return render_template('login.html')



# Logout route
@app.route('/logout')
def page_logout() -> Response:
    session.pop('username', None)
    return redirect(url_for('page_login'))




# Profile route
@app.route('/')
def page_root() -> str | Response:
    # Check if user is logged in
    if 'username' in session:
        return f'Logged in as {session.items()}'
    else:
        return redirect(url_for('page_login'))
        # return f'Logged in as {session.items()}'







if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)






'''
In the provided Flask code, the `app.secret_key` is used to set the secret key for the Flask application. The secret key is a cryptographic key used for session management and various security-related purposes.

Here's what it does:

1. **Session Management**: Flask uses sessions to store user-specific data securely between requests. The data in the session is cryptographically signed with the secret key to prevent tampering. This means that when you set `app.secret_key`, Flask will use it to sign session data, making it more secure.
2. **CSRF Protection**: Flask uses the secret key to generate anti-CSRF tokens. These tokens are used to protect against Cross-Site Request Forgery (CSRF) attacks by ensuring that form submissions originate from your own site.
3. **Secure Cookies**: The secret key is used to sign cookies. When you store data in cookies, it's signed with the secret key to ensure that the data hasn't been tampered with by the client. This helps protect sensitive information stored in cookies.
4. **Secure Key for Extensions**: Some Flask extensions and libraries may use the secret key for their own security-related operations.

Using a strong secret key is essential for the security of your Flask application, especially when dealing with sessions, cookies, and user authentication.
'''
