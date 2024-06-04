import logging
import os
import datetime
import time

from flask import Flask, request, jsonify, session, redirect, render_template
from requests_oauthlib import OAuth2Session

from log_db_handler import setup_db_logging, get_logs

# Configuration
AUTHORIZATION_BASE_URL = 'https://github.com/login/oauth/authorize'
TOKEN_URL = 'https://github.com/login/oauth/access_token'
REPORT_PAGE = 'log_report.html'

# Register MY_LOGGER
log = logging.getLogger('APP_LOGGER')
log.setLevel('DEBUG')

# Flask app setup
app = Flask(__name__)
app.secret_key = os.urandom(24)  # Random secret key for session


@app.route('/')
def index():
    if 'client_id' not in session or 'client_secret' not in session:
        return render_template('credentials_form.html')
    
    github = OAuth2Session(session['client_id'], scope='repo')
    authorization_url, state = github.authorization_url(AUTHORIZATION_BASE_URL)
    session['oauth_state'] = state
    return redirect(authorization_url)


@app.route('/callback')
def callback():
    if 'client_id' not in session or 'client_secret' not in session:
        return redirect('/')
    github = OAuth2Session(session['client_id'], state=session['oauth_state'])
    token = github.fetch_token(TOKEN_URL, client_secret=session['client_secret'],
                               authorization_response=request.url)
    session['oauth_token'] = token
    log.info(f"GitHub token retrieved successfully: {token}")
    
    # Store token in a file with a timestamp
    timestamp = datetime.datetime.now().timestamp()
    filename = f"NEW_TOKEN_{timestamp}.txt"
    with open(filename, "w") as file:
        file.write(token['access_token'])
    
    log.info(f"New token saved to {filename}")
    
    return 'GitHub token retrieved successfully! You can close this window.'


@app.route('/reports')
def reports():
    return render_template(REPORT_PAGE, logs=get_logs())


@app.route('/logs')
def logs():
    return get_logs()


@app.route('/get_github_token', methods=['POST'])
def get_github_token():
    client_id = request.form['client_id']
    client_secret = request.form['client_secret']
    session['client_id'] = client_id
    session['client_secret'] = client_secret

    return redirect('/')


def main():
    setup_db_logging()

    # Prompt for GitHub OAuth credentials
    log.info("Getting GitHub OAuth credentials..")
    log.info("Successfully got GitHub OAuth credentials")

    # Run Flask app to handle the OAuth flow
    log.info('Starting Flask server to handle GitHub OAuth...')
    print('Starting Flask server to handle GitHub OAuth...')
    app.run(port=5000, debug=True)


if __name__ == "__main__":
    main()
