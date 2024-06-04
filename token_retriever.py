import logging
import os
import datetime
import webbrowser
import requests

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
        log.info("Getting GitHub OAuth credentials..")
        return render_template('credentials_form.html')
    
    log.info("Successfully got GitHub OAuth credentials")
    github = OAuth2Session(session['client_id'], scope='repo')
    authorization_url, state = github.authorization_url(AUTHORIZATION_BASE_URL)
    session['oauth_state'] = state
    return redirect(authorization_url)


@app.route('/callback')
def callback():
    if 'client_id' not in session or 'client_secret' not in session:
        return redirect('/')
    
    code = request.args.get('code')
    state = request.args.get('state')

    if state != session['oauth_state']:
        log.error("State mismatch error.")
        return 'State mismatch error.', 400
    
    token_endpoint = TOKEN_URL
    redirect_url = "http://localhost:5000/callback"

    data = {
        "client_id": session['client_id'],
        "client_secret": session['client_secret'],
        "code": code,
        "redirect_uri": redirect_url
    }


    try:
        response = requests.post(token_endpoint, data=data, headers={"Accept": "application/json"})
        token_response = response.json()

        if 'access_token' in token_response:
            token = token_response['access_token']
            session['oauth_token'] = token
            
            # Create a new text file and add the token in it
            timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            filename = f"NEW_TOKEN_{timestamp}.txt"
            with open(filename, "w") as file:
                file.write(token)
            os.chmod(filename, 0o400)  # Set file permissions to be readable only by the owner
            
            log.info(f"New token saved to {filename} with secure permissions.")
            return 'GitHub token retrieved successfully! You can close this window.'
        else:
            log.error("Failed to get GitHub access token.")
            return 'Failed to get GitHub access token.', 400
    except Exception as e:
        log.exception("Exception occurred while retrieving GitHub token.")
        return 'Failed to retrieve GitHub token.', 500


@app.route('/reports')
def reports():
    log.info("Generating report from logs.")
    return render_template(REPORT_PAGE, logs=get_logs())


@app.route('/logs')
def logs():
    log.info("Fetching logs.")
    return get_logs()


@app.route('/get_github_token', methods=['POST'])
def get_github_token():
    client_id = request.form['client_id']
    client_secret = request.form['client_secret']
    session['client_id'] = client_id
    session['client_secret'] = client_secret
    log.info("Received GitHub client credentials from form.")
    return redirect('/')


def main():
    setup_db_logging()

    # Run Flask app to handle the OAuth flow
    log.info('Starting Flask server to handle GitHub OAuth...')

    # Open the web browser to the Flask app's index page
    webbrowser.open("http://localhost:5000")
    
    app.run(port=5000, debug=True)


if __name__ == "__main__":
    main()
