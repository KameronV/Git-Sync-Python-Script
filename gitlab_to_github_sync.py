import logging
import os
import argparse
import hmac
import hashlib

from flask import Flask, request, jsonify, session, redirect, render_template
from requests_oauthlib import OAuth2Session
from git import Repo, GitCommandError

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
    github = OAuth2Session(session['client_id'], scope='repo')
    authorization_url, state = github.authorization_url(AUTHORIZATION_BASE_URL)
    session['oauth_state'] = state
    return redirect(authorization_url)


@app.route('/callback')
def callback():
    github = OAuth2Session(session['client_id'], state=session['oauth_state'])
    token = github.fetch_token(TOKEN_URL, client_secret=session['client_secret'],
                               authorization_response=request.url)
    session['oauth_token'] = token
    return 'GitHub token retrieved successfully! You can close this window.'


@app.route('/webhook', methods=['POST'])
def webhook():
    payload = request.get_json()
    if not payload:
        return jsonify({'error': 'Invalid payload'}), 400

    # Validate the payload with the secret
    gitlab_token = session.get('gitlab_token')
    if gitlab_token:
        signature = request.headers.get('X-Gitlab-Token')
        if not signature or not hmac.compare_digest(signature, gitlab_token):
            return jsonify({'error': 'Invalid signature'}), 403

    # Check if it's a push event
    if payload.get('event_name') == 'push':
        try:
            repo_path = session['repo_path']
            github_url = session['github_url']
            github_token = session['github_token']

            repo = Repo(repo_path)
            origin = repo.remote(name='github')
            origin.set_url(f'https://{github_token}@{github_url}')
            origin.push()
            print('Pushed to GitHub successfully')
        except GitCommandError as e:
            print(f'Failed to push to GitHub: {e}')
            return jsonify({'error': str(e)}), 500

    return jsonify({'status': 'success'}), 200


@app.route('/reports')
def reports():
    return render_template(REPORT_PAGE, logs=get_logs())


@app.route('/logs')
def logs():
    return get_logs()


def get_github_token(client_id, client_secret):
    session['client_id'] = client_id
    session['client_secret'] = client_secret
    app.run(port=5000)
    return session['oauth_token']['access_token']


def main():
    setup_db_logging()

    log.info("Parsing the input arguments....")

    parser = argparse.ArgumentParser(description='Sync pushes between GitLab and GitHub repositories.')
    parser.add_argument('repo_path', help='Path to the local repository')
    parser.add_argument('github_url', help='GitHub repository URL (e.g., github.com/username/repo.git)')
    parser.add_argument('gitlab_url', help='GitLab repository URL (e.g., gitlab.com/username/repo.git)')
    parser.add_argument('webhook_secret', help='GitLab webhook secret token')

    args = parser.parse_args()
    log.info("Successfully parsed the input arguments")

    # Prompt for GitHub OAuth credentials
    log.info("Getting GitHub OAuth credentials..")
    client_id = input("Enter your GitHub OAuth Client ID: ")
    client_secret = input("Enter your GitHub OAuth Client Secret: ")
    log.info("Successfully got GitHub OAuth credentials")

    # Retrieve GitHub token
    log.info("Retrieving GitHub token..")
    github_token = get_github_token(client_id, client_secret)
    log.info("Successfully retrieved GitHub token..")

    # Store necessary information in the session
    log.info("Storing required information in the session..")
    session['repo_path'] = args.repo_path
    session['github_url'] = args.github_url
    session['gitlab_token'] = args.webhook_secret
    session['github_token'] = github_token
    log.info("Successfully stored required information in the session..")

    # Set up the GitLab remote if it doesn't exist
    repo = Repo(args.repo_path)
    if 'gitlab' not in repo.remotes:
        log.info("GitLab remote not exist. Setting up..")
        repo.create_remote('gitlab', args.gitlab_url)
        log.info("Successfully setup GitLab remote.")
    if 'github' not in repo.remotes:
        log.info("GitHab remote not exist. Setting up..")
        repo.create_remote('github', args.github_url)
        log.info("Successfully setup GitHub remote.")

    # Run Flask app to handle webhooks
    log.info('Starting Flask server to handle GitLab webhooks...')
    print('Starting Flask server to handle GitLab webhooks...')
    app.run(port=5000, debug=True)


if __name__ == "__main__":
    main()
