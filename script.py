from urllib.parse import urlencode
import webbrowser
import datetime
import requests

timestamp = datetime.datetime.now().timestamp()

print("The browser will open and get the value of 'code' from the URL bar")

client_id = input('CLIENT ID: ')
client_secret = input('CLIENT SECRET: ')

redirect_url = "http://localhost"

scope = input('SCOPE [eg: repo, user]: ')
query_params = {
    "response_type": "code",
    "client_id": client_id,
    "redirect_uri": redirect_url,
    "scope": scope
}

url = f"https://github.com/login/oauth/authorize?{urlencode(query_params)}"

print('Get Ready... Browser will open, COPY the code value quickly')

webbrowser.open(url)

print('Browser opened')

token_endpoint = "https://github.com/login/oauth/access_token"

code = input('YOUR CODE: ')

data = {
    "client_id": client_id,
    "client_secret": client_secret,
    "code": code,
    "redirect_uri": redirect_url
}

response = requests.post(token_endpoint, data=data, headers={"Accept": "application/json"})
token_response = response.json()

if 'access_token' in token_response:
    token = token_response['access_token']
    
    # Create a new text file and add the token in it
    filename = f"NEW_TOKEN_{timestamp}.txt"
    with open(filename, "w") as file:
        file.write(token)

    print("\nNew file created:", filename)
    print("\nToken:", token)
else:
    print("\nFailed to get GitHub access token.")