''' Example of Spotify authorization code flow (refreshable user auth).

Displays profile information of authenticated user and access token
information that can be refreshed by clicking a button.

Basic flow:
    -> '/'
    -> Spotify login page
    -> '/callback'
    -> get tokens
    -> use tokens to access API

Required environment variables:
    FLASK_APP, CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, SECRET_KEY

More info:
    https://developer.spotify.com/documentation/general/guides/authorization-guide/#authorization-code-flow

'''

from flask import (
    abort,
    Flask,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
    jsonify,
)
import json
import logging
import os
import requests
import secrets
import string
from urllib.parse import urlencode
import spotifyClient
import random
try:
    from keys import *
except:
    CLIENT_ID = os.environ['CLIENT_ID']
    CLIENT_SECRET = os.environ['CLIENT_SECRET']
    SECRET_KEY_APP = os.environ['SECRET_KEY_APP']
    REDIRECT_URI = os.environ['REDIRECT_URI']

logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s', level=logging.DEBUG
)






# Spotify API endpoints
AUTH_URL = 'https://accounts.spotify.com/authorize'
TOKEN_URL = 'https://accounts.spotify.com/api/token'
ME_URL = 'https://api.spotify.com/v1/me'


# Start 'er up
app = Flask(__name__)
app.secret_key = SECRET_KEY_APP


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/<loginout>')
def login(loginout):
    '''Login or logout user.

    Note:
        Login and logout process are essentially the same. Logout forces
        re-login to appear, even if their token hasn't expired.
    '''

    # redirect_uri can be guessed, so let's generate
    # a random `state` string to prevent csrf forgery.
    state = ''.join(
        secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16)
    )

    # Request authorization from user
    scope = 'user-read-private user-read-email user-library-read playlist-modify-public'

    payload = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': REDIRECT_URI,
        'state': state,
        'scope': scope,
        'show_dialog': True,
    }

    res = make_response(redirect(f'{AUTH_URL}/?{urlencode(payload)}'))
    res.set_cookie('spotify_auth_state', state)
    return res


@app.route('/callback')
def callback():
    error = request.args.get('error')
    code = request.args.get('code')
    state = request.args.get('state')
    stored_state = request.cookies.get('spotify_auth_state')

    if state is None or state != stored_state:
        app.logger.error('Error message: %s', repr(error))
        app.logger.error('State mismatch: %s != %s', stored_state, state)
        abort(400)

    payload = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
    }
    res = requests.post(TOKEN_URL, auth=(CLIENT_ID, CLIENT_SECRET), data=payload)
    res_data = res.json()

    if res_data.get('error') or res.status_code != 200:
        app.logger.error(
            'Failed to receive token: %s',
            res_data.get('error', 'No error information received.'),
        )
        abort(res.status_code)

    session['tokens'] = {
        'access_token': res_data.get('access_token'),
        'refresh_token': res_data.get('refresh_token'),
    }

    return redirect(url_for('finalize', original=request.cookies.get('to_compare')))


@app.route('/refresh')
def refresh():
    payload = {
        'grant_type': 'refresh_token',
        'refresh_token': session.get('tokens').get('refresh_token'),
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    res = requests.post(
        TOKEN_URL, auth=(CLIENT_ID, CLIENT_SECRET), data=payload, headers=headers
    )
    res_data = res.json()
    session['tokens']['access_token'] = res_data.get('access_token')

    return json.dumps(session['tokens'])


@app.route('/me')
def me():
    if 'tokens' not in session:
        app.logger.error('No tokens in session.')
        abort(400)

    headers = {'Authorization': f"Bearer {session['tokens'].get('access_token')}"}

    res = requests.get(ME_URL, headers=headers)
    res_data = res.json()
    spotifyClient.add_user_to_db(res_data)

    if res.status_code != 200:
        app.logger.error(
            'Failed to get profile info: %s',
            res_data.get('error', 'No error message returned.'),
        )
        abort(res.status_code)

    return render_template('me.html', data=res_data, tokens=session.get('tokens'))

@app.route('/sync_all')
def sync_all():
    if 'tokens' not in session:
        app.logger.error('No tokens in session.')
        abort(400)
    # Get profile info
    headers = {'Authorization': f"Bearer {session['tokens'].get('access_token')}"}

    res = requests.get(ME_URL, headers=headers)
    res_data = res.json()
    x = spotifyClient.add_all_songs_to_db(session['tokens'].get('access_token'), res_data['uri'])
    return jsonify({"data": list(x), "count": len(x)})

@app.route('/diff/<original>')
def get_diff(original):
    if 'spotify:user:' not in original:
        original = 'spotify:user:' + original
    
    state = ''.join(
        secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16)
    )

    # Request authorization from user
    scope = 'user-read-private user-read-email user-library-read playlist-modify-public'

    payload = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': REDIRECT_URI,
        'state': state,
        'scope': scope,
        'show_dialog': True,
    }

    res = make_response(redirect(f'{AUTH_URL}/?{urlencode(payload)}'))
    res.set_cookie('spotify_auth_state', state)
    res.set_cookie('to_compare', original)
    return res

@app.route('/finalize/<original>')
def finalize(original):
    if 'tokens' not in session:
        app.logger.error('No tokens in session.')
        abort(400)

    headers = {'Authorization': f"Bearer {session['tokens'].get('access_token')}"}

    res = requests.get(ME_URL, headers=headers)
    res_data = res.json()
    spotifyClient.add_user_to_db(res_data)

    spotifyClient.add_all_songs_to_db(session['tokens'].get('access_token'), res_data['uri'])

    user1 = spotifyClient.get_all_songs_from_db(original)
    if len(user1) == 0:
        abort(400, 'user {} not found'.format(original))

    user2 = spotifyClient.get_all_songs_from_db(res_data['uri'])

    if len(user2) == 0:
        abort(400, 'user {} not found'.format(res_data['uri']))
        
    x = list(user1.intersection(user2))

    playlistName = spotifyClient.get_user_by_uri(original)['name'] + " <> " + spotifyClient.get_user_by_uri(res_data['uri'])['name']
    url = spotifyClient.create_playlist_from_diff(session['tokens'].get('access_token'), list(x), playlistName)
    return redirect(url, code=302)

@app.route('/getUser/<uri>')
def get_user(uri):
    if 'spotify:user:' not in uri:
        uri = 'spotify:user:' + uri
    x = spotifyClient.get_user_by_uri(uri)
    del x['_id']
    return jsonify(x)

@app.route('/newPlaylist')
def new_playlist():
    user1 = spotifyClient.get_all_songs_from_db("spotify:user:12171377250")
    tmp = list(user1)
    random.shuffle(tmp)
    user2 = set(tmp[:50])
    diff = list(user1.intersection(user2))
    return jsonify(spotifyClient.create_playlist_from_diff(session['tokens'].get('access_token'), diff))

if __name__ == "__main__":
    app.run()