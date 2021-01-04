import requests
import pymongo
import time
import json
import threading
import os
try:
    from keys import *
except:
    MONGO_URL = os.environ['MONGO_URL']

client = pymongo.MongoClient(MONGO_URL)
db = client.test

db = client['Spotify']
collection = db['SpotifyCollection']

OVERRIDE = False

def add_all_songs_to_db(auth, uri, force=False):
    # force true if you want to add duplicate songs if a user has been added already
    if force == False:
        x = get_all_songs_from_db(uri)
        if len(x) != 0:
            return x
    headers = {
        'Authorization': 'Bearer {}'.format(auth),
    }
    e = set()
    url = 'https://api.spotify.com/v1/me/tracks?limit=50'
    while url != None:
        response = requests.get(url, headers=headers)
        i = 1
        while response.status_code != 200 and i < 3:
            i += 1
            time.sleep(i)
            response = requests.get(url, headers=headers)
        
        if i == 3:
            break

        response = response.json()
        temp = []
        for val in response['items']:
            document = {'uri': val['track']['uri'], 'user': uri, 'type': 'song'}
            temp.append(document)
            e.add(val['track']['uri'])
        collection.insert_many(temp)
        url = response['next']

    return e

def add_user_to_db(res_data):
    document = {}
    document['user'] = res_data['uri']
    document['name'] = res_data['display_name']
    document['image'] = None
    document['user_id'] = res_data['id']
    if len(res_data['images']) > 0:
        document['image'] = res_data['images'][0]['url']
    document['type'] = 'user'
    collection.insert_one(document)

def get_user_by_uri(uri):
    for val in collection.find({'user': uri, 'type': 'user'}).sort("created_at",pymongo.DESCENDING):
	    return val


def get_all_songs_from_db(uri):
    e = set()
    for val in collection.find({'user': uri, 'type': 'song'}).sort("created_at",pymongo.DESCENDING):
	    e.add(val['uri'])
    return e

def get_uri_from_auth(auth):
    headers = {'Authorization': f"Bearer {auth}"}

    res = requests.get("https://api.spotify.com/v1/me", headers=headers)
    res_data = res.json()
    return res_data['user']

def get_id_from_auth(auth):
    headers = {'Authorization': f"Bearer {auth}"}

    res = requests.get("https://api.spotify.com/v1/me", headers=headers)
    res_data = res.json()
    return res_data['id']

def add_to_playlist(auth, arrayOfTrackURI, playlistURL):
    # pass in array of track uris
    arrayOfTrackURI = list(arrayOfTrackURI)
    while len(arrayOfTrackURI) > 0:
        e = []
        for i in range(80):
            if len(arrayOfTrackURI) == 0:
                break
            e.append(arrayOfTrackURI.pop(0))
        requestData = json.dumps(e)
        headers = {
            'Authorization': 'Bearer {}'.format(auth),
            'Content-Type': 'application/json',
        }
        response = requests.post(
            playlistURL,
            data=requestData,
            headers=headers
        )

def create_new_playlist(auth, name):
    idVal = get_id_from_auth(auth)
    headers = {
        'Authorization': 'Bearer {}'.format(auth),
        'Content-Type': 'application/json',
    }
    data = '{"name":"' + name + '"}'

    

    response = requests.post('https://api.spotify.com/v1/users/{}/playlists'.format(idVal), headers=headers, data=data)
    return response.json()

def create_playlist_from_diff(auth, arrayOfTrackURI, title="Diff Playlist"):
    playlist = create_new_playlist(auth, title)
    playlistURL = playlist['tracks']['href']
    externalURL = playlist.get('external_urls', {}).get('spotify', '')
    threading.Thread(target=add_to_playlist, args=(auth, arrayOfTrackURI, playlistURL,)).start()
    return externalURL

