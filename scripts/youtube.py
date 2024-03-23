from googleapiclient.discovery import build
import sys
import json
import requests
from pathlib import Path

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

config_file='youtube.json'

def get_api_key_from_config():
    """
    Reads the API keys, urls, channel ID from a config.json file.
    """
    file_path = Path(__file__).parent
    config_file_path = Path.joinpath(file_path, config_file)
    try:
        with open(config_file_path, 'r') as file:
            config = json.load(file)
            yt_api_key = config.get('authentication', {}).get('yt_api_key', None)
            kl_api_key = config.get('authentication', {}).get('kl_api_key', None)
            kl_url = config.get('urls', {}).get('kineticlull_url', None)
            edl_url = config.get('urls', {}).get('edl_url', None)
            yt_ch_id = config.get('urls', {}).get('youtube_channel_id', None)
            command = config.get('command', 'update') # default to update if we don't have a value
            if not yt_api_key:
                print(f"\n\n[!]\tNo API Key found.")
                sys.exit()
            return yt_api_key, kl_api_key, kl_url, edl_url, yt_ch_id, command
        
    except FileNotFoundError:
        """
        command can be : new, update, overwrite
        """
        print(f"Config file not found at {config_file_path}. Creating with empty values.")
        config = {
            'authentication': {'yt_api_key': None, 'kl_api_key': None},
            'urls': {'kineticlull_url': None, 'edl_url': None, 'youtube_channel_id': None},
            'command' : 'update'
        }
        with open(config_file_path, 'w') as file:
            json.dump(config, file, indent=4)
        print(f"\n\n[i]\tUpdate {config_file_path} and then re-run\n\n")
        sys.exit()
    except json.JSONDecodeError:
        print("[!]\tError decoding JSON from the config file.")
        sys.exit()

def get_channel_videos(channel_id):
    """
    Get the Uploads playlist ID and builds a list of channel videos.

    """
    res = youtube.channels().list(id=channel_id, part='contentDetails').execute()
    playlist_id = res['items'][0]['contentDetails']['relatedPlaylists']['uploads']

    videos = []
    next_page_token = None

    while True:
        res = youtube.playlistItems().list(playlistId=playlist_id, part='snippet', maxResults=50, pageToken=next_page_token).execute()
        videos += res['items']
        next_page_token = res.get('nextPageToken')

        if next_page_token is None:
            break

    return videos

def kineticlull_upload(kl_url, kl_api_key, fqdn_list, edl_url, command):
    """
    API upload of the YT videos for the specific channel ID.
    
    """
    kl_url = kl_url.rstrip('/')
    submit_new_edl = "/api/submit_fqdn/"
    update_edl = "/api/update_edl/"
    if command == 'new':
        kl_url = kl_url + submit_new_edl
    else:
        kl_url = kl_url + update_edl
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {kl_api_key}"}
    json_data = { "auto_url" : edl_url, "command" : command, "fqdn_list" : fqdn_list }
    # print(kl_url, headers, json_data)
    response = requests.post(kl_url, headers=headers, json=json_data, verify=False, allow_redirects=False)
    if response.status_code == 301:
        print("Redirect URL:", response.headers['Location'])
    try:
        status_code = response.status_code
        response = response.json()
        message = response.get('message', f'Server says: {status_code}')
        print(f"\n[!]\t{message}\n\n")
    except requests.exceptions.JSONDecodeError as e:
        print(f"[!]\tError: {response.status_code} - JSON Decode Error: {e}\n[!]\tBecause there was no message back from the server")



if __name__ == "__main__":
    yt_api_key, kl_api_key, kl_url, edl_url, yt_ch_id, command = get_api_key_from_config()

    edl_url = edl_url.rstrip('/')

    if not yt_api_key or not kl_api_key:
        print("[!]\tAPI Key(s) not found.")
        sys.exit()

    youtube = build('youtube', 'v3', developerKey=yt_api_key)
    videos = get_channel_videos(yt_ch_id)

    fqdn_list = []
    for video in videos:
        fqdn_list.append(f"https://www.youtube.com/watch?v={video['snippet']['resourceId']['videoId']}")


    kineticlull_upload(kl_url, kl_api_key, fqdn_list, edl_url, command)