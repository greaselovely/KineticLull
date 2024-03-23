import sys
import json
import requests
from pathlib import Path
from googleapiclient.discovery import build

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

config_file='youtube.json'

def get_api_key_from_config():
    """
    Retrieves API keys, URLs, and a YouTube channel ID from a configuration file named 'config.json'.

    This function attempts to open and read the 'config.json' file located in the same directory as the script. It extracts the YouTube (YT) API key, the KineticLull API key, the URLs for KineticLull and another service (EDL), the YouTube channel ID, and a command directive from the configuration file.

    Returns:
        tuple: A tuple containing the YouTube API key, KineticLull API key, KineticLull URL, EDL URL, YouTube channel ID, and command directive. If any API key is not found, the script exits with a message indicating the absence.

    Raises:
        FileNotFoundError: If 'config.json' does not exist, it creates a new one with empty values for the necessary keys and exits, prompting the user to fill it in and rerun the script.
        json.JSONDecodeError: If there's an error decoding the JSON from 'config.json', it exits with an error message.

    Note:
        The 'command' can be 'new', 'update', or 'overwrite', with 'update' being the default value if not specified. This functionality allows for different operational modes based on the command provided in the configuration file.
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
    Fetches all videos from a specified YouTube channel's upload playlist.

    This function queries the YouTube Data API to find the playlist ID associated with the channel's uploads. It then iterates through the playlist, fetching up to 50 videos at a time (the maximum allowed per request) until all videos in the playlist have been retrieved.

    Parameters:
        channel_id (str): The unique identifier of the YouTube channel for which videos are to be retrieved.

    Returns:
        list: A list of dictionaries, where each dictionary contains details about each video in the channel's upload playlist. The information includes video IDs, titles, descriptions, timestamps, and more, as provided by the 'snippet' part of the YouTube Data API response.

    Note:
        - This function requires a previously initialized and authenticated YouTube Data API client (`youtube`) to be available in the scope where this function is called.
        - The function will continue fetching pages of results from the playlist until no more pages are available, indicated by the absence of a `nextPageToken` in the API response.
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
    Submits or updates a list of fully qualified domain names (FQDNs) associated with YouTube videos to the KineticLull API.

    Depending on the specified command, this function either uploads a new list of FQDNs or updates an existing list on the KineticLull platform. It constructs the appropriate API endpoint URL based on the command, sets up the request headers including the API key for authorization, and sends the data as a JSON payload.

    Parameters:
        kl_url (str): The base URL of the KineticLull API.
        kl_api_key (str): The API key for authenticating with the KineticLull API.
        fqdn_list (list): A list of fully qualified domain names to be submitted or updated.
        edl_url (str): The URL of the external dynamic list where the FQDNs are maintained.
        command (str): The operation to perform - 'new' to submit a new list or any other value (typically 'update') to update an existing list.

    Returns:
        None: This function prints the result of the API call, including any message returned by the server or error information in case of failure.

    Note:
        - This function uses the `requests` library to make HTTP POST requests to the KineticLull API.
        - The function adjusts the KineticLull API endpoint based on the command parameter and handles HTTP redirects (status code 301) by printing the new location URL.
        - The function prints detailed error messages in case the server response cannot be decoded as JSON, indicating a possible issue with the server or the network connection.
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

def main():
    """
    The main execution function for a script that integrates YouTube and KineticLull APIs.

    This script performs several key operations:
    1. It reads configuration settings from a json file, including API keys for YouTube and KineticLull, the base URL for KineticLull, an external dynamic list (EDL) URL, a YouTube channel ID, and a command directive.
    2. Validates the presence of necessary API keys.
    3. Initializes a YouTube API client and retrieves all videos from the specified YouTube channel.
    4. Constructs a list of fully qualified domain names (FQDNs) for each video in the channel.
    5. Submits this list of FQDNs to the KineticLull API, either adding them as a new list or updating an existing list, depending on the command directive.

    The script ensures that necessary data is available and correctly formatted before proceeding with each step, gracefully handling missing data or errors by printing informative messages and exiting if necessary.

    Note:
        - The script requires a 'config.json' file in the same directory, structured to include all necessary API keys and URLs.
        - It uses the Google API Client Library for Python to interact with the YouTube API and the 'requests' library for HTTP requests to the KineticLull API.
        - Proper execution of this script depends on the availability and correctness of the API keys and other configuration settings.
    """
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

if __name__ == "__main__":
    main()