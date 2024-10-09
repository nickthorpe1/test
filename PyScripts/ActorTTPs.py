import requests
import pandas as pd
import base64

# Set your Mandiant API credentials here
API_ID = ''
API_SECRET = ''

AUTH_URL = 'https://api.intelligence.mandiant.com/token'
BASE_URL = 'https://api.intelligence.mandiant.com/v4'


def get_access_token(api_id, api_secret):
    """Authenticate and get the access token."""
    auth_str = f'{api_id}:{api_secret}'
    auth_bytes = auth_str.encode('utf-8')
    auth_base64 = base64.b64encode(auth_bytes).decode('utf-8')
    headers = {
        'Authorization': f'Basic {auth_base64}',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'grant_type': 'client_credentials'
    }

    response = requests.post(AUTH_URL, headers=headers, data=data)

    if response.status_code != 200:
        print(f"Failed to obtain access token. Status code: {response.status_code}")
        print(f"Response: {response.text}")
        response.raise_for_status()

    return response.json().get('access_token')


def query_russia_threat_actors(access_token):
    """Query the Mandiant API for all Russia-related threat actors."""
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    # Endpoint for querying all actors with a filter (adjust as needed for API details)
    endpoint = f"{BASE_URL}/actor?filter=country:Russia"
    response = requests.get(endpoint, headers=headers)
    response.raise_for_status()
    return response.json().get('actors', [])


def query_ttps_for_actor(actor_id, access_token):
    """Query the TTPs for a given threat actor."""
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    endpoint = f"{BASE_URL}/actor/{actor_id}/attack-patterns"
    response = requests.get(endpoint, headers=headers)
    if response.status_code == 404:
        print(f"TTPs for actor {actor_id} not found.")
        return []
    response.raise_for_status()
    return response.json().get('ttps', [])


def clean_data(data):
    """Clean the data from unwanted characters."""
    if isinstance(data, str):
        return data.replace('{', '').replace('}', '').replace('_', ' ')
    elif isinstance(data, list):
        return [clean_data(item) for item in data]
    elif isinstance(data, dict):
        return {k: clean_data(v) for k, v in data.items()}
    return data


def main():
    try:
        access_token = get_access_token(API_ID, API_SECRET)
    except requests.exceptions.HTTPError as e:
        print(f"Error obtaining access token: {e}")
        return

    # Query for Russia-related threat actors
    actors = query_russia_threat_actors(access_token)
    if not actors:
        print("No Russia-related threat actors found.")
        return

    threat_actor_data = []

    # For each actor, get their TTPs
    for actor in actors:
        actor_id = actor.get('id')
        actor_name = actor.get('name')
        print(f"Querying TTPs for actor: {actor_name} (ID: {actor_id})")

        try:
            ttps = query_ttps_for_actor(actor_id, access_token)
            cleaned_ttps = clean_data(ttps)
            threat_actor_data.append({
                'Threat Actor': actor_name,
                'TTPs': cleaned_ttps
            })
        except requests.exceptions.HTTPError as e:
            print(f"Error querying TTPs for actor {actor_name}: {e}")
            continue

    # Convert the data to a DataFrame
    df = pd.DataFrame(threat_actor_data)

    # Save the data to CSV
    df.to_csv('russia_threat_actors_ttps.csv', index=False)

    print("Data saved to russia_threat_actors_ttps.csv")


if __name__ == "__main__":
    main()
