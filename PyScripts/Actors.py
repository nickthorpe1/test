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


def query_threat_actors_by_source_location(access_token, source_location):
    """Query Mandiant API for threat actors filtered by source location."""
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    endpoint = f"{BASE_URL}/actor?query=*&object_type=threat-actor&source_locations={source_location}"
    response = requests.get(endpoint, headers=headers)
    response.raise_for_status()
    return response.json().get('actors', [])


def query_ttps_for_actor(actor_id, access_token):
    """Query the TTPs (attack patterns) for a given threat actor."""
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    endpoint = f"{BASE_URL}/actors/{actor_id}/ttps"
    response = requests.get(endpoint, headers=headers)
    if response.status_code == 404:
        print(f"TTPs for actor {actor_id} not found.")
        return []
    response.raise_for_status()
    return response.json().get('ttps', [])


def main():
    source_location = 'United States'  # Example source location for Russia
    try:
        access_token = get_access_token(API_ID, API_SECRET)
    except requests.exceptions.HTTPError as e:
        print(f"Error obtaining access token: {e}")
        return

    # Query threat actors by source location
    actors = query_threat_actors_by_source_location(access_token, source_location)
    if not actors:
        print(f"No threat actors found for source location: {source_location}")
        return

    threat_actor_data = []

    # For each threat actor, get their associated TTPs
    for actor in actors:
        actor_id = actor.get('id')
        actor_name = actor.get('name')
        print(f"Querying TTPs for actor: {actor_name} (ID: {actor_id})")

        try:
            ttps = query_ttps_for_actor(actor_id, access_token)
            threat_actor_data.append({
                'Threat Actor': actor_name,
                'TTPs': ttps
            })
        except requests.exceptions.HTTPError as e:
            print(f"Error querying TTPs for actor {actor_name}: {e}")
            continue

    # Convert the data to a DataFrame
    df = pd.DataFrame(threat_actor_data)

    # Save the data to CSV
    df.to_csv('threat_actors_ttps.csv', index=False)

    print("Data saved to threat_actors_ttps.csv")


if __name__ == "__main__":
    main()
