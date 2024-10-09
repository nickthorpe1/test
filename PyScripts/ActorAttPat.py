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


def query_ttps_for_actor(actor_id, access_token):
    """Query the TTPs (attack patterns) for a given threat actor."""
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    endpoint = f"{BASE_URL}/actor/{actor_id}/attack-pattern"
    response = requests.get(endpoint, headers=headers)
    if response.status_code == 404:
        print(f"TTPs for actor {actor_id} not found.")
        return []
    response.raise_for_status()
    return response.json().get('ttps', [])


def main():
    # Input comma-separated threat actors
    threat_actor_input = input("Enter comma-separated threat actor names: ")
    threat_actors = [actor.strip() for actor in threat_actor_input.split(',')]

    try:
        access_token = get_access_token(API_ID, API_SECRET)
    except requests.exceptions.HTTPError as e:
        print(f"Error obtaining access token: {e}")
        return

    threat_actor_data = []

    # For each threat actor, get their associated TTPs
    for actor_name in threat_actors:
        print(f"Querying data for actor: {actor_name}")
        try:
            # Assuming the actor name works as the actor ID in the endpoint
            ttps = query_ttps_for_actor(actor_name, access_token)
            threat_actor_data.append({
                'Threat Actor': actor_name,
                'TTPs': ", ".join([ttp.get('name') for ttp in ttps])  # Collect TTP names into a string
            })
        except requests.exceptions.HTTPError as e:
            print(f"Error querying TTPs for actor {actor_name}: {e}")
            continue

    if not threat_actor_data:
        print("No TTP data available.")
        return

    # Convert the data to a DataFrame
    df = pd.DataFrame(threat_actor_data)

    # Save the data to CSV
    df.to_csv('threat_actors_ttps.csv', index=False)

    print("Data saved to threat_actors_ttps.csv")


if __name__ == "__main__":
    main()
