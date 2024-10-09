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


def query_all_threat_actors(access_token):
    """Query the Mandiant API for all threat actors."""
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    endpoint = f"{BASE_URL}/actor"
    response = requests.get(endpoint, headers=headers)
    response.raise_for_status()
    return response.json().get('actors', [])


def main():
    try:
        access_token = get_access_token(API_ID, API_SECRET)
    except requests.exceptions.HTTPError as e:
        print(f"Error obtaining access token: {e}")
        return

    # Query all threat actors
    actors = query_all_threat_actors(access_token)
    if not actors:
        print("No threat actors found.")
        return

    # Create a list of actor IDs
    actor_ids = [actor.get('id') for actor in actors]

    # Convert the data to a DataFrame
    df = pd.DataFrame(actor_ids, columns=['Threat Actor ID'])

    # Save the data to CSV
    df.to_csv('threat_actor_ids.csv', index=False)

    print("Threat actor IDs saved to threat_actor_ids.csv")


if __name__ == "__main__":
    main()
