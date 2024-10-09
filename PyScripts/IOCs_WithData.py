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


def query_threat_data(threat, access_token):
    """Query the Mandiant API for threat data."""
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    # Example correct endpoint for threat actor data
    endpoint = f"{BASE_URL}/actor/{threat}"
    response = requests.get(endpoint, headers=headers)
    if response.status_code == 404:
        print(f"Threat {threat} not found.")
        return None
    response.raise_for_status()
    return response.json()


def clean_data(data):
    """Clean the data from unwanted characters."""
    if isinstance(data, str):
        return data.replace('{', '').replace('}', '').replace('_', ' ')
    elif isinstance(data, list):
        return [clean_data(item) for item in data]
    elif isinstance(data, dict):
        return {k: clean_data(v) for k, v in data.items()}
    return data


def main(threats):
    try:
        access_token = get_access_token(API_ID, API_SECRET)
    except requests.exceptions.HTTPError as e:
        print(f"Error obtaining access token: {e}")
        return

    with pd.ExcelWriter('threat_data2.xlsx', engine='openpyxl') as writer:
        for threat in threats:
            print(f"Querying data for threat: {threat}")
            try:
                threat_data = query_threat_data(threat, access_token)
                if threat_data is None:
                    continue
            except requests.exceptions.HTTPError as e:
                print(f"Error querying data for threat {threat}: {e}")
                continue

            last_updated = threat_data.get('last_updated', 'N/A')
            ttps = threat_data.get('ttps', [])
            iocs = threat_data.get('iocs', [])
            procedures = threat_data.get('procedures', [])

            cleaned_ttps = clean_data(ttps)
            cleaned_iocs = clean_data(iocs)
            cleaned_procedures = clean_data(procedures)

            # Convert each data list to a DataFrame and save it to the Excel sheet
            ttps_df = pd.DataFrame(cleaned_ttps, columns=['TTPs'])
            iocs_df = pd.DataFrame(cleaned_iocs, columns=['IOCs'])
            procedures_df = pd.DataFrame(cleaned_procedures, columns=['Procedures'])

            ttps_df.to_excel(writer, sheet_name=f'{threat}_TTPs', index=False)
            iocs_df.to_excel(writer, sheet_name=f'{threat}_IOCs', index=False)
            procedures_df.to_excel(writer, sheet_name=f'{threat}_Procedures', index=False)

    print("Data saved to threat_data2.xlsx")


if __name__ == "__main__":
    threats_input = input("Enter comma-separated threats: ")
    threats = [threat.strip() for threat in threats_input.split(',')]
    main(threats)

