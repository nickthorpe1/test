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
    endpoint = f"{BASE_URL}/actor/{threat}"
    response = requests.get(endpoint, headers=headers)
    if response.status_code == 404:
        print(f"Threat {threat} not found.")
        return None
    response.raise_for_status()
    return response.json()


def query_ioc_data(threat, access_token):
    """Query the Mandiant API for IOC data."""
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    endpoint = f"{BASE_URL}/actor/{threat}/indicators"
    response = requests.get(endpoint, headers=headers)
    if response.status_code == 404:
        print(f"IOC data for threat {threat} not found.")
        return []
    response.raise_for_status()
    return response.json().get('indicators', [])


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

    with pd.ExcelWriter('threat_data.xlsx', engine='openpyxl') as writer:
        # Create a default sheet to ensure the workbook has at least one visible sheet
        default_df = pd.DataFrame({"Message": ["This sheet is required to keep the workbook valid."]})
        default_df.to_excel(writer, sheet_name='Default', index=False)

        for threat in threats:
            print(f"Querying data for threat: {threat}")
            try:
                threat_data = query_threat_data(threat, access_token)
                ioc_data = query_ioc_data(threat, access_token)
                if threat_data is None:
                    continue
            except requests.exceptions.HTTPError as e:
                print(f"Error querying data for threat {threat}: {e}")
                continue

            print(f"Raw threat data for {threat}: {threat_data}")
            print(f"Raw IOC data for {threat}: {ioc_data}")

            # Add debugging to inspect the JSON response structure
            print(f"JSON keys for {threat}: {threat_data.keys()}")

            last_updated = threat_data.get('last_updated', 'N/A')
            ttps = threat_data.get('ttps', [])
            procedures = threat_data.get('procedures', [])

            print(f"Last updated: {last_updated}")
            print(f"TTPs: {ttps}")
            print(f"Procedures: {procedures}")

            cleaned_ttps = clean_data(ttps)
            cleaned_iocs = clean_data(ioc_data)
            cleaned_procedures = clean_data(procedures)

            print(f"Cleaned TTPs: {cleaned_ttps}")
            print(f"Cleaned IOCs: {cleaned_iocs}")
            print(f"Cleaned Procedures: {cleaned_procedures}")

            # Convert each data list to a DataFrame and save it to the Excel sheet
            ttps_df = pd.DataFrame(cleaned_ttps, columns=['TTPs'])
            iocs_df = pd.DataFrame(cleaned_iocs, columns=['IOCs'])
            procedures_df = pd.DataFrame(cleaned_procedures, columns=['Procedures'])

            # Add checks to ensure we only write non-empty dataframes
            if not ttps_df.empty:
                print(f"Writing TTPs to {threat}_TTPs")
                ttps_df.to_excel(writer, sheet_name=f'{threat}_TTPs', index=False)
            if not iocs_df.empty:
                print(f"Writing IOCs to {threat}_IOCs")
                iocs_df.to_excel(writer, sheet_name=f'{threat}_IOCs', index=False)
            if not procedures_df.empty:
                print(f"Writing Procedures to {threat}_Procedures")
                procedures_df.to_excel(writer, sheet_name=f'{threat}_Procedures', index=False)

    # Removing the default sheet if other data has been written
    with pd.ExcelWriter('threat_data.xlsx', engine='openpyxl', mode='a') as writer:
        if writer.book.sheetnames != ['Default']:
            writer.book.remove(writer.book['Default'])

    print("Data saved to threat_data.xlsx")


if __name__ == "__main__":
    threats_input = input("Enter comma-separated threats: ")
    threats = [threat.strip() for threat in threats_input.split(',')]
    main(threats)
