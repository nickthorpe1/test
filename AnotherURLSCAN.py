import requests
import json
import csv
import time

# Replace 'YOUR_API_KEY' with your actual URLScan API key
API_KEY = 'enterAPIKey'
URLSCAN_API = 'https://urlscan.io/api/v1/scan/'

# URLs to be scanned
urls_to_scan = [
    'https://www.timeanddate.com/stopwatch/'
    # Add more URLs here
]


def submit_url(url):
    headers = {
        'Content-Type': 'application/json',
        'API-Key': API_KEY,
    }
    payload = {
        'url': url,
        'public': 'on'
    }
    response = requests.post(URLSCAN_API, headers=headers, data=json.dumps(payload))
    return response.json()


def get_scan_results(scan_id):
    url = f'https://urlscan.io/api/v1/result/{scan_id}/'
    headers = {
        'API-Key': API_KEY,
    }
    response = requests.get(url, headers=headers)
    return response.json()


def main():
    with open('urlscan_results.csv', 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            'task.uuid', 'task.time', 'task.url', 'task.visibility', 'task.method', 'task.tags',
            'page.url', 'page.domain', 'page.ip', 'page.ptr', 'page.country', 'page.city', 'page.server',
            'page.asn', 'page.asnname', 'data.requests', 'data.cookies', 'data.console', 'data.links',
            'data.timing', 'data.globals', 'meta.processors.asn.data', 'meta.processors.download.data',
            'meta.processors.geoip.data', 'meta.processors.rdns.data', 'meta.processors.umbrella.data',
            'meta.processors.wappa.data', 'lists.ips', 'lists.countries', 'lists.asns', 'lists.domains',
            'lists.server', 'lists.urls', 'lists.linkDomains', 'lists.certificates', 'lists.hashes',
            'verdicts.urlscan.score', 'verdicts.urlscan.categories', 'verdicts.urlscan.brands'
        ]  # Customize as needed
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for url in urls_to_scan:
            submission = submit_url(url)
            scan_id = submission['uuid']
            print(f"Submitted URL: {url}, Scan ID: {scan_id}")

            # Wait for the scan to finish
            time.sleep(30)  # Adjust this based on actual scan time

            result = get_scan_results(scan_id)

            # Extracting and formatting the required fields from the result
            task = result.get('task', {})
            page = result.get('page', {})
            data = result.get('data', {})
            meta_processors = result.get('meta', {}).get('processors', {})
            lists = result.get('lists', {})
            verdicts = result.get('verdicts', {}).get('urlscan', {})

            writer.writerow({
                'task.uuid': task.get('uuid', ''),
                'task.time': task.get('time', ''),
                'task.url': task.get('url', ''),
                'task.visibility': task.get('visibility', ''),
                'task.method': task.get('method', ''),
                'task.tags': ', '.join(task.get('tags', [])),
                'page.url': page.get('url', ''),
                'page.domain': page.get('domain', ''),
                'page.ip': page.get('ip', ''),
                'page.ptr': page.get('ptr', ''),
                'page.country': page.get('country', ''),
                'page.city': page.get('city', ''),
                'page.server': page.get('server', ''),
                'page.asn': page.get('asn', ''),
                'page.asnname': page.get('asnname', ''),
                'data.requests': json.dumps(data.get('requests', [])),
                'data.cookies': json.dumps(data.get('cookies', [])),
                'data.console': json.dumps(data.get('console', [])),
                'data.links': json.dumps(data.get('links', [])),
                'data.timing': json.dumps(data.get('timing', {})),
                'data.globals': json.dumps(data.get('globals', [])),
                'meta.processors.asn.data': json.dumps(meta_processors.get('asn', {}).get('data', [])),
                'meta.processors.download.data': json.dumps(meta_processors.get('download', {}).get('data', [])),
                'meta.processors.geoip.data': json.dumps(meta_processors.get('geoip', {}).get('data', [])),
                'meta.processors.rdns.data': json.dumps(meta_processors.get('rdns', {}).get('data', [])),
                'meta.processors.umbrella.data': json.dumps(meta_processors.get('umbrella', {}).get('data', [])),
                'meta.processors.wappa.data': json.dumps(meta_processors.get('wappa', {}).get('data', [])),
                'lists.ips': json.dumps(lists.get('ips', [])),
                'lists.countries': json.dumps(lists.get('countries', [])),
                'lists.asns': json.dumps(lists.get('asns', [])),
                'lists.domains': json.dumps(lists.get('domains', [])),
                'lists.server': json.dumps(lists.get('server', [])),
                'lists.urls': json.dumps(lists.get('urls', [])),
                'lists.linkDomains': json.dumps(lists.get('linkDomains', [])),
                'lists.certificates': json.dumps(lists.get('certificates', [])),
                'lists.hashes': json.dumps(lists.get('hashes', [])),
                'verdicts.urlscan.score': verdicts.get('score', ''),
                'verdicts.urlscan.categories': ', '.join(verdicts.get('categories', [])),
                'verdicts.urlscan.brands': json.dumps(verdicts.get('brands', []))
            })
            print(f"Scan completed for URL: {url}")


if __name__ == "__main__":
    main()
