
#!/usr/bin/python3
import sys
import requests
import json

def query_urlhaus(auth_key, url):
    # Construct the HTTP request
    data = {
        'url' : url
    }
    # Set the Authentication header
    headers = {
        "Auth-Key"      :   auth_key
    }
    response = requests.post('https://urlhaus-api.abuse.ch/v1/url/', data, headers=headers)
    # Parse the response from the API
    json_response = response.json()
    if json_response['query_status'] == 'ok':
        print(json.dumps(json_response, indent=4, sort_keys=False))
    elif json_response['query_status'] == 'no_results':
        print("No results")
    else:
        print(json_response['query_status'])

auth_key="72cf95deef08dc4bd917188116f7c062214a3a86a2f95428"
url= "http://221.142.48.141:5399/.i"

query_urlhaus(auth_key, url)