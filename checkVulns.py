#! /usr/bin/python
  
import base64
import datetime
import json
import requests
import urllib
import sys
  
# TODO: Set the severities you are interested in
SEVERITIES = 'CRITICAL,HIGH'
 
# TODO: Set your application name (as per your package.json)
url = '%env.url%api/ng/%env.orgid%/applications/name?'+urllib.urlencode({ 'filterText' : 'APPLICATION NAME', 'filterServers' : '%teamcity.agent.hostname%' })
  
headers = {
    'Accept': 'application/json',
    'API-Key': '%env.apikey%',
    'Authorization': base64.b64encode('%env.username%:%env.servicekey%')
}
  
print ('HTTP GET ' + url)
response = requests.get(url, headers = headers)
  
# Check the status of the request
if (not response.ok):
    response.raise_for_status()
    exit()
  
# Parse the JSON content
json_data = json.loads(response.content)
  
# Get the application id for the app
# TODO: Error handling
APP_ID = json_data['applications'][0]['app_id']
  
# Contrast Security API request to get vulnerabilities
url = '%env.url%api/ng/%env.orgid%/traces/'+APP_ID+'/quick?'+urllib.urlencode({ 'severities' : SEVERITIES, 'filterText' : '%env.BUILD_NUMBER%' })
  
print ('HTTP GET ' + url)
response = requests.get(url, headers = headers)
  
# Check the status of the request
if (not response.ok):
    response.raise_for_status()
    exit()
  
# Parse the JSON content
json_data = json.loads(response.content)
  
vulns_all = 0
vulns_open = 0
  
for filter in json_data['filters']:
    if (filter['name'] == 'All'):
        vulns_all = filter['count']
    elif (filter['name'] == 'Open'):
        vulns_open = filter['count']
  
print ('All vulnerabilities: ' + str(vulns_all))
print ('Open vulnerabilities: ' + str(vulns_open))

# TODO Set the threshold for the number of vulnerabilities (of given severities)
if (vulns_open > 0):
    sys.exit(1)
