#! /usr/bin/python
  
import base64
import datetime
import json
import requests
import urllib
import sys
import os

  
# TODO: Set the severities you are interested in
SEVERITIES = 'CRITICAL,HIGH'
 
# TODO: Set your application name (as per your package.json) - todo: remove hardcoded stuff
url = 'https://eval.contrastsecurity.com/Contrast/api/ng/c992a0ef-e965-4f92-a410-e09256a78758/applications/name?'+urllib.urlencode({ 'filterText' : 'MirkosJuiceShop', 'filterServers' : 'stuttgart.local' })
  
headers = {
    'Accept': 'application/json',
    'API-Key': '3wsMBpOKKQtiqbaLpbP4Z1K4g4qh6VXV',
    'Authorization': base64.b64encode('mirko.brandner@contrastsecurity.com:G4I3FCMZW7YJOU0G')
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
url = 'https://eval.contrastsecurity.com/Contrast/api/ng/c992a0ef-e965-4f92-a410-e09256a78758/traces/'+APP_ID+'/quick?'+urllib.urlencode({ 'severities' : SEVERITIES, 'filterText' : os.environ['CIRCLE_BUILD_NUM'] })
  
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
