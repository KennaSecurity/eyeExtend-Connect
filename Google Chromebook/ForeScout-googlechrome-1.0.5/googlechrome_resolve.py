"""
Copyright © 2020 Forescout Technologies, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import logging
import uuid
import json
import urllib.request
from datetime import datetime, timedelta

# ***** START - AUTH API CONFIGURATION ***** #
timeout = 1800  # 30 minutes from now
now = datetime.utcnow()
timeout_datetime = now + timedelta(seconds=timeout)
epoch_time = int((now - datetime(1970, 1, 1)).total_seconds())
epoch_timeout = int((timeout_datetime - datetime(1970, 1, 1)).total_seconds())
jti_val = str(uuid.uuid4())

# Get the token
bearer_token = params["connect_authorization_token"]
google_macaddress = params["mac"]

logging.debug("Retrieved Token [ {} ] and MAC Address [ {} ]".format(bearer_token,google_macaddress))

request_header = {
    'Authorization': 'Bearer ' + bearer_token,
    'Accept': 'application/json'
}
request_url = 'https://www.googleapis.com/admin/directory/v1/customer/my_customer/devices/chromeos?projection=full&query=wifi_mac:' + google_macaddress
request_data = ''

request = urllib.request.Request(request_url, headers=request_header)
logging.debug("Requesting URL [ {} ] and including Headers [ {} ]".format(request_url,request_header))
resp = urllib.request.urlopen(request, context=ssl_context)
request_response = json.loads(resp.read())
response_json = request_response
logging.debug("Response received [ {} ]".format(response_json))

if 'chromeosdevices' not in response_json:
    #Try polling via ethernet mac macAddress
    logging.debug("Not found using WiFi MAC Address, trying Ethernet MAC Address")

    request_url = 'https://www.googleapis.com/admin/directory/v1/customer/my_customer/devices/chromeos?projection=full&query=ethernet_mac:' + google_macaddress
    request_data = ''

    request = urllib.request.Request(request_url, headers=request_header)
    resp = urllib.request.urlopen(request, context=ssl_context)
    logging.debug("Requesting URL [ {} ] and including Headers [ {} ]".format(request_url,request_header))
    request_response = json.loads(resp.read())
    response_json = request_response
    logging.debug(response_json)
    logging.debug("Response received [ {} ]".format(response_json))

# Mapping between googlechrome API response fields to CounterACT properties
googlechrome_to_ct_props_map = {
    "serialNumber": "connect_googlechrome_serial_number",
    "deviceId": "connect_googlechrome_device_id",
    "macAddress": "connect_googlechrome_mac_address",
    "ethernetMacAddress": "connect_googlechrome_eth_mac_address",
    "status": "connect_googlechrome_status",
    "annotatedAssetId": "connect_googlechrome_asset_id",
    "platformVersion": "connect_googlechrome_platform_version",
    "firmwareVersion": "connect_googlechrome_firmware_version",
    "annotatedUser": "connect_googlechrome_user",
    "lastSync": "connect_googlechrome_last_sync",
    "model": "connect_googlechrome_model",
    "osVersion": "connect_googlechrome_os_version",
    "bootMode": "connect_googlechrome_boot_mode",
    "orgUnitPath": "connect_googlechrome_org_unit",
    "annotatedLocation": "connect_googlechrome_location",
    "notes": "connect_googlechrome_notes"
}
properties = {}
response = {}

# Extraction of the device information from Google Chrome

if 'chromeosdevices' in response_json:
    try:
        chrome_device = response_json["chromeosdevices"][0]
        for key, value in chrome_device.items():
            if key in googlechrome_to_ct_props_map:
                properties[googlechrome_to_ct_props_map[key]] = value

        logging.debug("Resolve script resolved the following properties for device with MAC Address [ {} ] :".format(google_macaddress))
        logging.debug("[[ {} ]]".format(properties))
        response["properties"] = properties
    except:
        response["error"] = "Could not resolve properties. chromeosdevices extraction exception "
else:
    response["error"] = "Could not resolve properties for mac:" + google_macaddress + "API failed to get data"
