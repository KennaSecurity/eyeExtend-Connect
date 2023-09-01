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

logging.debug("===> Starting CiscoVM Script")

# Defining Variables
response = dict(properties=dict(connect_ciscovm_exported=True))


url = params["connect_ciscovm_url"]
token = params["connect_ciscovm_token"]
uid = params["connect_ciscovm_uid"]

try:
    logging.debug(f"PARAMS: {params}")
    client = ciscovm_helpers.CVMHTTPClient(url=url, auth_token=token, uid=uid)
    was_sent = client.post(json=ciscovm_helpers.DataGenerator(fs_data=params).generate())
    if not was_sent:
        response["properties"]["connect_ciscovm_exported"] = False
        response["error"] = "Couldn't send data."
except Exception as e:
    response["properties"]["connect_ciscovm_exported"] = False
    response["error"] = str(e)

logging.debug("===> End CiscoVM Script")
