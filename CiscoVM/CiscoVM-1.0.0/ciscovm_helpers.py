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
import functools
import json
import time
from datetime import datetime, timezone

import requests


class CVMHTTPClient:
    """Cisco Vulnerability Management HTTP client"""
    CHECK_EVENT_TYPE = "ping"
    POST_EVENT_TYPE = "job-results"
    # Create a custom Retry object with max retries set to 3
    RETRY_STRATEGY = {
        "total": 1,
        "backoff_factor": 1,
        "status_forcelist": [408, 429, 500, 502, 503, 504]
    }
    TIMEOUT_SECONDS = 60

    def __init__(self, url: str, uid: str, auth_token: str):
        self.full_url = f"{url.strip('/')}/{uid.strip('/').strip()}"
        self.auth_token = auth_token.strip()

    def _generate_headers(self, event_type: str = CHECK_EVENT_TYPE) -> dict:
        """Generate request headers"""
        return {
            "X-Forescout-Event": event_type,
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.auth_token}",
        }

    def response_handler(func):
        """Handle any request errors and logging them."""
        @functools.wraps(func)
        def wrap(self, *args, **kwargs):
            msg = ""
            for attempt in range(self.RETRY_STRATEGY["total"]):
                try:
                    response = func(self, *args, **kwargs)
                    if response.status_code == 200:
                        logging.debug(f"Data was sent to {self.full_url}")
                        return True, msg
                    elif response.status_code in self.RETRY_STRATEGY["status_forcelist"]:
                        # Retry request with backoff delay
                        delay = self.RETRY_STRATEGY["backoff_factor"] * (2 ** attempt)
                        msg = f"Status code: {response.status_code}"
                        logging.debug(f"{msg}. Retrying in {delay} seconds...")
                        time.sleep(delay)
                        continue
                    else:
                        msg = (f"Status code: {response.status_code} "
                               f"Response msg: {response.text}")
                        logging.debug(msg)
                        return False, msg
                except Exception as e:
                    msg = str(e)
                    break

            logging.debug(msg)
            return False, msg
        return wrap

    @response_handler
    def ping(self) -> requests.Response:
        """Check connection to the service."""
        return requests.post(self.full_url, headers=self._generate_headers(),
                             timeout=self.TIMEOUT_SECONDS)

    @response_handler
    def post(self, data: dict) -> requests.Response:
        """Send data"""
        return requests.post(
            self.full_url,
            headers=self._generate_headers(self.POST_EVENT_TYPE),
            data=json.dumps(data),
            timeout=self.TIMEOUT_SECONDS
        )


class DataGenerator:
    """Generate output data"""

    TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
    FS_PROP_FOR_CVM = (
        "mac",
        "ip",
        "dhcp_hostname",
        "vendor_classification",
        "vendor",
        "prim_classification",
    )

    def __init__(self, fs_data: dict):
        self._fs_data = fs_data

    def generate(self) -> dict:
        """Generate output JSON"""
        data = dict()
        for field_name in self.FS_PROP_FOR_CVM:
            data[field_name] = self._fs_data.get(field_name)

        data["last_seen_time"] = (
            datetime.now(timezone.utc).strftime(self.TS_FORMAT)
        )
        return data
