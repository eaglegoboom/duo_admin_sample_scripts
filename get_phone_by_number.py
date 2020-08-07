#!/usr/bin/env python

"""
For more information on this API, please visit:
https://duo.com/docs/adminapi

 -

Script Dependencies:
    requests
    pprint
Depencency Installation:
    $ pip install -r requirements.txt

System Requirements:
    - Duo MFA, Duo Access or Duo Beyond account with aministrator priviliedges.
    - Duo Admin API enabled

Copyright (c) 2020, Cisco Systems, Inc. All rights reserved.
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

import json, base64, email, hmac, hashlib, urllib3, urllib
import requests
import pprint
import config

# Disable SSL warnings
urllib3.disable_warnings()

# Imported API configuration variables
API_HOSTNAME = config.DUO_API_HOSTNAME
S_KEY = config.DUO_API_SECRET_KEY
I_KEY = config.DUO_API_INTEGRATION_KEY

# Script specific variables
METHOD = 'GET'
API_PATH = '/admin/v1/phones'
NUMBER = ''  # Phone number of device
PARAMS = {'number': NUMBER}

# Requesr signing helper function
def sign(method=METHOD, 
         host=API_HOSTNAME, 
         path=API_PATH, 
         params=PARAMS, 
         skey=S_KEY, 
         ikey=I_KEY):

    """
    Return HTTP Basic Authentication ("Authorization" and "Date") headers.
    method, host, path: strings from request
    params: dict of request parameters
    skey: secret key
    ikey: integration key
    """

    # create canonical string
    now = email.utils.formatdate()
    canon = [now, method.upper(), host.lower(), path]
    args = []
    for key in sorted(params.keys()):
        val = params[key]
        if isinstance(val, str):
            val = val.encode("utf-8")
        args.append(
            '%s=%s' % (urllib.parse.quote(key, '~'), urllib.parse.quote(val, '~')))
    canon.append('&'.join(args))
    canon = '\n'.join(canon)

    # sign canonical string
    sig = hmac.new(skey.encode('utf-8'), canon.encode('utf-8'), hashlib.sha1)
    auth = '%s:%s' % (ikey, sig.hexdigest())
    encoded_auth = base64.b64encode(auth.encode('utf-8'))

    # return headers
    return {'Date': now, 'Authorization': 'Basic %s' % str(encoded_auth, 'UTF-8')}


url = "https://{}{}?number={}".format(API_HOSTNAME, API_PATH, NUMBER)

request_headers = sign()

users = requests.request(METHOD, url, headers=request_headers, verify=False)

pprint.pprint(json.loads(users.content))