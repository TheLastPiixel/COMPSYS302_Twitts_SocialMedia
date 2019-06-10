import urllib.request
import server
import json
import base64
import cherrypy
import cherrypy
import nacl.encoding
import nacl.signing
import nacl.secret
import nacl.utils
import nacl.pwhash
import sqlite3
import makerequest
import base64
import main
import json
import time
import ast

useapikey = False

# url = "http://cs302.kiwi.land/api/report"
#
#
#
# #create HTTP BASIC authorization header
# credentials = ('%s:%s' % (username, password))
# b64_credentials = base64.b64encode(credentials.encode('ascii'))
# headers = {
#     'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
#     'Content-Type': 'application/json; charset=utf-8',
# }
#
# payload = {
#     # STUDENT TO COMPLETE THIS...
#     "connection_location": "2",
#     "connection_address": "202.36.244.10"
# }

#STUDENT TO COMPLETE:
#1. convert the payload into json representation,

#2. ensure the payload is in bytes, not a string

#3. pass the payload bytes into this function


def sendPayload(url, payload, username, password):

    headers = makeHeader(username, password)

    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers)
        response = urllib.request.urlopen(req, timeout=2)
        data = response.read()  # read the received bytes
        encoding = response.info().get_content_charset('utf-8')  #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()

    JSON_object = json.loads(data.decode(encoding))
    return(JSON_object)

def makeHeader(username, password):
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }
    return headers
