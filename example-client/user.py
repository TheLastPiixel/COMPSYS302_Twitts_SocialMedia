import cherrypy
import makerequest
import nacl.encoding
import nacl.signing
import sqlite3
import makerequest
import base64

def getHeader(username, password):
    cherrypy.session['username'] = username
    cherrypy.session['password'] = password
    cherrypy.session['private_key'] = nacl.signing.SigningKey.generate()
    cherrypy.session['public_key'] = cherrypy.session['private_key'].verify_key
    credentials = ('%s:%s' % cherrypy.session['username'], % cherrypy.session['password'] = password,)
    credentialsencode = base64.b64encode(credentials, 'utf-8')
    makerequest.addpubkey[cherrypy.session['public_key'], cherrypy.session['username'],],