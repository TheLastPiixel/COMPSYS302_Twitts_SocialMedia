import cherrypy
import json
import makerequest
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

#APP API CLASS
class apiApp(object):

    # CherryPy Configuration
    _cp_config = {'tools.encode.on': True,
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on': 'True',
                  }

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def ping_check(self):
        received_payload = cherrypy.request.json
        error = 0
        error_message = ""
        print(received_payload)

        if (received_payload['my_time'] is None):
            error = 1
            error_message = "Invalid time!"
        elif (received_payload['connection_address'] is None):
            error = 1
            error_message = "Invalid connection_address!"
        elif (received_payload['connection_location'] is None):
            error = 1
            error_message = "Invalid connection_location"

        if (error == 0):
            response = "ok"
        else:
            response = "error"

        response = {
            "response": response,
            "message": error_message,
            "my_time": str(time.time()),
        }

        return response

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def rx_broadcast(self):
        received_payload = cherrypy.request.json

        # Splits up the payload
        loginserver_record_str = received_payload['loginserver_record']
        loginserver_record = loginserver_record_str.split(",")
        username = loginserver_record[0]
        public_key = loginserver_record[1]
        message = received_payload['message']
        send_time = received_payload['sender_created_at']
        signature = received_payload['signature']
        print(message)

        #Loads up database
        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        # Writes credentials & keys into database
        data = [username, public_key, message, send_time, signature]
        c.execute(
            """INSERT INTO Public_Messages (Username, Public_Key, Message, Send_Time, Signature) VALUES (?,?,?,?,?)""",
            data)
        conn.commit()
        conn.close()

        response = {
            "response": "ok"
        }
        return response

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def rx_privatemessage(self):
        try:
            received_payload = cherrypy.request.json
            print(received_payload)

            # Splits up the payload
            loginserver_record_str = received_payload['loginserver_record']
            loginserver_record = loginserver_record_str.split(",")
            username = loginserver_record[0]
            public_key = loginserver_record[1]
            message = received_payload['encrypted_message']
            send_time = received_payload['sender_created_at']
            signature = received_payload['signature']
            recipient = received_payload['target_username']

            #Loads up database
            conn = sqlite3.connect('database.db')
            c = conn.cursor()

            # Writes credentials & keys into database
            data = [username, public_key, message, send_time, signature, recipient]
            c.execute(
                """INSERT INTO Private_Messages (Username, Public_Key, Encrypted_Message, Send_Time, Signature, Recipient) VALUES (?,?,?,?,?,?)""",
                data)
            conn.commit()
            conn.close()

            response = {
                "response": "ok"
            }

            return response
        except:
            response = {
                "response": "error",
                "message": "Why does your payload suck?"
            }
            return response



