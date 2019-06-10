import cherrypy
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
import socket
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader('templates'))

startHTML = '<html><head><title>CS302 JCHU491</title>' \
            '<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous">' \
            '<body><script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>' \
            '<script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js" integrity="sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1" crossorigin="anonymous"></script>' \
            '<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js" integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM" crossorigin="anonymous"></script>'
            #startHTML = "<html><head><title>CS302 JCHU491</title><link rel='stylesheet' href='/static/example.css' /></head><body>"

class MainApp(object):

	#CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }       

	# If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        Page = startHTML + "I don't know where you're trying to go, so have a 404 Error."
        cherrypy.response.status = 404
        return Page

    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def home(self, status="online"):
        template = env.get_template('main.html')
        report(status)

        users = list_users()
        userlist = {}
        statuslist = {}
        for i in range(len(users)):
            userlist[i] = users[i]['username']
            statuslist[i] = users[i]['status']

        #Creates array of messages
        msguser, msgpubkey, msg, msgtime = read_public_messages()

        Page = template.render(username=cherrypy.session['username'], users=userlist, statuslist=statuslist,
                               msguser=msguser, msgpubkey=msgpubkey, msgtime=msgtime, msg=msg, status=status)

        return Page
        
    @cherrypy.expose
    def index(self, bad_attempt=0):
        template = env.get_template('login.html')

        if bad_attempt != 0:
            error_message = "Invalid username/password"
            error = 1
        else:
            error_message = ""
            error = 0
        Page = template.render(Error=error)

        return Page
    
    @cherrypy.expose    
    def sum(self, a=0, b=0): #All inputs are strings by default
        output = int(a)+int(b)
        return str(output)
        
    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None, uniquepassword=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        authorised = ping(username, password)['authentication'] == 'basic'
        if authorised:
            cherrypy.session['username'] = username
            cherrypy.session['password'] = password
            cherrypy.session['uniquepassword'] = uniquepassword
            loginmanager()

            #add_privatedata()
            get_privatedata()
#            ping_check()
            raise cherrypy.HTTPRedirect('/home')
        else:
            raise cherrypy.HTTPRedirect('/?bad_attempt=1')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        if username is None:
            pass
        else:
            cherrypy.lib.sessions.expire()
            report("offline")
        raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def loopy(self): #TODO LOOPS EVERY 30S
        print("Loop-de-doop-te-Loopty-Loop")
        report(str(cherrypy.session['status']))
        ping_check_all()

    @cherrypy.expose
    def changestatus(self, status="offline"):
        report(status)
        cherrypy.session['status'] = status

    @cherrypy.expose
    def sendbroadcast(self, message=None):
        #Get list of URLs to send to
        listusers = list_users()
        print(listusers)

        for i in range(len(listusers)):
            try:
                connection_address = listusers[i]['connection_address']
                url = "http://"+str(connection_address)+"/api/rx_broadcast"
                broadcast(message, url)
                print("Broadcasted to: ")
                print(url)
            except:
                pass
                print("Broadcast Failed!: ")
                print(url)

        return "Messages Sent"


    @cherrypy.expose
    def get_online_users(self):
        users = list_users()

        data = {
            "users": users
        }

        return json.dumps(data)

    @cherrypy.expose
    def get_current_messages(self):
        # Opens database
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        messagelist = []

        c.execute('SELECT * FROM Public_Messages')
        rows = c.fetchall()

        for row in rows:
            messagepayload = {
                "username": str(row[0]),
                "public_key": str(row[1]),
                "message": str(row[2]),
                "send_time": str(row[3])
            }
            messagelist.append(messagepayload)

        conn.close()

        data = {
            "messagelist": messagelist
        }

        return json.dumps(data)

    @cherrypy.expose
    def send_private_message(self, message=None, username=None):
        print("sending private message to:")
        print(username)
        sendprivatemessage(str(message), str(username))

    @cherrypy.expose
    def get_private_messages(self):
        data = {
            "messagelist": read_private_messages()
        }
        return json.dumps(data)

###
### Functions only after here
###


def ping(username, password):#public_key, private_key):
    url = "http://cs302.kiwi.land/api/ping"

    payload = {

    }
    response = makerequest.sendPayload(url, payload, username, password)
    print("My ping response is: ")
    print(response)
    return response

def loginmanager():
    username = cherrypy.session['username']
    password = cherrypy.session['password']

    # Loads up database
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    response = ping(username, password)['response']

    if (response == 'ok'):
        c.execute('SELECT * FROM Users WHERE Username=(?)', [cherrypy.session['username'], ])
        data = c.fetchone()
        if data is None:
            generate_Keys()

        else:
            load_Keys()

    conn.close()

def generate_Keys():
    username = cherrypy.session['username']
    password = cherrypy.session['password']

    #Loads up database
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    #Generates public and private key
    addPubKey(username, password)
    private_key = cherrypy.session['private_key'].encode(encoder=nacl.encoding.HexEncoder)
    public_key = cherrypy.session['public_key'].decode('utf-8')
    loginserver_record = cherrypy.session['loginserver_record']

    #Writes credentials & keys into database
    data = [username, password, private_key, public_key, loginserver_record]
    c.execute("""INSERT INTO Users (Username, Password_Hex, Private_Key, Public_Key, Loginserver_Record) VALUES (?,?,?,?,?)""", data)
    conn.commit()
    conn.close()

def load_Keys():
    #Opens database
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute('SELECT * FROM Users WHERE Username=(?)', [cherrypy.session['username'], ])
    data = c.fetchone()
    cherrypy.session['private_key'] = nacl.signing.SigningKey(data[2], encoder=nacl.encoding.HexEncoder)
    cherrypy.session['public_key'] = data[3].encode('utf-8')
    cherrypy.session['loginserver_record'] = data[4]
    cherrypy.session['public_key_str'] = cherrypy.session['public_key'].decode('utf-8')
    conn.close()


def addPubKey(username, password):
    url = "http://cs302.kiwi.land/api/add_pubkey"

    cherrypy.session['private_key'] = nacl.signing.SigningKey.generate()

    cherrypy.session['public_key'] = cherrypy.session['private_key'].verify_key.encode(encoder=nacl.encoding.HexEncoder)
    cherrypy.session['public_key_str'] = cherrypy.session['public_key'].decode('utf-8')
    public_key_bytes = bytes(cherrypy.session['public_key_str'] + username, encoding='utf-8')

    signed = cherrypy.session['private_key'].sign(public_key_bytes, encoder=nacl.encoding.HexEncoder)

    payload = {
        "pubkey": cherrypy.session['public_key_str'],
        "username": username,
        "signature": signed.signature.decode('utf-8')
    }
    response = makerequest.sendPayload(url, payload, username, password)
    cherrypy.session['loginserver_record'] = response['loginserver_record']

def report(status):
    url = "http://cs302.kiwi.land/api/report"
    public_key = cherrypy.session['public_key_str']
    print("Reporting for Duty, Sir")

    username = cherrypy.session['username']
    password = cherrypy.session['password']

    payload = {
        "connection_address": str(socket.gethostbyname(socket.getfqdn())) + ":1234", 
        "connection_location": 2, #HARD CODED PLS CHANGE
        "incoming_pubkey": public_key,
        "status": status 
    }
    response = makerequest.sendPayload(url, payload, username, password)

def broadcast(message, url):

    username = cherrypy.session['username']
    password = cherrypy.session['password']
    loginserver_record = cherrypy.session['loginserver_record']
    sender_created_at = time.time()-100

    payload = {
        "loginserver_record": loginserver_record,
        "message": message,
        "sender_created_at": str(sender_created_at),
        "signature": sign(str(loginserver_record) + message + str(sender_created_at))
    }
    response = makerequest.sendPayload(url, payload, username, password)
    return response


def sendprivatemessage(message=None, username=None):
    userfound = False
    listusers = list_users()
    print('sending private message')

    for i in range(len(listusers)):
        if listusers[i]['username'] == username:
            connection_address = listusers[i]['connection_address']
            target_publickey = listusers[i]['incoming_pubkey']
            userfound = True
        else:
            pass

    if (userfound is True):
        url = "http://" + str(connection_address) + "/api/rx_privatemessage"
        rx_privatemessage(message, url, username, target_publickey)
        print("Private Message sent to (sendprivatemessages): ")
        print(username)
        return "Private Message Send"


    print("Private Message Failed")
    return "Private Message Failed"

def rx_privatemessage(message, url, target_username, target_pubkey_str):
    username = cherrypy.session['username']
    password = cherrypy.session['password']

    loginserver_record = cherrypy.session['loginserver_record']
    target_pubkey = target_pubkey_str.encode('utf-8') #TODO HARD CODED PLS CHANGE
    encrypted_message = sealed_box(message, target_pubkey)
    sender_created_at = str(time.time())
    signature = sign(loginserver_record + target_pubkey_str + target_username + encrypted_message + sender_created_at)

    payload = {
        "loginserver_record": loginserver_record,
        "target_pubkey": target_pubkey_str,
        "target_username": target_username,
        "encrypted_message": encrypted_message,
        "sender_created_at": sender_created_at,
        "signature": signature
    }

    # Loads up database to store sent message
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    public_key = cherrypy.session['public_key']
    myencrypted_message = sealed_box(message, public_key)
    # Writes credentials & keys into database
    data = [str(username), public_key, myencrypted_message, sender_created_at, str(signature), str(username)]
    c.execute(
        """INSERT INTO Private_Messages (Username, Public_Key, Encrypted_Message, Send_Time, Signature, Recipient) VALUES (?,?,?,?,?,?)""",
        data)
    conn.commit()
    conn.close()

    print(payload)
    response = makerequest.sendPayload(url, payload, username, password)
    print(response)

def list_users():
    url = "http://cs302.kiwi.land/api/list_users"

    username = cherrypy.session['username']
    password = cherrypy.session['password']

    payload = {

    }
    response = makerequest.sendPayload(url, payload, username, password)

    status = response['response']
    users = response['users']
    return users

def sign(message):
    message_bytes = bytes(message, encoding='utf-8')
    signed = cherrypy.session['private_key'].sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    decoded = signed.signature.decode('utf-8')
    return decoded

def list_apis(username, password):
    url = "http://cs302.kiwi.land/api/list_apis"
    payload = {

    }
    response = makerequest.sendPayload(url, payload, username, password)

def add_privatedata(): #TODO NOT DONE
    url = "http://cs302.kiwi.land/api/add_privatedata"

    username = cherrypy.session['username']
    password = cherrypy.session['password']

    #PRIVATE DATA
    prikey = ""
    blocked_pubkeys = ""
    blocked_usernames = "jono, mpop"
    blocked_message_signatures = ""
    blocked_words = ""
    favourite_message_signatures = ""
    friends_username = ""
    Data = {"prikey": prikey,
            "blocked_pubkeys": blocked_pubkeys,
            "blocked_usernames": blocked_usernames,
            "blocked_message_signatures": blocked_message_signatures,
            "blocked_words": blocked_words,
            "favourite_message_signatures": favourite_message_signatures,
            "friends_username": friends_username
            }
    privatedata = encrypt(Data)

    loginserver_record = cherrypy.session['loginserver_record']
    client_saved_at = str(time.time())
    signature = sign(str(privatedata) + str(loginserver_record) + client_saved_at)

    payload = {
        "privatedata": privatedata,
        "loginserver_record": loginserver_record,
        "client_saved_at": client_saved_at,
        "signature": signature
    }
    response = makerequest.sendPayload(url, payload, username, password)
    print("add_privatedata response: " + response['response'])

def get_privatedata(): #TODO PUT IN TRY CATCH
    url = "http://cs302.kiwi.land/api/get_privatedata"
    username = cherrypy.session['username']
    password = cherrypy.session['password']

    payload = {

    }
    response = makerequest.sendPayload(url, payload, username, password)

    encrypted = response['privatedata']
    privatedata = decrypt(encrypted)

    print("Private Data: ")
    print(privatedata)
    return privatedata

#SECRET BOX, ENCRYPTING & DECRYPTING
def generate_secret_box(): #TODO NOT DONE
    uniquepassword = cherrypy.session['uniquepassword']
    uniquepassword_bytes = bytes(uniquepassword, "utf-8")
    salt = bytes((uniquepassword*16)[0:16], "utf-8")

    symetrickey = nacl.pwhash.argon2i.kdf(32, uniquepassword_bytes, salt, 8, 536870912) #Maybe not 32???
    box = nacl.secret.SecretBox(symetrickey)
    return box

def encrypt(message): #TODO NOT DONE
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    box = generate_secret_box()

    jsonstr = json.dumps(message)
    msgbytes = bytes(jsonstr, "utf-8")

    encrypted = box.encrypt(msgbytes, nonce)
    encodedmessage = base64.b64encode(encrypted)

    return encodedmessage.decode('utf-8')

def decrypt(encryptedmsg):
    box = generate_secret_box()
#    encrypt = bytes(encryptedmsg, "utf-8")
    encrypted = base64.b64decode(encryptedmsg)

    decryptmsg = box.decrypt(encrypted)
    msgstr = json.loads(decryptmsg.decode('utf-8'))

    return msgstr

def ping_check_all():
    #Get list of URLs to send to
    listusers = list_users()
    print("Check Ping Pong Ding Dong")

    for i in range(len(listusers)):
        try:
            connection_address = listusers[i]['connection_address']
            url = "http://"+str(connection_address)+"/api/rx_broadcast"
            ping_check(url)
            #print("Ping Check Successful: ")
            #print(url)
        except:
            pass
            #print("Ping Check Failed!: ")
            #print(url)

    return "Messages Sent"


def ping_check(url): #TODO I THINK IT NEEDS TO BE TRY CATCH
    username = cherrypy.session['username']
    password = cherrypy.session['password']

    my_time = str(time.time())
    connection_address = "125.239.153.97" #TODO HARD CODED PLS CHANGe
    connection_location = 2 #TODO Hard coded

    payload = {
        "my_time": my_time,
        "connection_address": connection_address,
        "connection_location": connection_location
    }

    try:
        response = makerequest.sendPayload(url, payload, username, password)
        print("Yo I ping checked: ")
        print(response)
    except:
        print("Ping check failed")

def read_public_messages():
    # Opens database
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    usernames = {}
    public_keys = {}
    messages = {}
    send_times = {}
    i = 0

    for row in c.execute('SELECT * FROM Public_Messages'):
        usernames[i] = row[0]
        public_keys[i] = row[1]
        messages[i] = row[2]
        send_times[i] = row[3]
        i = i + 1

    conn.close()
    return usernames, public_keys, messages, send_times

def sealed_box(message, userpubkey):
    message_bytes = bytes(message, encoding='utf-8')
    verify_key = nacl.signing.VerifyKey(userpubkey, encoder=nacl.encoding.HexEncoder)
    publickey = verify_key.to_curve25519_public_key()
    sealed_box = nacl.public.SealedBox(publickey)
    encrypt = sealed_box.encrypt(message_bytes, encoder=nacl.encoding.HexEncoder)
    newmessage = encrypt.decode('utf-8')

    return newmessage

def open_sealed_box(sealed_message):
    signing_key = cherrypy.session['private_key']
    signing_curvekey = signing_key.to_curve25519_private_key()

    sealed_box = nacl.public.SealedBox(signing_curvekey)
    encrypted_message = sealed_message.encode('utf-8')
    decrypted_message = sealed_box.decrypt(encrypted_message, encoder=nacl.encoding.HexEncoder).decode('utf-8')

    return decrypted_message
    print("Decrypted message: ", decrypted_message)


def load_new_apikey():
    url = "http://cs302.kiwi.land/api/load_new_apikey"

    username = cherrypy.session['username']
    password = cherrypy.session['password']

    payload = {

    }
    response = makerequest.sendPayload(url, payload, username, password)
    cherrypy.session['api_key'] = response['api_key']


def read_private_messages():
    # Opens database
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    message_list = []

    for row in c.execute('SELECT * FROM Private_Messages'):
        if (row[5] == str(cherrypy.session['username'])):
            encrypted_message = row[2]
            message = {
                "username": str(row[0]),
                "public_keys": str(row[1]),
                "message": str(open_sealed_box(encrypted_message)),
                "send_time": str(row[3])
            }
            message_list.append(message)

    conn.close()
    return message_list





