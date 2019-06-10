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
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader('templates'))