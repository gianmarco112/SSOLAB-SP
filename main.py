# SSOLAB-SP
#Gruppo 2: SP
#1. Deve accettare richieste di Auth dagli utenti e inviare loro la SAML request
#2. Deve accettare di ritorno le SAML response e verificare assieme all’IdP associato la validità, 
# chiedendo all’IdP se ha generato lui la risposta di certo ID a certo Time
#3. Inviare la conferma di Auth all’utente (o fallimento)

#API per l'interfacciamento
#1. /auth
#2. /acs
#3. /slo

from flask import Flask, request, jsonify
import requests
import json
import datetime
import os
import base64
import xml.etree.ElementTree as ET
import xml.dom.minidom
import xmltodict
import uuid
import hashlib
from urllib.parse import urlparse
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

#Funzione per la creazione della SAML request


