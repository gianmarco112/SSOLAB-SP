#Gruppo 1: User / Browser
#1. Deve poter contattare l’SP
#2. Deve poter inviare la SAML request dell’SP al
#IdP scelto, insieme alle credenziali di Auth
#3. Deve inviare la SAML response al SP
#4. Deve sapere quando è riuscito ad accedere o
#meno ai servizi dell’SP.


# Path: WebPage.py

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

#Definisci la classe per la saml request
class SAMLRequest:
    def __init__(self, ID, Version, IssueInstant, Destination):
        self.ID = ID
        self.Version = Version
        self.IssueInstant = IssueInstant
        self.Destination = Destination
        self.Issuer = "SP"

#webpage per la richiesta di autenticazione
@app.route('/auth', methods=['POST'])
def auth():
    #Estrai i dati dalla richiesta
    data = request.get_json()
    username = data['username']
    password = data['password']
    idp = data['idp']
    acs = data['acs']
    
    #Genera l'ID della richiesta
    requestID = str(uuid.uuid4())
    
    #Genera l'ID della risposta
    responseID = str(uuid.uuid4())
    
    #Genera il timestamp
    timestamp = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    
    #Genera la SAML request
    samlRequest = SAMLRequest(requestID, "2.0", timestamp, acs)
    
    #Costruisci la richiesta
    requestXML = ET.Element("samlp:AuthnRequest", xmlns="urn:oasis:names:tc:SAML:2.0:protocol", ID=samlRequest.ID, Version=samlRequest.Version, IssueInstant=samlRequest.IssueInstant)
    issuer = ET.SubElement(requestXML, "saml:Issuer")
    issuer.text = samlRequest.Issuer
    
    #Serializza la richiesta
    requestString = ET.tostring(requestXML, encoding='utf-8', method='xml').decode()
    
    #Codifica la richiesta in base64
    encodedRequest = base64.b64encode(requestString.encode()).decode()
    
    #Invia la richiesta all'IdP
    response = requests.post(idp, json={"SAMLRequest": encodedRequest})
    
    #Decodifica la risposta
    responseXML = ET.fromstring(base64.b64decode(response.json()['SAMLResponse']))
    
    #Estrai i dati dalla risposta
    assertion = responseXML.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
    user = assertion.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}NameID").text
    
    #Verifica la firma
    signature = responseXML.find(".//{http://www.w3.org/2000/09/xmldsig#}Signature")
    signedInfo = signature.find(".//{http://www.w3.org/2000/09/xmldsig#}SignedInfo")
    signatureValue = signature.find(".//{http://www.w3.org/2000/09/xmldsig#}SignatureValue").text
    canonicalized = ET.tostring(signedInfo, encoding='utf-8', method='xml').decode()
    m = hashlib.sha256()
    m.update(canonicalized.encode())
    digest = m.digest()
    if signatureValue != base64.b64encode(digest).decode():
        return jsonify({"error": "Invalid signature"})
    
    #Verifica l'ID della risposta
    if responseXML.attrib["ID"] != responseID:
        return jsonify({"error": "Invalid response ID"})
    
    #Verifica il timestamp
    responseTimestamp = datetime.datetime.strptime(responseXML.attrib["IssueInstant"], "%Y-%m-%dT%H:%M:%S.%fZ")
    if (datetime.datetime.now() - responseTimestamp).total_seconds() > 60:
        return jsonify({"error": "Invalid timestamp"})
    
    #Verifica il codice di autenticazione
    statusCode = responseXML.find(".//{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode")
    if statusCode.attrib["Value"] != "urn:oasis:names:tc:SAML:2.0:status:Success":
        return jsonify({"error": "Authentication failed"})
    
    #Invia la risposta all'utente
    return jsonify({"user": user})

if __name__ == '__main__':
    app.run(port=5000)
