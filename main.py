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

#<samlp:Response
#ID="responseID" // Generato random dall’IdP
#Version="2.0" // Check della versione
#IssueInstant="timestamp" // Istante di risposta
#Destination="SP-Assertion-Consumer-Service-URL">
#<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
#IdP-Entity-ID // Identità dell’SP (nome o ID, decidete voi se coincidono)
#</saml:Issuer>
#<samlp:Status>
#<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/> // Codice di auth (Successo o no)
#</samlp:Status>
#<saml:Assertion
#xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
#ID="assertionID" // Fatelo coincidere con la Request ID >
#<!-- Informazioni sull'utente autenticato -->
#</saml:Assertion>
#</samlp:Response>

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
def createSAMLRequest():
    #Creazione dell'ID della SAML request
    requestID = "_" + str(uuid.uuid4())
    #Creazione del timestamp
    timestamp = datetime.datetime.now().isoformat()
    #Creazione del file XML
    root = ET.Element("samlp:AuthnRequest", xmlns="urn:oasis:names:tc:SAML:2.0:protocol", ID=requestID, Version="2.0", IssueInstant=timestamp, Destination="http://localhost:5000/acs")
    issuer = ET.SubElement(root, "saml:Issuer")
    issuer.text = "SP"
    #Creazione del file XML
    tree = ET.ElementTree(root)
    #Creazione del file XML
    tree.write("SAMLRequest.xml")
    #Apertura del file XML
    file = open("SAMLRequest.xml", "r")
    #Lettura del file XML
    data = file.read()
    #Codifica in base64
    encoded = base64.b64encode(data.encode())
    #Decodifica in stringa
    decoded = encoded.decode()
    #Ritorno della stringa
    return decoded

#Funzione per la creazione della SAML response

def createSAMLResponse():
    #Creazione dell'ID della SAML response
    responseID = "_" + str(uuid.uuid4())
    #Creazione del timestamp
    timestamp = datetime.datetime.now().isoformat()
    #Creazione del file XML
    root = ET.Element("samlp:Response", xmlns="urn:oasis:names:tc:SAML:2.0:protocol", ID=responseID, Version="2.0", IssueInstant=timestamp, Destination="http://localhost:5000/acs")
    issuer = ET.SubElement(root, "saml:Issuer")
    issuer.text = "SP"
    status = ET.SubElement(root, "samlp:Status")
    statusCode = ET.SubElement(status, "samlp:StatusCode", Value="urn:oasis:names:tc:SAML:2.0:status:Success")
    assertion = ET.SubElement(root, "saml:Assertion", xmlns="urn:oasis:names:tc:SAML:2.0:assertion", ID="assertionID")
    #Creazione del file XML
    tree = ET.ElementTree(root)
    #Creazione del file XML
    tree.write("SAMLResponse.xml")
    #Apertura del file XML
    file = open("SAMLResponse.xml", "r")
    #Lettura del file XML
    data = file.read()
    #Codifica in base64
    encoded = base64.b64encode(data.encode())
    #Decodifica in stringa
    decoded = encoded.decode()
    #Ritorno della stringa
    return decoded

#Funzione per la verifica della SAML response
def verifySAMLResponse(response):
    #Decodifica in base64
    decoded = base64.b64decode(response)
    #Creazione del file XML
    file = open("SAMLResponse.xml", "w")
    #Scrittura del file XML
    file.write(decoded.decode())
    #Chiusura del file XML
    file.close()
    #Apertura del file XML
    file = open("SAMLResponse.xml", "r")
    #Lettura del file XML
    data = file.read()
    #Parsing del file XML
    root = ET.fromstring(data)
    #Verifica della versione
    if root.attrib["Version"] != "2.0":
        return False
    #Verifica del timestamp
    timestamp = datetime.datetime.strptime(root.attrib["IssueInstant"], "%Y-%m-%dT%H:%M:%S.%f")
    if (datetime.datetime.now() - timestamp).total_seconds() > 60:
        return False
    #Verifica del codice di auth
    statusCode = root.find(".//samlp:StatusCode", namespaces={"samlp": "urn:oasis:names:tc:SAML:2.0:protocol"})
    if statusCode.attrib["Value"] != "urn:oasis:names:tc:SAML:2.0:status:Success":
        return False
    #Verifica dell'ID dell'assertion
    assertion = root.find(".//saml:Assertion", namespaces={"saml": "urn:oasis:names:tc:SAML:2.0:assertion"})
    if assertion.attrib["ID"] != "assertionID":
        return False
    return True

#API per l'interfacciamento
@app.route("/auth", methods=["GET"])
def auth():
    #Creazione della SAML request
    samlRequest = createSAMLRequest()
    #Ritorno della SAML request
    return samlRequest

@app.route("/acs", methods=["POST"])
def acs():
    #Verifica della SAML response
    response = request.data.decode()
    if verifySAMLResponse(response):
        #Creazione della SAML response
        samlResponse = createSAMLResponse()
        #Ritorno della SAML response
        return samlResponse
    else:
        return "Invalid SAML response"
    
if __name__ == "__main__":
    app.run(port=5000)





