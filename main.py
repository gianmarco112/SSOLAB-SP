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

#<samlp:AuthnRequest
#ID="requestID" //Generato random dall’SP
#Version="2.0" // Check della versione
#IssueInstant="timestamp" > // Istante di richiesta
#<\saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
#SP-Entity-ID // Identità dell’SP (nome o ID, decidete voi se coincidono)
#</saml:Issuer>
#</samlp:AuthnRequest>


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
#import classes from saml.py
from saml import SAMLRequest
from saml import SAMLResponse
from saml import ServiceProvider

app = Flask(__name__)
CORS(app)

#Definisci la classe per la saml request

#Funzione per la creazione della SAML request
def createSAMLRequest():
    #Generazione dell'ID della richiesta
    requestID = str(uuid.uuid4())
    #Generazione del timestamp
    timestamp = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    #Creazione della SAML request
    samlRequest = SAMLRequest(requestID, "2.0", timestamp, "http://localhost:5000/acs")
    #Creazione dell'elemento XML
    requestXML = ET.Element("samlp:AuthnRequest", xmlns="urn:oasis:names:tc:SAML:2.0:protocol", ID=samlRequest.ID, Version=samlRequest.Version, IssueInstant=samlRequest.IssueInstant)
    #Creazione dell'elemento Issuer
    issuer = ET.SubElement(requestXML, "saml:Issuer", xmlns="urn:oasis:names:tc:SAML:2.0:assertion")
    #Inserimento del valore dell'issuer
    issuer.text = "SP"
    #Creazione del file XML
    file = open("SAMLRequest.xml", "w")
    #Scrittura del file XML
    file.write(ET.tostring(requestXML).decode())
    #Chiusura del file XML
    file.close()
    #Apertura del file XML
    file = open("SAMLRequest.xml", "r")
    #Lettura del file XML
    data = file.read()
    #Codifica in base64
    encoded = base64.b64encode(data.encode())
    #Ritorno della SAML request
    return encoded.decode()

#Funzione per la verifica della SAML response
def verifySAMLResponse(response):
    #Decodifica della SAML response
    decoded = base64.b64decode(response)
    #Parsing della SAML response
    root = ET.fromstring(decoded)
    #Estrazione del timestamp
    timestamp = root.attrib["IssueInstant"]
    #Estrazione dell'ID della response
    responseID = root.attrib["ID"]
    #Estrazione dell'issuer
    issuer = root.find("saml:Issuer").text
    #Estrazione dello status code
    statusCode = root.find("samlp:Status/samlp:StatusCode").attrib["Value"]
    #Verifica del timestamp
    if datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ') != timestamp:
        return False
    #Verifica dell'issuer
    if issuer != "IdP":
        return False
    #Verifica dello status code
    if statusCode != "urn:oasis:names:tc:SAML:2.0:status:Success":
        return False
    #Verifica dell'ID della response
    if ServiceProvider().verify_response(decoded, SAMLResponse()):
        return True
    else:
        return False


#API per l'interfacciamento
@app.route("/auth", methods=["GET"])
def auth():
    #Creazione della SAML request
    samlRequest = createSAMLRequest()
    #Ritorno della SAML request
    return samlRequest

@app.route("/acs", methods=["POST"])
def acs():
    #Verifica della SAML response e return se può accedere o meno
    response = request.data.decode()
    if verifySAMLResponse(response):
        return "Accesso consentito"
    else:
        return "Accesso negato"
    
@app.route("/slo", methods=["POST"])
def slo():
    #Verifica della SAML response
    response = request.data.decode()
    if verifySAMLResponse(response):
        return "Logout effettuato"
    else:
        return "Errore durante il logout"
    
    
if __name__ == "__main__":
    app.run(port=5000)





