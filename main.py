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

#Definisci la classe per la saml request
class SAMLRequest:
    def __init__(self, ID, Version, IssueInstant, Destination):
        self.ID = ID
        self.Version = Version
        self.IssueInstant = IssueInstant
        self.Destination = Destination

#Funzione per la creazione della SAML request
def createSAMLRequest():
    #Creazione dell'ID della SAML request
    requestID = "_" + str(uuid.uuid4()) #Genera un ID univoco esempio: _f4f3d8f3-3b0d-4f6d-8b0f-2f3f4d3f4d3f
    #Creazione del timestamp
    timestamp = datetime.datetime.now().isoformat() #Genera un timestamp esempio: 2021-06-01T12:00:00.000000
    #Creazione del file XML
    root = ET.Element("samlp:AuthnRequest", xmlns="urn:oasis:names:tc:SAML:2.0:protocol", ID=requestID, Version="2.0", IssueInstant=timestamp, Destination="http://localhost:5000/acs") #Crea il tag radice del file XML
    issuer = ET.SubElement(root, "saml:Issuer") #Crea il tag figlio del tag radice
    issuer.text = "SP"
    #Creazione del file XML
    tree = ET.ElementTree(root) #Crea l'albero del file XML
    #Creazione del file XML
    tree.write("SAMLRequest.xml") #Scrive il file XML esempio: <samlp:AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="_f4f3d8f3-3b0d-4f6d-8b0f-2f3f4d3f4d3f" Version="2.0" IssueInstant="2021-06-01T12:00:00.000000" Destination="http://localhost:5000/acs"><saml:Issuer>SP</saml:Issuer></samlp:AuthnRequest>
    #Apertura del file XML
    file = open("SAMLRequest.xml", "r") #Apre il file XML 
    #Lettura del file XML
    data = file.read() #Legge il file XML
    #Codifica in base64
    encoded = base64.b64encode(data.encode()) #Codifica il file XML in base64 esempio: 
    #Decodifica in stringa
    decoded = encoded.decode() #Decodifica il file XML in stringa esempio: PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxucz0iaHR0cDovL2xvY2FsaG9zdDo1MDAwL2FjcyIgSUQ9Il9mNGYzZDhmMy0zYjBkLTRmNmQtOGIwZi0yZjNmNGQzZjRkM2YiIFZlcnNpb249IjIuMCIgSXNzdWluZ0luc3RhbnQ9IjIwMjEtMDYtMDFUMTI6MDA6MDAuMDAwMDAwIiBEZXN0aW5hdGlvbj0iaHR0cDovL2xvY2FsaG9zdDo1MDAwL2FjcyI+PHNhbWw6SXNzdWluZz5TUDwvc2FtbDpJc3N1aW5nPg==
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
    #verifica con l'IdP tramite API
    responseID = root.attrib["ID"]
    url = "http://localhost:8080/verify"
    headers = {"Content-Type": "application/json"}
    body = {"responseID": responseID, "timestamp": timestamp}
    response = requests.post(url, headers=headers, data=json.dumps(body))
    if response.json():
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





