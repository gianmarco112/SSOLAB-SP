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
        
    def toXML(self):
        root = ET.Element("samlp:AuthnRequest", xmlns="urn:oasis:names:tc:SAML:2.0:protocol", ID=self.ID, Version=self.Version, IssueInstant=self.IssueInstant, Destination=self.Destination)
        issuer = ET.SubElement(root, "saml:Issuer")
        issuer.text = self.Issuer
        tree = ET.ElementTree(root)
        tree.write("SAMLRequest.xml")
        file = open("SAMLRequest.xml", "r")
        data = file.read()
        encoded = base64.b64encode(data.encode())
        decoded = encoded.decode()
        return decoded

#Funzione per la creazione della SAML request
def createSAMLRequest():
    ID = str(uuid.uuid4())
    Version = "2.0"
    IssueInstant = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")
    Destination = "http://localhost:5000/acs"
    samlRequest = SAMLRequest(ID, Version, IssueInstant, Destination)
    return samlRequest.toXML()


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





