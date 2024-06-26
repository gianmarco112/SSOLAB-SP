import xml.etree.ElementTree as ET
import random
import time

class SAMLRequest:
    def generate(self, user_id):
        xml_str = f"""
        <SAMLRequest>
            <UserID>{user_id}</UserID>
        </SAMLRequest>
        """
        return xml_str.strip()

    def parse(self, xml_str):
        root = ET.fromstring(xml_str)
        user_id = root.find('UserID').text
        return user_id

class SAMLResponse:
    def generate(self, user_id):
        random_id = random.randint(1000, 9999)
        timestamp = int(time.time())
        xml_str = f"""
        <SAMLResponse>
            <UserID>{user_id}</UserID>
            <RandomID>{random_id}</RandomID>
            <Timestamp>{timestamp}</Timestamp>
        </SAMLResponse>
        """
        return xml_str.strip()

    def parse(self, xml_str):
        root = ET.fromstring(xml_str)
        user_id = root.find('UserID').text
        random_id = int(root.find('RandomID').text)
        timestamp = int(root.find('Timestamp').text)
        return user_id, random_id, timestamp

class ServiceProvider:
    def verify_response(self, response_xml, idp):
        user_id, random_id, timestamp = idp.parse(response_xml)
        # Simuliamo la verifica dell'ID random con l'IdP
        if random_id == idp.last_generated_id:
            return True
        else:
            return False

# Esempio di utilizzo
#idp = SAMLResponse()
#sp = ServiceProvider()

# Generazione di una richiesta SAML
#user_id = "alice"
#request_xml = SAMLRequest().generate(user_id)
#print("SAML Request:")
#print(request_xml)

# Parsing della richiesta SAML
#parsed_user_id = SAMLRequest().parse(request_xml)
#print("\nParsed User ID:")
#print(parsed_user_id)

# Generazione di una risposta SAML
#response_xml = idp.generate(user_id)
#print("\nSAML Response:")
#print(response_xml)

# Verifica della risposta SAML da parte del Service Provider
#verification_result = sp.verify_response(response_xml, idp)
#print("\nResponse Verification Result:")
#print(verification_result)