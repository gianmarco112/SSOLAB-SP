
# 🔐 SSOLAB-SP 🦺

Questo repository contiene l'implementazione di un service provider (SP) per il Single Sign-On (SSO) del Gruppo 2.

## 🛠️ Funzionalità 🛠️

Il SSOLAB-SP è responsabile delle seguenti attività:

1. Accettare le richieste di autenticazione dagli utenti e inviare loro la richiesta SAML.
2. Accettare le risposte SAML e verificarne la validità insieme all'Identity Provider (IdP) associato, interrogando l'IdP per confermare se ha generato la risposta con un determinato ID in un determinato momento.
3. Inviare la conferma di autenticazione (o il fallimento) all'utente.

## 🐝 Endpoint dell'API 🐝

I seguenti endpoint dell'API sono disponibili per l'interfacciamento:

1. `/auth` - Avvia il processo di autenticazione fornendo una richiesta SAML.
2. `/acs` - Riceve le risposte SAML e verifica l'autenticazione dell'utente.
3. `/slo` - Gestisce le richieste di Single Logout (SLO).

## 🎫 Formato della Richiesta e della Risposta SAML 🎫

### Risposta SAML (Esempio)
```xml
<samlp:Response
ID="responseID"
Version="2.0"
IssueInstant="timestamp"
Destination="SP-Assertion-Consumer-Service-URL">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    IdP-Entity-ID
  </saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="assertionID">
    <!-- Informazioni di autenticazione dell'utente -->
  </saml:Assertion>
</samlp:Response>
```

### AuthnRequest SAML (Esempio)
```xml
<samlp:AuthnRequest
ID="requestID"
Version="2.0"
IssueInstant="timestamp">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    SP-Entity-ID
  </saml:Issuer>
</samlp:AuthnRequest>
```

## Dettagli Implementativi

Questa implementazione è realizzata utilizzando Flask, un framework leggero per applicazioni web WSGI in Python. Include funzionalità per la creazione di richieste SAML, la verifica delle risposte SAML e la gestione degli endpoint dell'API per le interazioni SSO.

## Come Eseguire

1. Assicurarsi che Python e Flask siano installati.
2. Clonare questo repository.
3. Navigare nella directory clonata.
4. Eseguire `python main.py`.
5. Il servizio verrà avviato su `http://localhost:5000`.

## Contribuenti


Gianmarco [@gianmarco112](https://github.com/gianmarco112)
Mattia [@ErMaT02](https://github.com/ErMaT02)
Davide [@QualcunoACaso](https://github.com/QualcunoACaso)
Alessandro [@GAle982](https://github.com/GAle982)
Tommaso [@GitKindr3d](https://github.com/GitKindr3d)
Nicola [@Nex3ren](https://github.com/Nex3ren)
