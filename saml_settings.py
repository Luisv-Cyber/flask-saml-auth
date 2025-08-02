import os

def get_saml_settings():
    settings = {
        "strict": True,
        "debug": True,
        "sp": {
            "entityId": "http://localhost:5000/metadata/",
            "assertionConsumerService": {
                "url": "http://localhost:5000/acs/",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            },
            "singleLogoutService": {
                "url": "http://localhost:5000/sls/",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "x509cert": "",
            "privateKey": ""
        },
        "idp": {
            "entityId": "",
            "singleSignOnService": {
                "url": "",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "singleLogoutService": {
                "url": "",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "x509cert": ""
        }
    }