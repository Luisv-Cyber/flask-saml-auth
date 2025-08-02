from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser

with open("GoogleIDPMetadata.xml", "r") as f:
    xml = f.read()

settings = OneLogin_Saml2_IdPMetadataParser.parse(xml)
print(settings)
