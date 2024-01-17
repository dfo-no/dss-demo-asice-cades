# dss-demo-asice-cades
 
 This demo application demonstrates the use of the (Digital Signature Services) DSS library to establish message security 
in the context of the enhanced Peppol eDelivery communication infrastructure for financial messages in ISO 20022. 

It aims to adhere to the specifications outlined in "https://anskaffelser.dev/payment/g1/docs/current/rulebook" and
DSS "https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/doc/dss-documentation.html#R02"(use of CAdES/ASiCE).

The applications basic building blocks (in recommended review order):

* "DemoFilesAndConfig" - contains configuration and references to files, certificates and keystores.

* "ASiCeBuilderApp" - demonstrates the signing of message content (content.xml, metadata.xml) using CAdES signature and the creation of the inner- and outer ASiC-E container.

* "CryptoBuilderApp" - demonstrates the encryption (decryption) of the ASiCE container produced in previous step a).

* "ASiCeCAdESLevelBValidationApp" - demonstrates the basic validation of an "inner ASiCE" and the creation of DSS validation reports using online OCSP lookup (isolated in OCSPLookupApp) and certificate trust store.

* "ConstructStandardBusinessDocumentApp" - demonstrates the construction of the final "StandardBusinessDocument" XML message using the results of the building blocks demonstrated in a) and b).








		
