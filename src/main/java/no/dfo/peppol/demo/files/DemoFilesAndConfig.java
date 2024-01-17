package no.dfo.peppol.demo.files;

/* Resources used and result files created 
 * 
 * This demo is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY.
 */

public class DemoFilesAndConfig {
	
	// PKI resource files/-settings
	protected static final String RESOURCE_PATH = "src/main/resources/";
	protected static final String SIGNING_KEYSTORE = RESOURCE_PATH + "PeppolDemoSign.p12";		// PKCS12 keystore with private signing key
	protected static final String ENCRYPTION_KEYSTORE = RESOURCE_PATH + "PeppolDemoEnc.p12";	// PKCS12 keystore with private encryption key
	protected static final String TRUSTANCHORS = RESOURCE_PATH + "TrustAnchors.jks"; 			// keystore containing trusted certificates
	protected static final String KEYSTORE_PWD = "1234";
		
	// Test files/-settings for inner-/outer asice
	protected static final String TEST_PATH = "src/main/resources/";
	protected static final String SBDH = TEST_PATH + "sbdh.xml";					// StandardBusinessDocumentHeader (Sender, Receiver, ...)
	protected static final String METADATA = TEST_PATH + "metadata.xml";			// Bank specific configuration file
	protected static final String ISOCONTENT = TEST_PATH + "content.xml";			// ISO 20022 xml content 
	protected static final String INNER_ASICE_EX = TEST_PATH + "content.asice.sce";	// inner ASiCE example
	protected static final String P7M_EX = TEST_PATH + "content.asice.p7m";			// encrypted inner ASiCE example
	
	// Certificates for signature validation 
	protected static final String SIGNING_CERTIFICATE = TEST_PATH + "PeppolDemo_AS_Commfides.crt";		// simulate 3rd party certificate
	protected static final String SIGNING_ROOT_CERTIFICATE = TEST_PATH + "CommfidesLegalPerson.crt";	// simulate 3rd party certificate
	
	// Result files/-settings - created when excuting demo classes for signing, encryption, validation and finally StandardBusinessDocument creation
	protected static final String RESULT_PATH = "C:/temp/";
	protected static final String INNER_ASICE = RESULT_PATH + "content.asice.sce";						// inner ASiCE including metadata.xml, content.xml and signature
	protected static final String ENCRYPTED_INNER_ASICE = RESULT_PATH + "content.asice.p7m";			// encrypted ASiCE including metadata.xml, content.xml and signature
	protected static final String DECRYPTED_INNER_ASICE = RESULT_PATH + "decrypted-content.asice.zip";	// decrypted inner ASiCE
	protected static final String OUTER_ASICE = RESULT_PATH + "outer.asice.sce";						// outer ASiCE containing inner ASiCE (not encrypted)
	protected static final String STANDARD_BUSINESS_DOCUMENT = RESULT_PATH + "StandardBusinessDocument.xml"; // final result: StandardBusinessDocument 
	
	// Validation report files/-settings - determine validation success (see DSS documentation for details)
	protected static final String REPORT_PATH = "C:/temp/";
	protected static final String DIAGNOSTIC_DATA = REPORT_PATH + "DiagnosticData.xml";
	protected static final String SIMPLE_REPORT = REPORT_PATH + "SimpleReport.xml";
	protected static final String DETAILED_REPORT = REPORT_PATH + "DetailedReport.xml";
	protected static final String VALIDATION_REPORT = REPORT_PATH + "ValidationReport.xml";

}
