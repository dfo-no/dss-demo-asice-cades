package no.dfo.peppol.demo.asice.cades.signature.validation;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
import eu.europa.esig.dss.validation.reports.Reports;
import no.dfo.peppol.demo.files.DemoFilesAndConfig;

/*
 * The DSS library provides an extensive number of configuration options for the validation of certificates and signatures  
 * The "ASiCE" document validation here demonstrates only a basic example.
 * 
 * Please see DSS documentation chapter "7.3. Signature validation and reports" for further details.
 * https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/doc/dss-documentation.html#signatureValidationProcess
 * https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/doc/dss-documentation.html#SignatureValidationModel
 * https://ec.europa.eu/digital-building-blocks/code/projects/ESIG/repos/dss/browse/dss-cookbook/src/main/asciidoc/_chapters/signature-validation.adoc?at=337553739b837736dd5a035a3ce03cd1c4582090
 * 
 * This demo is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY.
 */

public class ASiCeCAdESLevelBValidationApp extends DemoFilesAndConfig {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCeCAdESLevelBValidationApp.class);

	public ASiCeCAdESLevelBValidationApp(DSSDocument signedDocument){
		try {
			this.validate(signedDocument);
		} catch (Exception e) {
			LOG.error("Error validating signed document : {}", e.getMessage(), e);
		}
	}

	// validate DSSDocument - see DSS documentation 7.1.4. CertificateVerifier configuration
	public void validate(DSSDocument signedDocument ) throws Exception {

		// Validates a signed document, the content of the document is determined automatically. It can be: XML, CAdES(p7m), PDF or ASiC(zip). 
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);

		// verify the status of a certificate using the trust model (OCSP, CRL, AIA, trusted certificate source)
		// we are using OCSP onlye
		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();  
		certificateVerifier.setTrustedCertSources(getTrustedCertificateSource());  // use trusted source/-trust anchor
		certificateVerifier.setAIASource(null);  // AIA source used to collect certificates from external resources (AIA)
		certificateVerifier.setCrlSource(null);  // CRL Source to be used for external accesses (can be configured with a cache..)
		// online certificate check
		certificateVerifier.setOcspSource(getOnlineOCSPSource());  // OCSP Source to be used for external accesses (can be configured with a cache,...)
		validator.setCertificateVerifier(certificateVerifier);

		// Validate the signature only against its B-level
		validator.setValidationLevel(ValidationLevel.BASIC_SIGNATURES);

		// Allows specifying which tokens need to be extracted in the diagnostic data (Base64).
		validator.setTokenExtractionStrategy(TokenExtractionStrategy.EXTRACT_CERTIFICATES_AND_REVOCATION_DATA);

		// choose the signature policy to use
		SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
		signaturePolicyProvider.setDataLoader(null);

		// Set custom Signature Policy Provider 
		validator.setSignaturePolicyProvider(signaturePolicyProvider);

		// validate doucments, use the default and embedded validation policy
		Reports reports = validator.validateDocument();

		// write reports to file system
		this.unmarshallXmlReports(reports);
	}
	
	// Create an online OCSP source
	private RevocationSource<OCSP> getOnlineOCSPSource() {

		OCSPDataLoader ocspDataLoader = new OCSPDataLoader();
		OnlineOCSPSource ocspSource = new OnlineOCSPSource(ocspDataLoader);
		return ocspSource;
	}

	// retrieve "trust anchors" (trusted certificates) from Java keystore (see DSS documentation chapter "11. Trusted Lists")
	private CommonTrustedCertificateSource getTrustedCertificateSource() {

		CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
		try 
		{
			KeyStore keyStore = KeyStore.getInstance("JKS");
			char[] pass = KEYSTORE_PWD.toCharArray();

			// creating and initializing object of InputStream
			try(InputStream is = new FileInputStream(TRUSTANCHORS);){

				keyStore.load(is, pass);

				Enumeration<String> es = keyStore.aliases();
				String alias = "";
				while (es.hasMoreElements()) {

					alias = (String) es.nextElement();

					// store public certificates in map
					X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
					String b64Cert = Base64.getEncoder().encodeToString(cert.getEncoded());

					trustedCertificateSource.addCertificate(
							DSSUtils.loadCertificateFromBase64EncodedString(b64Cert));
				}
			}
		} catch (Exception e) {
			LOG.error("Unable to create trustedCertificateSource: {}", e.getMessage(), e);
		}
		return trustedCertificateSource;
	}

	// persist all XML reports for demonstration
	private void unmarshallXmlReports(Reports reports) {

		unmarshallDiagnosticData(reports);
		unmarshallDetailedReport(reports);
		unmarshallSimpleReport(reports);
		unmarshallValidationReport(reports);
	}

	// persist diagnostic data xml
	private void unmarshallDiagnosticData(Reports reports) 
	{
		try (FileOutputStream fout = new FileOutputStream(DIAGNOSTIC_DATA);)
		{
			final String xmlDiagnosticData = reports.getXmlDiagnosticData();
			fout.write(xmlDiagnosticData.getBytes(StandardCharsets.UTF_8.name()));
		} catch (Exception e) {
			LOG.error("Unable to unmarshall the Diagnostic data : {}", e.getMessage(), e);
		}
	}

	// persist detailed report xml
	private void unmarshallDetailedReport(Reports reports) 
	{
		try (FileOutputStream  fout = new FileOutputStream(DETAILED_REPORT);)
		{
			final String xmlDetailedReport = reports.getXmlDetailedReport();
			fout.write(xmlDetailedReport.getBytes(StandardCharsets.UTF_8.name()));
		} catch (Exception e) {
			LOG.error("Unable to unmarshall the Diagnostic data : {}", e.getMessage(), e);
		}
	}

	// persist simple report xml
	private void unmarshallSimpleReport(Reports reports) 
	{
		try (FileOutputStream  fout = new FileOutputStream(SIMPLE_REPORT);)
		{
			final String xmlSimpleReport = reports.getXmlSimpleReport();
			fout.write(xmlSimpleReport.getBytes(StandardCharsets.UTF_8.name()));

			// print qualification summary
			this.verifySimpleReport(reports.getSimpleReport());
		} catch (Exception e) {
			LOG.error("Unable to unmarshall the Diagnostic data : {}", e.getMessage(), e);
		}
	}

	// persist validation report xml
	private void unmarshallValidationReport(Reports reports) 
	{
		try (FileOutputStream  fout = new FileOutputStream(VALIDATION_REPORT);)
		{
			final String xmlValidationReport = reports.getXmlValidationReport();
			fout.write(xmlValidationReport.getBytes(StandardCharsets.UTF_8.name()));
		} catch (Exception e) {
			LOG.error("Unable to unmarshall the Diagnostic data : {}", e.getMessage(), e);
		}
	}

	// get validation summary from SimpleReport
	private void verifySimpleReport(SimpleReport simpleReport) {

		List<String> signatureIdList = simpleReport.getSignatureIdList();
		Indication indication = null;
		for (String sigId : signatureIdList) 
		{
			indication = simpleReport.getIndication(sigId);
			if (indication != Indication.TOTAL_PASSED) 
			{
				System.out.println("Validation has failed!");
				break;
			}
		}
		if(indication == Indication.TOTAL_PASSED) 
		{
			System.out.println("\n" + simpleReport.getValidationTime() + ": Successful validation!");
		} else {
			System.out.println("\n" + simpleReport.getValidationTime() + ": Validation failed!");
		}
	}

	// simple validation example 
	public static void main(String[] args) throws Exception 
	{
		new ASiCeCAdESLevelBValidationApp(
				new InMemoryDocument(
						FileUtils.readFileToByteArray(new FileDocument(INNER_ASICE_EX).getFile()),
						"content.asice.sce", 
						MimeTypeEnum.ASICE));

	}
}


