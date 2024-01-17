package no.dfo.peppol.demo;

import java.io.File;
import java.io.IOException;
import java.util.Base64;

import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.FileDocument;
import no.dfo.peppol.demo.asice.cades.signature.ASiCeBuilderApp;
import no.dfo.peppol.demo.bc.CryptoBuilderApp;
import no.dfo.peppol.demo.files.DemoFilesAndConfig;

/*                Construct StandardBusinessDocument
 * To collect all building blocks for the creation of the StandardBusinessDocument execute in this order:
 * 1. ASiCeBuilderApp.java
 * 2. CryptoBuilderApp.java
 * 3. optional: ASiCeCAdESLevelBValidationApp.java
 * 4. ConstructStandardBusinessDocumentApp
 * 
 * This demo is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY.
 */

public class ConstructStandardBusinessDocumentApp extends DemoFilesAndConfig {

	private static final Logger LOG = LoggerFactory.getLogger(ConstructStandardBusinessDocumentApp.class);

	public ConstructStandardBusinessDocumentApp() {

		StringBuilder sbd;
		try {
			ASiCeBuilderApp asiceBuilder = new ASiCeBuilderApp();
			
			// build/sign and encrypt, build/sign and encode
			final String binaryContent = new String( Base64.getEncoder().encode(
					asiceBuilder.createOuterAsice( 
							(new CryptoBuilderApp(
									asiceBuilder.createInnerAsice()).getEncryptedData()), "asice.content.p7m")),"UTF-8");

			sbd = new StringBuilder("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
					+ "<StandardBusinessDocument xmlns=\"http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader\">"
					+ FileUtils.readFileToString(new FileDocument(SBDH).getFile(), "UTF-8").
					replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "").
					replace(" xmlns=\"http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader\"", "") 
					+ "<BinaryContent mimeType=\"application/vnd.etsi.asic-e+zip\" xmlns=\"http://peppol.eu/xsd/ticc/envelope/1.0\">" 
					+ binaryContent + "</BinaryContent>"
					+ "</StandardBusinessDocument>");

			FileUtils.writeByteArrayToFile(new File(STANDARD_BUSINESS_DOCUMENT), sbd.toString().getBytes("UTF-8")); 
			System.out.println("\nStandardBusinessDocument written to: " + STANDARD_BUSINESS_DOCUMENT);
			
		} catch (IOException e) {
			LOG.error("Error in constructing StandardBusinessDocument : {}", e.getMessage(), e);
		}
	}

	// construct a StandardBusinessDocument from its building blocks (content.xml, metadata.xml, inner ASiCE, sbdh.xml, outer ASiCE, "BinaryContent")
	public static void main(String[] args) throws Exception 
	{
		new ConstructStandardBusinessDocumentApp();
	}
}
