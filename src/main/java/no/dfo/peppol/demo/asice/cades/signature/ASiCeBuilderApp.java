package no.dfo.peppol.demo.asice.cades.signature;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore.PasswordProtection;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.SimpleASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import no.dfo.peppol.demo.files.DemoFilesAndConfig;


/*                  Create inner- and outer ASiC-E container
 * Demonstrates signing multiple documents using CAdES, ASiC-E container and CAdES-BASELINE-B signature level.
 * for details see:
 * https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/doc/dss-documentation.html 
 * https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/doc/dss-documentation.html#_complete_examples_of_signature_creation
 * chapters "19.4.2. CAdES" and "19.4.5.2. ASiC-E"
 * 
 * This demo is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY.
*/

public class ASiCeBuilderApp extends DemoFilesAndConfig{

	private static final Logger LOG = LoggerFactory.getLogger(ASiCeBuilderApp.class);
	private byte[] signedDocumentBytes;

	public ASiCeBuilderApp() {
		// add BC provider
		Security.addProvider(new BouncyCastleProvider());
	}
	public ASiCeBuilderApp(List<DSSDocument> documentsToBeSigned) throws Exception 	{
		this();
		this.signedDocumentBytes = signASiCEBaselineB(documentsToBeSigned);
	}

	// get signed document result
	public byte[] getSignedDocumentBytes() {
		return this.signedDocumentBytes;
	}

	// Use CAdES-BASELINE-B to sign ISO content.xml and metadata.xml within an ASiC-E container
	// (see https://anskaffelser.dev/payment/g1/docs/current/security/  6.1 Content Signature)
	public byte[] signASiCEBaselineB(List<DSSDocument> documentsToBeSigned) {

		try (SignatureTokenConnection signingToken = getPkcs12Token()) 
		{
			DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

			// Preparing parameters for the ASiC-E signature
			ASiCWithCAdESSignatureParameters parameters = new ASiCWithCAdESSignatureParameters();

			// We choose the level of the signature (-B, -T, -LT or -LTA).
			parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
			// We choose the container type (ASiC-S pr ASiC-E)
			parameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

			// We set the digest algorithm to use with the signature algorithm. You
			// must use the same parameter when you invoke the method sign on the token. The
			// default value for PEPPOL is SHA3_256
			parameters.setDigestAlgorithm(DigestAlgorithm.SHA3_256);

			// We set the signing certificate
			parameters.setSigningCertificate(privateKey.getCertificate());

			// We set the certificate chain
			parameters.setCertificateChain(privateKey.getCertificateChain());

			// Create common certificate verifier
			CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
			
			// Create ASiC service for signature
			ASiCWithCAdESService service = new ASiCWithCAdESService(commonCertificateVerifier);
			
			// use factory to define signature- and manifest file names
			SimpleASiCWithCAdESFilenameFactory filenameFactory = new SimpleASiCWithCAdESFilenameFactory();
			final String fingerprint = DigestUtils.sha1Hex(privateKey.getCertificate().getEncoded()); // use certificate thumb-/fingerprint
			filenameFactory.setSignatureFilename("signature-" + fingerprint + ".p7s" );
			filenameFactory.setManifestFilename("ASiCManifest-" + fingerprint + ".xml");
			service.setAsicFilenameFactory(filenameFactory);

			// Get the SignedInfo segment that need to be signed.
			ToBeSigned dataToSign = service.getDataToSign(documentsToBeSigned, parameters);

			// This function obtains the signature value for signed information
			// using the private key and specified algorithm
			DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
			SignatureValue signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);

			// We invoke the CadesService to sign the document with the signature
			// value obtained in the previous step.
			DSSDocument signedDocument = service.signDocument(documentsToBeSigned, parameters, signatureValue);
			return IOUtils.toByteArray(signedDocument.openStream());

		} catch (IOException e) {
			LOG.error("Error encrypting data : {}", e.getMessage(), e);
		}
		return null;
	}

	// Get a token connection to pkcs12 file (short cut process! See DSS documentation for explicit handling of token connection)
	// https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/apidocs/eu/europa/esig/dss/token/SignatureTokenConnection.html
	public SignatureTokenConnection getPkcs12Token() {

		try(InputStream keystore  = FileUtils.openInputStream(new FileDocument(SIGNING_KEYSTORE).getFile());)
		{
			Pkcs12SignatureToken token = 
					new Pkcs12SignatureToken(keystore, 
							new PasswordProtection(KEYSTORE_PWD.toCharArray()));
			return token;
		} catch (IOException e) {
			LOG.error("Error while retrieving keystore token : {}", e.getMessage(), e);
		}
		return null;
	}

	// create inner asice
	public byte[] createInnerAsice() {

		// Preparing the documents to be embedded in the container and signed
		List<DSSDocument> documentsToBeSigned = new ArrayList<DSSDocument>();
		DSSDocument metadataDoc;
		try {
			metadataDoc = new InMemoryDocument(
					FileUtils.readFileToByteArray(new FileDocument(METADATA).getFile()), 
					"metadata.xml", MimeTypeEnum.XML );
			documentsToBeSigned.add(metadataDoc);

			DSSDocument contentDoc = new InMemoryDocument(
					FileUtils.readFileToByteArray(new FileDocument(ISOCONTENT).getFile()), 
					"content.xml", 
					MimeTypeEnum.XML );
			documentsToBeSigned.add(contentDoc);

			// sign documents, create and write to file
			return this.signASiCEBaselineB(documentsToBeSigned);

		} catch (IOException e) {
			LOG.error("Error while creating inner ASiCE : {}", e.getMessage(), e);
		}
		return null;
	}

	// create outer asice
	public byte[] createOuterAsice(byte[] innerAsiceBytes, String content) {

		// Preparing the documents to be embedded in the container and signed
		List<DSSDocument> documentsToBeSigned = new ArrayList<DSSDocument>();
		DSSDocument sbdh;
		try {
			sbdh = new InMemoryDocument(
					FileUtils.readFileToByteArray(new FileDocument(SBDH).getFile()), 
					"sbdh.xml", 
					MimeTypeEnum.XML );
			documentsToBeSigned.add(sbdh);

			DSSDocument innerAsice = new InMemoryDocument(innerAsiceBytes, content, MimeTypeEnum.ASICE );
			documentsToBeSigned.add(innerAsice);

			// sign documents, create and write to file
			return this.signASiCEBaselineB(documentsToBeSigned);
			
		} catch (IOException e) {
			LOG.error("Error while creating outer ASiCE : {}", e.getMessage(), e);
		}
		return null;
	}

	//  create inner- and outer ASiC-E
	public static void main(String[] args) throws Exception 
	{
		ASiCeBuilderApp signer = new ASiCeBuilderApp();

		// create inner ASiCE (sign documents, create and write to file)
		byte[] innerAsiceBytes = signer.createInnerAsice();
		FileUtils.writeByteArrayToFile( new File(INNER_ASICE) , innerAsiceBytes);
		System.out.println("\nInner ASiCE written to: " + INNER_ASICE);

		// create outer ASiCE
		System.out.println("\nNow add the SBDH.xml and create outer ASiCE container: " + OUTER_ASICE + "\n");
		// sign documents, create and write to file
		FileUtils.writeByteArrayToFile( new File(OUTER_ASICE), 
				signer.createOuterAsice(innerAsiceBytes, "content.asice.sce")); // inner asic not encrypted 
	}
}
