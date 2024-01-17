package no.dfo.peppol.demo.bc;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore.PasswordProtection;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.util.Collection;
import java.util.List;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.Recipient;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.KSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import no.dfo.peppol.demo.files.DemoFilesAndConfig;

/*
 * Demonstrate encryption/decryption of "ASiC-E container" byte arrays using BouncyCastle
 * see https://www.bouncycastle.org/documentation.html 
 * 
 * This demo is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY.
 */

public class CryptoBuilderApp extends DemoFilesAndConfig {

	private static final Logger LOG = LoggerFactory.getLogger(CryptoBuilderApp.class);
	private byte[] encryptedData;

	// default
	public CryptoBuilderApp() {
		// add BC provider
		Security.addProvider(new BouncyCastleProvider());
	}

	// constructor encrypt (demo)
	public CryptoBuilderApp(byte[] data) {
		this();
		try (SignatureTokenConnection token = this.getPkcs12Token()) 
		{
			X509Certificate recipientCert = token.getKeys().get(0).getCertificate().getCertificate();
			this.encryptedData = this.encryptData(data, recipientCert);

		}catch (Exception e) {
			LOG.error("Error encrypting data : {}", e.getMessage(), e);
		}
	}

	// get encrypted data
	public byte[] getEncryptedData() {
		return this.encryptedData;
	}

	// 2022-11-18 Rulebook requirement OAEP
	public byte[] encryptData(byte[] data, X509Certificate recipientCert){

		// General class for generating a CMS enveloped-data message
		CMSEnvelopedDataGenerator envelopedGenerator = new CMSEnvelopedDataGenerator();
		JcaAlgorithmParametersConverter paramsConverter = new JcaAlgorithmParametersConverter();

		// Constructs a parameter set for OAEP padding as defined in the PKCS #1 standard using the specified message digest algorithm 
		OAEPParameterSpec oaepSpec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
		try 
		{
			AlgorithmIdentifier algorithmIdentifier = paramsConverter.getAlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP, oaepSpec);
			/*
			 * @param recipientCert certificate carrying the public key.
			 * @param algorithmIdentifier the identifier and parameters for the encryption algorithm to be used.
			 */
			JceKeyTransRecipientInfoGenerator recipient = new JceKeyTransRecipientInfoGenerator(recipientCert, algorithmIdentifier).setProvider("BC");  

			envelopedGenerator.addRecipientInfoGenerator((RecipientInfoGenerator)recipient);

			// a holding class for a byte array of data to be processed
			CMSProcessableByteArray cMSProcessableByteArray = new CMSProcessableByteArray(data);

			// General interface for an operator that is able to produce an OutputStream that will output encrypted data
			OutputEncryptor encryptor = (new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_GCM)).setProvider("BC").build();

			// encrypt
			CMSEnvelopedData cmsEnvelopedData = envelopedGenerator.generate((CMSTypedData)cMSProcessableByteArray, encryptor);
			encryptedData = cmsEnvelopedData.getEncoded();

		} catch (CertificateEncodingException | CMSException | IOException | InvalidAlgorithmParameterException e) {
			LOG.error("Error encrypting data : {}", e.getMessage(), e);
		}
		return encryptedData;
	}

	// decrypt encrypted bytes
	public byte[] decryptData(byte[] encryptedData, PrivateKey decryptionKey) 
	{
		byte[] decryptedData = null;

		try 
		{
			if (encryptedData != null && decryptionKey != null) 
			{
				CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedData);
				Collection<RecipientInformation> recip = envelopedData.getRecipientInfos().getRecipients();
				KeyTransRecipientInformation recipientInfo = (KeyTransRecipientInformation)recip.iterator().next();
				JceKeyTransEnvelopedRecipient recipient = 
						(JceKeyTransEnvelopedRecipient) new JceKeyTransEnvelopedRecipient(decryptionKey).setProvider("BC");
				decryptedData = recipientInfo.getContent((Recipient)recipient);
			} 
		} catch (CMSException e) {
			LOG.error("Error decrypting data : {}", e.getMessage(), e);
		}
		return decryptedData;
	}

	/* Get a token connection to pkcs12 file (short process! See DSS documentation for explicit handling of token connection)
	 * https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/apidocs/eu/europa/esig/dss/token/SignatureTokenConnection.html
	 */
	private SignatureTokenConnection getPkcs12Token() throws IOException {

		try(InputStream keystore  = FileUtils.openInputStream(new FileDocument(ENCRYPTION_KEYSTORE).getFile());)
		{
			Pkcs12SignatureToken token = 
					new Pkcs12SignatureToken(keystore, 
							new PasswordProtection(KEYSTORE_PWD.toCharArray()));
			return token;
		}
	}

	// demonstrate encryption/decryption of inner ASiCE
	public static void main(String[] args) throws Exception 
	{
		CryptoBuilderApp cryptor = new CryptoBuilderApp();

		try (SignatureTokenConnection token = cryptor.getPkcs12Token()) 
		{
			X509Certificate recipientCert = token.getKeys().get(0).getCertificate().getCertificate();
			byte[] data = FileUtils.readFileToByteArray(new FileDocument(INNER_ASICE_EX).getFile());

			// create and write encrypted data to file
			File encryptedFile = new File(ENCRYPTED_INNER_ASICE);
			FileUtils.writeByteArrayToFile(encryptedFile , cryptor.encryptData(data, recipientCert));

			System.out.println("\nEncrypted inner ASiCE is written to: " + ENCRYPTED_INNER_ASICE);

			// Decryption of inner ASiCE received from bank (pain.002, camt.054..)
			System.out.println("\nNow let's demonstrate the decryption of the encrypted inner ASiCE...");

			// retrieve private key for decryption
			List<DSSPrivateKeyEntry> keys = token.getKeys();
			KSPrivateKeyEntry privateKeyEntry = (KSPrivateKeyEntry) keys.get(0);
			PrivateKey privateKey = privateKeyEntry.getPrivateKey();

			// create and write to file
			FileUtils.writeByteArrayToFile(new File(DECRYPTED_INNER_ASICE) , 
					cryptor.decryptData(FileUtils.readFileToByteArray(encryptedFile), privateKey));

			System.out.println("\nDecrypted file is written to: " + DECRYPTED_INNER_ASICE);
			

		}catch (Exception e) {
			new RuntimeException("Encryption failed. " + e.getMessage());
		}
	}
}
