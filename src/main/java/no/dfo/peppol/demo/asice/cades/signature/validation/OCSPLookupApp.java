package no.dfo.peppol.demo.asice.cades.signature.validation;

import java.io.File;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import no.dfo.peppol.demo.files.DemoFilesAndConfig;

/*
 * OCSP validation of a certificate. See DSS documentation chapter "19.3.1.2. OCSP"
 * https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/doc/dss-documentation.html
 * 
 * This demo is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY.
 */

// check online revocation status for provided certificates
public class OCSPLookupApp extends DemoFilesAndConfig{
	
	private boolean getOCSPStatus() {
		
		// the "3rd" party signing certificate
		CertificateToken signingToken = DSSUtils.loadCertificate(new File(SIGNING_CERTIFICATE));
		
		// the "3rd" party intermediate-/root certificate
		CertificateToken rootToken = DSSUtils.loadCertificate(new File(SIGNING_ROOT_CERTIFICATE));
		
		OCSPDataLoader ocspDataLoader = new OCSPDataLoader();
		
		// Retrieves OCSP response from online source.
		OnlineOCSPSource ocspSource = new OnlineOCSPSource(ocspDataLoader);
		
		// Extract OCSP for a certificate
		OCSPToken ocspToken = ocspSource.getRevocationToken(signingToken, rootToken);
		if(ocspToken == null) throw new RuntimeException("OCSP lookup failure.");
		
		if(ocspSource.getRevocationToken(signingToken, rootToken).getStatus().isGood()) {
			System.out.println("\nOCSP status is good");
			return true;
		} else {
			return false;
		}
	}
	
	public static void main(String[] args) {
		
		new OCSPLookupApp().getOCSPStatus();
	}
}
