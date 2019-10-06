package io.roger.crypto.cryptography;

import java.io.*;
import java.security.cert.*;
import java.security.PublicKey;

/**
 * Given a certificate, extract the public key for operations such as
 * encryption/signature
 */
public class Certificates {

	/**
	 * Client side public key methods
	 *
	 * @param certfile
	 * @return
	 */
	public static PublicKey getPublicKey(String certfile) {
		X509Certificate certificate = null;

		try {
			FileInputStream fin = new FileInputStream(certfile);
			CertificateFactory f = CertificateFactory.getInstance("X.509");

			certificate = (X509Certificate) f.generateCertificate(fin);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		}

		return certificate.getPublicKey();
	}
}
