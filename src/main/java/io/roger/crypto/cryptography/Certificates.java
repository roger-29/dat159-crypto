package io.roger.crypto.cryptography;

import java.io.FileInputStream;
import java.io.FileNotFoundException;

import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

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
