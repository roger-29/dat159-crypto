package io.roger.crypto.cryptography;

import java.io.UnsupportedEncodingException;
import java.security.*;
import javax.xml.bind.DatatypeConverter;

public class DigitalSignature {

	// public static final String SIGNATURE_SHA256WithDSA = "SHA256WithDSA";
	public static final String SIGNATURE_SHA256WithRSA = "SHA256WithRSA";

	public static byte[] sign(String message, PrivateKey privateKey, String algorithm)
			throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException {

		Signature signature = Signature.getInstance(algorithm);

		signature.initSign(privateKey);
		signature.update(getEncodedBinary(message));

		return signature.sign();
	}

	public static boolean verify(String message, byte[] digitalSignature, PublicKey publickey, String algorithm)
			throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException {

		Signature signature = Signature.getInstance(algorithm);

		signature.initVerify(publickey);
		signature.update(message.getBytes());

		return signature.verify(digitalSignature);
	}

	public static String getHexValue(byte[] signature) {
		return DatatypeConverter.printHexBinary(signature);
	}

	public static byte[] getEncodedBinary(String signatureinhex) {
		return DatatypeConverter.parseHexBinary(signatureinhex);
	}
}
