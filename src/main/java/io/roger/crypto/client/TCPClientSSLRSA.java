package io.roger.crypto.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;

import javax.crypto.NoSuchPaddingException;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

import io.roger.crypto.config.ServerConfig;
import io.roger.crypto.cryptography.DigitalSignature;
import io.roger.crypto.cryptography.KeyStores;

public class TCPClientSSLRSA {

	private String server;
	private int port;

	public TCPClientSSLRSA(String server, int port) {
		this.server = server;
		this.port = port;
	}

	public void clientProcess(String msg) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException,
			NoSuchPaddingException, UnrecoverableKeyException, KeyStoreException {

		try {

			SocketFactory ssf = SSLSocketFactory.getDefault();
			Socket csocket = ssf.createSocket(server, port);

			PrintWriter outmsg = new PrintWriter(csocket.getOutputStream(), true);
			BufferedReader inmsg = new BufferedReader(new InputStreamReader(csocket.getInputStream()));

			System.out.println("Message to TCPServer: " + msg);

			// Sign the message and append the signature to the message to the server
			String algorithm = DigitalSignature.SIGNATURE_SHA256WithRSA;
			PrivateKey privateKey = getPrivateKey();

			byte[] signature = DigitalSignature.sign(msg, privateKey, algorithm);
			String signatureinhex = DigitalSignature.getHexValue(signature);

			msg = msg + "-" + signatureinhex; // format message as: Message-Signature

			// Send msg + sign to the server
			outmsg.println(msg);

			// Read the response from the server
			StringBuffer sb = new StringBuffer();
			String line = "";
			while ((line = inmsg.readLine()) != null) {
				sb.append(line + "\n");
			}

			System.out.println("Response from Server: " + sb);

			outmsg.close();
			inmsg.close();
			csocket.close();

		} catch (IOException ex) {
			ex.printStackTrace();
		}
	}

	private PrivateKey getPrivateKey()
			throws NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableKeyException, KeyStoreException {

		String keystore = "keys/tcp_keystore";

		String alias = "tcpexample";

		String password = "abcdef";

		return KeyStores.getPrivateKeyFromKeyStore(keystore, alias, password);
	}

	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException,
			NoSuchPaddingException, UnrecoverableKeyException, KeyStoreException {
		// Set the truststore dynamically using the system property

		System.setProperty("javax.net.ssl.trustStore", "keys/tcp_truststore");
		System.setProperty("javax.net.ssl.trustStorePassword", "abcdef");

		String message = "Message from TCP SSLClient";
		TCPClientSSLRSA c = new TCPClientSSLRSA(ServerConfig.SERVER, ServerConfig.PORT);
		c.clientProcess(message);
	}
}
