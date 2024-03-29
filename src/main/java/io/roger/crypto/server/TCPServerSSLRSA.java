package io.roger.crypto.server;

import java.io.*;
import java.net.*;
import java.security.*;

import javax.crypto.NoSuchPaddingException;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;

import io.roger.crypto.config.ServerConfig;
import io.roger.crypto.cryptography.Certificates;
import io.roger.crypto.cryptography.DigitalSignature;

public class TCPServerSSLRSA {

	private ServerSocket ssocket = null;
	private int port;

	public TCPServerSSLRSA(int port) {
		this.port = port;
		createSSLServerSocket();
	}

	private void createSSLServerSocket() {
		try {
			ServerSocketFactory ssf = SSLServerSocketFactory.getDefault();
			ssocket = ssf.createServerSocket(port);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public void socketlistener()
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, SignatureException {

		try {

			System.out.println("[LISTENING:]");
			Socket socket = ssocket.accept();

			BufferedReader inmsg = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			DataOutputStream outmsg = new DataOutputStream(socket.getOutputStream());

			String clientmsg = inmsg.readLine();
			System.out.println("Message recieved from the Client: " + clientmsg);

			boolean valid = checkMessageForValidity(clientmsg, getPublicKey());

			String feedback = " ";
			if (valid)
				feedback = "signature valid";
			else
				feedback = "signature invalid";

			String response = "HTTP/1.1 200 OK \r\n\r\n" + feedback;

			outmsg.write(response.getBytes());
			outmsg.flush();
			inmsg.close();
			outmsg.close();

			socket.close();

		} catch (IOException e) {

			e.printStackTrace();
		}
	}

	private boolean checkMessageForValidity(String messageandsignature, PublicKey publickey)
			throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException, SignatureException {

		if (messageandsignature.startsWith("GET /")) {
			messageandsignature = messageandsignature.replace("GET /", "");
			messageandsignature = messageandsignature.replace("HTTP/1.1", "");
		}

		String[] tokens = messageandsignature.trim().split("-");
		String message = tokens[0].replace("%20", " ");
		String signatureinhex = tokens[1];

		byte[] digitalSignature = DigitalSignature.getEncodedBinary(signatureinhex);

		return DigitalSignature.verify(message, digitalSignature, publickey, DigitalSignature.SIGNATURE_SHA256WithRSA);
	}

	private PublicKey getPublicKey() throws NoSuchAlgorithmException, NoSuchPaddingException {

		String certpath = "keys/tcpexample.cer"; // extract public key from the certificate file

		return Certificates.getPublicKey(certpath);
	}

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, SignatureException {
		// set the keystore dynamically using the system property

		System.setProperty("javax.net.ssl.keyStore", "keys/tcp_keystore");
		System.setProperty("javax.net.ssl.keyStorePassword", "abcdef");

		TCPServerSSLRSA tcpserver = new TCPServerSSLRSA(ServerConfig.PORT);

		// start the server and let it run forever
		while (true) {
			tcpserver.socketlistener();
		}
	}
}
