# Cryptography

> DAT159

## Certificate and Key Management

- keytool: Java command-line tool for generating and managing keys and certificates
- keystores: where the private keys and certificates used as credentials are stored (TLS server extracts info from the keystores and forward to the client)
- trustores: stores the public certificates that your application will use to determine trust. It is used to validate the credentials supplied from a keystore

### Step 1

- From a shell (command line). Create a key pair (public and private key)
- Change directory to the location where you want to store the keys (cd /Users/../mykeys)

```bash
$ keytool -genkeypair -alias tcpexample -keyalg RSA -validity 365 -keystore tcp_keystore

Enter keystore password:
Re-enter new password:
What is your first and last name?
[Unknown]: localhost
What is the name of your organizational unit?
[Unknown]: Tosin Oyetoyan
What is the name of your organization?
[Unknown]: Security Corp
What is the name of your City or Locality?
[Unknown]: Bergen
What is the name of your State or Province?
[Unknown]: HO
What is the two-letter country code for this unit?
[Unknown]: NO
Is CN=localhost, OU=Tosin Oyetoyan, O=Security Corp, L=Bergen, ST=HO, C=NO correct?
[no]: yes

Generating 2,048 bit RSA key pair and self-signed certificate (SHA256withRSA) with a validity of 7 days
for: CN=localhost, OU=Tosin Oyetoyan, O=Security Corp, L=Bergen, ST=HO, C=NO
```

The keys and certificate are stored in tcp_keystore file.

### Step 2

List the content

```bash
$ keytool -list -v -keystore tcp_keystore

Enter keystore password:
Keystore type: PKCS12
Keystore provider: SUN

Your keystore contains 1 entry

Alias name: tcpexample
Creation date: Aug 18, 2019
Entry type: PrivateKeyEntry
Certificate chain length: 1
Certificate[1]:
Owner: CN=localhost, OU=Tosin Oyetoyan, O=Security Corp, L=Bergen, ST=HO, C=NO
Issuer: CN=localhost, OU=Tosin Oyetoyan, O=Security Corp, L=Bergen, ST=HO, C=NO
Serial number: 72facba7
Valid from: Sun Aug 18 08:51:36 CEST 2019 until: Sun Aug 25 08:51:36 CEST 2019
Certificate fingerprints:
SHA1: 93:BF:19:DC:3D:61:DE:39:69:67:C6:6F:B2:C9:FF:FA:75:F2:C7:D6
SHA256: 8C:88:85:00:DD:43:34:7B:96:FD:39:94:81:34:5C:99:4B:E5:1E:F0:95:A0:0B:C5:85:0C:A0:80:6B:CC:ED:FD
Signature algorithm name: SHA256withRSA
Subject Public Key Algorithm: 2048-bit RSA key
Version: 3

Extensions:

#1: ObjectId: 2.5.29.14 Criticality=false
SubjectKeyIdentifier [
KeyIdentifier [
0000: F6 A4 24 1A 40 80 F1 76 62 F9 7A B6 59 B0 F3 14 ..$.@..vb.z.Y...
0010: FB 6F 6C D0 .ol.
]
]
```

### Step 3

Extract the certificate from the keystore tcp_keystore (step 3) and add it to the truststore (step 4)

```bash
$ keytool -exportcert -alias tcpexample -keystore tcp_keystore -rfc -file tcpexample.cer

Enter keystore password:
Certificate stored in file <tcpexample.cer>
```

```bash
$ cat tcpexample.cer

-----BEGIN CERTIFICATE-----
MIIDfzCCAmegAwIBAgIEcvrLpzANBgkqhkiG9w0BAQsFADBwMQswCQYDVQQGEwJO
TzELMAkGA1UECBMCSE8xDzANBgNVBAcTBkJlcmdlbjEWMBQGA1UEChMNU2VjdXJp
dHkgQ29ycDEXMBUGA1UECxMOVG9zaW4gT3lldG95YW4xEjAQBgNVBAMTCWxvY2Fs
aG9zdDAeFw0xOTA4MTgwNjUxMzZaFw0xOTA4MjUwNjUxMzZaMHAxCzAJBgNVBAYT
Ak5PMQswCQYDVQQIEwJITzEPMA0GA1UEBxMGQmVyZ2VuMRYwFAYDVQQKEw1TZWN1
cml0eSBDb3JwMRcwFQYDVQQLEw5Ub3NpbiBPeWV0b3lhbjESMBAGA1UEAxMJbG9j
YWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArZOgv+aJa9Zm
PqIO9cvv+rkKaa9Kszw0CJpFK20rmlIoLX8zzLLSnuURIoMTrC6ZTRK17iAmMSmZ
cvcUMSLDrIGalNer4/MYsjP7YypTgHsdmds7cLcHx1Na5s9JLEGtvcjRoZbe4sEk
RYLoRuy+TV9hRmM8+caP+bxSiUPg89PTbnJ27VqDg+egjSlikP8Q02Q/l0lfQs4S
GbsNPhdY6h00UnEmfls9GY5ZP9yiA8cm4cLBp43rkVbxf1l0Hev6ete7if9glwj5
o/Y4tOv0uzLLirZcFyKrYiBBf2CauaZ9J72YnoqeOXebkaCPHEKDTOVbmKBUFCMm
6Duq49lSjwIDAQABoyEwHzAdBgNVHQ4EFgQU9qQkGkCA8XZi+Xq2WbDzFPtvbNAw
DQYJKoZIhvcNAQELBQADggEBAABephDNur4JC8mRi34Q3QOG44cIsUvwf45B1mC+
MNE2xy4D94FWmnhVHpa6A+E+Z1xInYh9QvXPf6MiAfheJsIWWNvBucm5NxzWcYel
4arK4JcEPlptiFV5RURUzWr2WWTAfwNsTVOrZVvxDAp5FcJubwgifNInwj+uTRzy
FuaeIQCGFG/xCi3hdZhUu8gx1MwlSKJP4HXtBlH286zFRX8r0kS1qtXy4SO6/ARs
mY6uT8j/nwSfQv/08S896b5o0akWh4stcvvA8lsm2q4KPr8njmrkQMTGM/cxhcNW
nPPTt8UgNRJ6FyrPsX6PIXD7BI7rWYKrTDiVZwYbJjuKpy4=
-----END CERTIFICATE-----
```

### Step 4

Import the public cert into the truststore.

```bash
$ keytool -import -alias tcpexamplecert -file tcpexample.cer -keystore tcp_truststore

Enter keystore password:
Re-enter new password:
Owner: CN=localhost, OU=Tosin Oyetoyan, O=Security Corp, L=Bergen, ST=HO, C=NO
Issuer: CN=localhost, OU=Tosin Oyetoyan, O=Security Corp, L=Bergen, ST=HO, C=NO
Serial number: 72facba7
Valid from: Sun Aug 18 08:51:36 CEST 2019 until: Sun Aug 25 08:51:36 CEST 2019
Certificate fingerprints:
SHA1: 93:BF:19:DC:3D:61:DE:39:69:67:C6:6F:B2:C9:FF:FA:75:F2:C7:D6
SHA256: 8C:88:85:00:DD:43:34:7B:96:FD:39:94:81:34:5C:99:4B:E5:1E:F0:95:A0:0B:C5:85:0C:A0:80:6B:CC:ED:FD
Signature algorithm name: SHA256withRSA
Subject Public Key Algorithm: 2048-bit RSA key
Version: 3

Extensions:

#1: ObjectId: 2.5.29.14 Criticality=false
SubjectKeyIdentifier [
KeyIdentifier [
0000: F6 A4 24 1A 40 80 F1 76 62 F9 7A B6 59 B0 F3 14 ..$.@..vb.z.Y...
0010: FB 6F 6C D0 .ol.
]
]

Trust this certificate? [no]: yes
Certificate was added to keystore
```

The tcp_truststore contains the certificate with the public key that matches the private key stored in the tcp_keystore.
Next step is to configure the TCPServer to use the tcp_keystore and the TCPClient to use the tcp_truststore
What happens next is that during client/server handshake, the TCPServer sends the certificate in the tcp_keystore to the client
the client then verifies it with the public key in the tcp_truststore.

## Extracting certificates from web servers

In some cases, you may need to connect your applications, devices, etc programmatically to a web server without using a web browser (client).

### Step 1

You can use the openssl tool to extract the certificate from the site if the certificate file is not available.

`$ > openssl s_client -connect localhost:8443 < /dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > localhost-rsa-pubk.cer`

### Step 2

Import the public cert into the truststore.

```bash
$ keytool -import -alias tomcatcert -file localhost-rsa-pubk.cer -keystore tomcat_truststore

Enter keystore password: <<enter a new password if you want>>
Re-enter new password:
Owner: CN=localhost, OU=Tosin Oyetoyan, O=Security Corp, L=Bergen, ST=HO, C=NO
Issuer: CN=localhost, OU=Tosin Oyetoyan, O=Security Corp, L=Bergen, ST=HO, C=NO
Serial number: 7b471bad
Valid from: Wed Aug 21 13:16:36 CEST 2019 until: Tue Nov 19 12:16:36 CET 2019
Certificate fingerprints:
SHA1: BE:D4:37:01:DC:29:2E:86:8F:92:92:93:4E:C5:99:6F:C0:01:A5:06
SHA256: 92:00:E3:9E:C4:71:95:53:91:B3:DF:25:EC:AB:9C:AB:34:C9:7A:13:F2:80:99:49:91:69:0C:95:49:99:3D:FB
Signature algorithm name: SHA256withRSA
Subject Public Key Algorithm: 2048-bit RSA key
Version: 3

Extensions:

#1: ObjectId: 2.5.29.14 Criticality=false
SubjectKeyIdentifier [
KeyIdentifier [
0000: A9 8D F6 5C B0 84 7C FD 82 CD 9A 8C E0 38 84 EB ...\.........8..
0010: 79 6F 56 B0 yoV.
]
]

Trust this certificate? [no]: yes
Certificate was added to keystore
```

### Step 3

List the content (if you want)

```bash
$ keytool -list -v -keystore tomcat_truststore

Keystore type: PKCS12
Keystore provider: SUN

Your keystore contains 1 entry

Alias name: tomcatcert
Creation date: Aug 21, 2019
Entry type: trustedCertEntry

Owner: CN=localhost, OU=Tosin Oyetoyan, O=Security Corp, L=Bergen, ST=HO, C=NO
Issuer: CN=localhost, OU=Tosin Oyetoyan, O=Security Corp, L=Bergen, ST=HO, C=NO
Serial number: 7b471bad
Valid from: Wed Aug 21 13:16:36 CEST 2019 until: Tue Nov 19 12:16:36 CET 2019
Certificate fingerprints:
SHA1: BE:D4:37:01:DC:29:2E:86:8F:92:92:93:4E:C5:99:6F:C0:01:A5:06
SHA256: 92:00:E3:9E:C4:71:95:53:91:B3:DF:25:EC:AB:9C:AB:34:C9:7A:13:F2:80:99:49:91:69:0C:95:49:99:3D:FB
Signature algorithm name: SHA256withRSA
Subject Public Key Algorithm: 2048-bit RSA key
Version: 3

Extensions:

#1: ObjectId: 2.5.29.14 Criticality=false
SubjectKeyIdentifier [
KeyIdentifier [
0000: A9 8D F6 5C B0 84 7C FD 82 CD 9A 8C E0 38 84 EB ...\.........8..
0010: 79 6F 56 B0 yoV.
]
]
```
