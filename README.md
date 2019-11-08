# Cryptography

> DAT159

By Sondre Gjellestad and Arne Molland

## Task 1

After setting up the certificate, the connection works.

![Console](images/task1.png)
![Code](images/task1code.png)
![Wireshark](images/task1wireshark.png)

## Task 3

Here is the result in WireShark.

![Console](images/task3.png)
![Wireshark](images/task3wireshark.png)

## Task 4 | Tamper with the Message (Integrity)

After setting up the proxy certificates, we've set a breakpoint like this:

![ZAP](images/task4breakpoint.png)

After tampering with the message this is the response from the server.

![Tampered](images/task4tampered.png)

## Question

Can we impersonate HttpsClientProxySSLRSA in this setup? If so, we would need it's private key in order to sign messages correctly.
