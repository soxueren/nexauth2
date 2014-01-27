NexAuth2
========

NexAuth2 provides an encrypted pull communication channel between a HTTP server and clients' 
web browser without making use of SSL.

* Encryption is done with JavaScript. No SSL servers required.
* Every transmit data is strongly encrypted, making it practically impossible to eavesdrop the data.
* Cross-domain request _is_ supported.

Architecture
------------

Client (JavaScript) sends an authenticated request to the NexAuth endpoint 
and the server returns the response to the client. This is similar to the way that non-streaming
XMLHttpRequest does.

To accomplish a completely safe transmission, NexAuth2 makes use of both of the public-key 
encryption algorithm and shared-key one. First the client generate a private key and shared 
key. And then it encrypts the shared key with the private key and sends it to the server. 
The server decrypts the shared key with the public key, and uses it to encrypt further transmissions.

One of the most useful features of NexAuth is the user authentication. Upon establishing a session,
the client can provide a user name and password. This password is salted and hashed before being sent
to the server, and thus, the clear password is kept in safe even when the secure connection is
compromised. 

Requirements
------------

* Java Servlet Container (Tomcat, Glassfish, etc...)
* [Apache Commons Codec](http://commons.apache.org/proper/commons-codec/)
* [Apache Commons Collections](http://commons.apache.org/proper/commons-collections/)
* [Jackson JSON Processor](http://jackson.codehaus.org) - 2.1.1 or later recommended

Usage
-------------------

### Server

First, create a Java servlet class that inherits from `net.nexhawks.nexauth.NexAuthServlet`. After implementing
some member methods, add some command handlers that look like this:

	public NexAuthParams cmd_CommandNameHere(Command cmd) throws NexAuthException

The best example on how to implement this can be found at [NexAuthServet.java](src/net/nexhawks/nexauth/NexAuthServlet.java) `cmd_GetNexAuthVersion` member method.

### Client

See [demo.html](client-library/demo.html).


