# SSL-Handshake-Simulation
Program simulates a client and server performing an SSL handshake. Performs Ephemeral Diffie-Helman key exchange to create session keys, AES encryption in CTR and CBC-MAC mode, finally the sending of encrypted messages across a network.

How to compile and run: 

This program was created and compiled in JAVA subversion 1.8

To compile the program:
javac Server.java
javac Client.java

Server must be run before client, To run the program:
java Server <port number>
java Client <server computer name> <server port number>

