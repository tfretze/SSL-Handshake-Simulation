//A3-Question 2
//**********************************
//Author: Tomas Fretze
//Course: SENG2250
//Program: This program simulates a server awaiting connection from a client
//         and exchanging encrypted messages and keys


import java.math.BigInteger;
import java.net.*;
import java.io.*;
import java.security.NoSuchAlgorithmException;

public class Server {
    private static CryptoEngine c = new CryptoEngine();

    public static void main(String[] args) throws IOException {

        if (args.length != 1) {
            System.err.println("Usage: java Server <port number>");
            System.exit(1);
        }

        int portNumber = Integer.parseInt(args[0]);

        try (
                ServerSocket serverSocket = new ServerSocket(Integer.parseInt(args[0]));
                Socket clientSocket = serverSocket.accept();
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        ) {

            //start messaging here
            System.out.print("Generating RSA keys...");
            BigInteger[] signatureKeys = c.createRSAKeys();
            System.out.println("done");
            System.out.println("Server RSA private key: " + signatureKeys[5]);
            System.out.println("Server RSA public key: " + signatureKeys[4]);

            System.out.println(in.readLine());
            out.println("Setup: 65537 " + signatureKeys[2]);     //send rsa public key and modulus
            System.out.println(in.readLine());

            out.println("Server_Hello: " + c.generateID() + ", " + c.generateID());

            System.out.print("Generating DH keys...");
            BigInteger dhPrivateKey = c.generateDHPrivateKey();
            BigInteger dhPublicKey = c.generateDHPublicKey(dhPrivateKey);
            System.out.println("done");
            System.out.println("Server diffie helman private key: " + dhPrivateKey);
            System.out.println("Server diffie helman public key: " + dhPublicKey);

            System.out.print("Receiving client DH key...");
            BigInteger clientDHKey = new BigInteger(in.readLine());
            System.out.println("done");

            System.out.print("Generating ephemeral DH key...");
            BigInteger serverSignature = c.hashSHA256(dhPublicKey);
            serverSignature = (c.fastExponentiation(serverSignature, signatureKeys[5], signatureKeys[2]));
            System.out.println("done");

            System.out.print("Transferring server ephemeral DH public key and public key...");
            out.println(serverSignature);
            out.println(dhPublicKey);
            System.out.println("done");

            System.out.print("Generating session key...");
            BigInteger sessionKey = c.generateDHSessionKey(clientDHKey, dhPrivateKey);
            System.out.println("done");
            System.out.println("Session key: " + sessionKey);

            System.out.print("Generating session key hash...");
            BigInteger localHash = c.hashSHA256(sessionKey);
            System.out.println("done");
            System.out.println("Session key hash: " + localHash);

            System.out.print("Receiving Message...");
            String clientTag = in.readLine();
            String clientMsg = in.readLine();
            System.out.println("done");
            System.out.println("Clients CBCMac: " + clientTag);
            System.out.println("Clients Encrypted Message: " + clientMsg);

            System.out.print("Decrypting Message and authenticating...");
            clientMsg = c.decryptCTR(localHash, clientMsg);
            String localTag = c.generateCBCMAC(localHash, clientMsg);
            c.compareMAC(clientTag, localTag);

            System.out.println("Message from client: " + clientMsg);

            System.out.print("Encrypting message and MAC TAG...");
            String cbcMacTag = c.generateCBCMAC(localHash, "A new broom sweeps clean but an old broom knows the corners.....");
            String encryptedMsg = c.encryptCTR(localHash, "A new broom sweeps clean but an old broom knows the corners.....");
            System.out.println("done");

            System.out.print("Transfering Message...");
            out.println(cbcMacTag);
            out.println(encryptedMsg);
            System.out.println("done");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}