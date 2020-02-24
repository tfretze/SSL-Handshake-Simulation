//home comp DESKTOP-1DC3O95
//laptop DESKTOP-L2DMJ61
//A3-Question 2
//**********************************
//Author: Tomas Fretze
//Course: SENG2250
//Program: This program simulates a client connecting to a server
//         and exchanging encrypted messages and keys

import java.io.*;
import java.net.*;
import java.math.BigInteger;

public class Client {
    private static CryptoEngine c = new CryptoEngine();

    public static void main(String[] args) throws IOException {

        if (args.length != 2) {
            System.err.println("Usage: java Client <host name> <port number>");
            System.exit(1);
        }

        String hostName = args[0];
        int portNumber = Integer.parseInt(args[1]);

        try (
                Socket echoSocket = new Socket(hostName, portNumber);
                PrintWriter out = new PrintWriter(echoSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(echoSocket.getInputStream()));
        ) {

            //start messaging here
            out.println("Setup_Request: hello");
            String setup = in.readLine();
            System.out.println(setup);

            out.println("Client_Hello: " + c.generateID());
            System.out.println(in.readLine());
            String[] setupSplit = setup.split(" ");
            BigInteger rsaPublicKey = new BigInteger(setupSplit[1]);
            BigInteger rsaMod = new BigInteger(setupSplit[2]);

            System.out.print("Generating DH keys...");
            BigInteger dhPrivateKey = c.generateDHPrivateKey();
            BigInteger dhPublicKey = c.generateDHPublicKey(dhPrivateKey);
            System.out.println("done");
            System.out.println("Client diffie helman private key: " + dhPrivateKey);
            System.out.println("Client diffie helman public key: " + dhPublicKey);

            System.out.print("Transferring client DH public key...");
            out.println(dhPublicKey);
            System.out.println("done");

            System.out.print("Receiving server ephemeral DH key & Verifying server identity..");
            BigInteger serverSignature = c.fastExponentiation(new BigInteger(in.readLine()), rsaPublicKey, rsaMod);
            BigInteger serverDHKey = new BigInteger(in.readLine());
            c.compareSig(serverDHKey, serverSignature);

            System.out.print("Generating session key...");
            BigInteger sessionKey = c.generateDHSessionKey(serverDHKey, dhPrivateKey);
            System.out.println("done");
            System.out.println("Session key: " + sessionKey);

            System.out.print("Generating session key hash...");
            BigInteger localHash = c.hashSHA256(sessionKey);
            System.out.println("done");
            System.out.println("Session key hash: " + localHash);

            System.out.print("Encrypting message and MAC TAG...");
            String cbcMacTag = c.generateCBCMAC(localHash, "the wise understand by themselves fools follow reports of others");
            String encryptedMsg = c.encryptCTR(localHash, "the wise understand by themselves fools follow reports of others");
            System.out.println("done");

            System.out.print("Transfering Message...");
            out.println(cbcMacTag);
            out.println(encryptedMsg);
            System.out.println("done");

            System.out.print("Receiving Message...");
            String serverTag = in.readLine();
            String serverMsg = in.readLine();
            System.out.println("done");
            System.out.println("Servers CBCMac: " + serverTag);
            System.out.println("Servers Encrypted Message: " + serverMsg);


            System.out.print("Decrypting Message and authenticating...");
            serverMsg = c.decryptCTR(localHash, serverMsg);
            String localTag = c.generateCBCMAC(localHash, serverMsg);
            c.compareMAC(serverTag, localTag);

            System.out.println("Message from Server: " + serverMsg);

        } catch (UnknownHostException e) {
            System.err.println("Don't know about host " + hostName);
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Couldn't get I/O for the connection to " +  hostName);
            System.exit(1);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
