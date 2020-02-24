//A3-Question 2
//**********************************
//Author: Tomas Fretze
//Course: SENG2250
//Program: This class provides cryptographic functions
//         to the client and server


import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class CryptoEngine {
    private static BigInteger p = new BigInteger("178011905478542266528237562450159990145232156369120674273274450314442865788737020770612695252123463079567156784778466449970650770920727857050009668388144034129745221171818506047231150039301079959358067395348717066319802262019714966524135060945913707594956514672855690606794135837542707371727429551343320695239");
    private static BigInteger g = new BigInteger ("174068207532402095185811980123523436538604490794561350978495831040599953488455823147851597408940950725307797094915759492368300574252438761037084473467180148876118103083043754985190983472601550494691329488083395492313850000361646482644608492304078721818959999056496097769368017749273708962006689187956744210730");

    public CryptoEngine() {}


    //Pre-conditions: session key has been created and is a 256bit value
    //Post-conditions: CBC-Mac tag has been generated and is output as a Hexadecimal string
    public String generateCBCMAC(BigInteger key, String msg) throws Exception{
        Cipher cipherCBC = Cipher.getInstance("AES/ECB/NoPadding");
        int msgSize = msg.length()/16;
        String tagStr = new String();
        byte[] tag = msgBytes(0, msg);
        for(int i = 0; i<msgSize; i++){
            cipherCBC.init(Cipher.ENCRYPT_MODE, formatKey(key));
            tag = cipherCBC.doFinal(tag);
            if(i < (msgSize-1)) {
                for (int j = 0; j < 16; j++) {
                    tag[j] = (byte) (tag[j] ^ msgBytes(i+1, msg)[j]);
                }
            }
        }
        for(int i = 0; i < 16; i++){
            tagStr += formatOutput(i, tag);
        }
        return tagStr;
    }

    //Pre-conditions: session key has been created and is a 256bit value
    //Post-conditions: message has been encrypted and is output as a Hexadecimal string
    public String encryptCTR(BigInteger key, String msg) throws Exception{
        Cipher cipherCTR = Cipher.getInstance("AES/ECB/NoPadding");
        int msgSize = msg.length()/16;
        byte[][] encryptedMsg = new byte[msgSize][16];
        String encryptedStr = new String();
        //perform ctr encryption
        for(int i = 0; i < msgSize; i++){
            cipherCTR.init(Cipher.ENCRYPT_MODE, formatKey(key));
            encryptedMsg[i] = cipherCTR.doFinal(generateCountBytes(i));
            for(int j = 0; j<16; j++){
                encryptedMsg[i][j] = (byte) (encryptedMsg[i][j] ^ msgBytes(i, msg)[j]);
                encryptedStr += formatOutput(j, encryptedMsg[i]);
            }
        }
        return encryptedStr;
    }

    //Pre-conditions: session key has been created and is a 256bit value, message is encrypted using a 256bit key in CTR mode
    //Post-conditions: message has been decrypted and is output as a string
    public String decryptCTR(BigInteger key, String msg) throws Exception {
        Cipher cipherCTR = Cipher.getInstance("AES/ECB/NoPadding");
        int msgSize = msg.length()/32;

        //format message in 4 x 16 byte arrays
        byte[][] msgBytes = new byte[msgSize][16];
        for(int i = 0; i < msgSize; i++){
            for(int j = 0; j < 16; j++) {
                int firstDigit = Character.digit(msg.charAt((j*2)+(i*32)),16);
                int secondDigit = Character.digit(msg.charAt((j*2)+(i*32)+1), 16);
                msgBytes[i][j] = (byte) ((firstDigit << 4) + secondDigit);
            }
        }
        byte[][] decryptedMsg = new byte[msg.length()/32][16];
        String decryptedStr = new String();

        //decrypt the message in ctr mode
        for(int i = 0; i<msg.length()/32; i++){
            cipherCTR.init(Cipher.ENCRYPT_MODE, formatKey(key));
            decryptedMsg[i] = cipherCTR.doFinal(generateCountBytes(i));
            for(int j = 0; j<16; j++){
                decryptedMsg[i][j] = (byte) (decryptedMsg[i][j] ^ msgBytes[i][j]);
            }
            decryptedStr += new String(decryptedMsg[i]);
        }
        return decryptedStr;
    }

    //Pre-conditions: NA
    //Post-conditions: returns a byte counter that can be encrypted by the AES cipher
    private byte[] generateCountBytes(int count){
        return new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) count};
    }

    //Pre-conditions: encrypted byte array has been created
    //Post-conditions: returns hexadecimal string value of the byte
    private String formatOutput(int count, byte[] b){
        char[] hexDigits = new char[2];
        hexDigits[0] = Character.forDigit((b[count] >> 4) & 0xF, 16);
        hexDigits[1] = Character.forDigit((b[count] & 0xF), 16);
        return new String(hexDigits);
    }

    //Pre-conditions: BigInteger value of the key
    //Post-conditions: returns a value of the key that can be read into the AES cipher
    private SecretKey formatKey(BigInteger key){
        byte[] keyBytes = key.toByteArray();
        if(keyBytes.length > 32) {
            keyBytes = Arrays.copyOfRange(keyBytes, 1, keyBytes.length);
        }
        return new SecretKeySpec(keyBytes, "AES");
    }

    //Pre-conditions: takes a message in string format
    //Post-conditions: returns message in byte format
    private byte[] msgBytes(int count, String msg){
        return msg.substring(count*16, (count+1) * 16).getBytes();
    }

    //Pre-conditions: NA
    //Post-conditions: returns a BigInteger array of keys that will be used for RSA signature generation
    public BigInteger[] createRSAKeys() {
        BigInteger[] keys = new BigInteger[6];
        Boolean keysCreated = false;
        while (!keysCreated) {
            SecureRandom rnd1 = new SecureRandom();
            keys[0] = BigInteger.probablePrime(2048, rnd1);                                   //p
            SecureRandom rnd2 = new SecureRandom();
            keys[1] = BigInteger.probablePrime(2048, rnd2);                                   //q
            keys[2] = keys[0].multiply(keys[1]);                                                       //n
            keys[3] = (keys[0].subtract(BigInteger.ONE)).multiply(keys[1].subtract(BigInteger.ONE));   //phi(n) = (p-1)(q-1)
            keys[4] = BigInteger.valueOf(65537);                                                       //public key e
            if (keys[4].gcd(keys[3]).equals(BigInteger.ONE)) {
                if (keys[4].modInverse(keys[3]).signum() == 1) {
                    keys[5] = keys[4].modInverse(keys[3]);                                             //private key d
                    keysCreated = true;
                }
            }

        }
        return keys;
    }

    //compares 2 hash values and outputs the result of the comparison
    public void compareSig(BigInteger h1, BigInteger h2) throws Exception{
        h1 = hashSHA256(h1);
        if(h1.compareTo(h2) == 0){
            System.out.println("Success!");
        }else{
            System.out.println("Failure");
        }
    }

    //compares 2 CBCMAC tags and outputs the result of the comparison
    public synchronized void compareMAC(String m1, String m2){
        if(m1.compareTo(m2) == 0){
            System.out.println("Success!");
        }else{
            System.out.println("Failure");
        }
    }

    //generates random ID's for the session
    public int generateID(){
        return new Random().nextInt(1000) + 10;
    }

    //Pre-conditions: A big integer session key has been created
    //Post-conditions: returns a hash value of the session key in BigInteger format
    public BigInteger hashSHA256(BigInteger input) throws Exception {
        MessageDigest message = MessageDigest.getInstance("SHA-256");
        return new BigInteger(1, message.digest(input.toByteArray()));
    }

    //calls the fast exponentiation function
    public BigInteger generateDHPublicKey(BigInteger key){
        return fastExponentiation(g, key, p);
    }

    //calls the fast exponentiation function
    public BigInteger generateDHSessionKey(BigInteger senderPubKey, BigInteger publicKey){
        return fastExponentiation(senderPubKey, publicKey, p);
    }

    //generates a Diffie-helman private key that is 256 bits long as
    public BigInteger generateDHPrivateKey(){
        SecureRandom key = new SecureRandom();
        return BigInteger.probablePrime(256, key);
    }

    //Pre-conditions: NA
    //Post-conditions: returns the result of fastExponentiation as a BigInteger value
    public BigInteger fastExponentiation(BigInteger b, BigInteger e, BigInteger m) {
        if(m.equals(BigInteger.ONE)) {
            return BigInteger.ZERO;
        }
        BigInteger result = BigInteger.ONE;
        while(e.compareTo(BigInteger.ZERO) == 1)
        {
            if(e.mod(BigInteger.TWO).compareTo(BigInteger.ONE) == 0) {
                result = (result.multiply(b)).mod(m);
            }
            e = e.divide(BigInteger.TWO);
            b = b.multiply(b).mod(m);
        }
        return result;
    }
}