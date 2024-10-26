package DSTP;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.MessageDigest;

import javax.crypto.spec.GCMParameterSpec;  
import java.security.SecureRandom;  

public class DSTPSocket {

   private DatagramSocket socket;
   private ReadConfig readConfig;


    public DSTPSocket() throws SocketException, IOException {
        this.socket = new DatagramSocket(0);
        this.readConfig = new ReadConfig("cryptoconfig.txt");
    }

    public DSTPSocket(int port) throws SocketException, IOException {
        this.socket = new DatagramSocket(port);
        this.readConfig = new ReadConfig("cryptoconfig.txt");
    }

    public DSTPSocket(SocketAddress bindaddr) throws SocketException, IOException {
        this.socket = new DatagramSocket(bindaddr);
        this.readConfig = new ReadConfig("cryptoconfig.txt");
    }

    public void send (DatagramPacket packet) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException{
        byte[] unProtectedPacketData = packet.getData();
        //Integrity
        byte[] hashedData;
        if (readConfig.getIntegrity().trim().equals("HMAC")){
            hashedData = hashHMAC(unProtectedPacketData);
        } else {
            hashedData = hashH(unProtectedPacketData);
        } 

        //Combine data and Hash
        byte[] dataPlusHash = join(unProtectedPacketData,hashedData);
        byte[] encryptedData = encrypt(dataPlusHash);
    

        //Final Packet
        DatagramPacket encryptedPacket = new DatagramPacket(encryptedData, encryptedData.length, packet.getAddress(), packet.getPort());
        socket.send(encryptedPacket);
    }

    

    public void receive(DatagramPacket packet) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
        socket.receive(packet);
        //Decrytpion of the Packet
        byte[] protectedData = packet.getData();
        byte[] dataDecrypted = decrypt(protectedData);

        //Split the data from the hashed data
        byte[] data         = Arrays.copyOfRange(dataDecrypted, 0, dataDecrypted.length - getHashsize());
        byte[] hashedData   = Arrays.copyOfRange(dataDecrypted, dataDecrypted.length - getHashsize() , dataDecrypted.length); 
    
        //Integrity verification
        byte[] hashResult;
        if (readConfig.getIntegrity().trim().equals("HMAC")) {
            hashResult = hashHMAC(data);
        } else { 
            hashResult = hashH(data);
        }

        //Checking Integrity
        if(!Arrays.equals(hashedData, hashResult)){
            throw new SecurityException("Packet is not the same !!");
        }
        
        System.arraycopy(data, 0, packet.getData(), 0, data.length);
        packet.setLength(data.length);
    }

    public void close() {
        socket.close();
    }

    public int getLocalPort(){
        return socket.getLocalPort();
    }

    public void setSoTimeout(int time) throws SocketException{
        socket.setSoTimeout(time);
    }
    
    @SuppressWarnings("unlikely-arg-type")
    protected byte[] encrypt(byte[] dataToEncrypt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {

        //Get cipherSuit and algorithm from the CipherSuit
        Cipher cipher       = Cipher.getInstance(readConfig.getCipherSuit().trim());
        String algorithm    = readConfig.getCipherSuit().split("/")[0];
        String mode         = "NULL";
        byte[] encryptedData;

        if(readConfig.getCipherSuit().contains("/")){
            mode = readConfig.getCipherSuit().split("/")[1];
        }

        //Key related to the algorithm
        SecretKey key = new SecretKeySpec(readConfig.getSymmetricKey(), algorithm);

        if (readConfig.getIV().equals("NULL") && !"GCM".equals(mode)){
            cipher.init(Cipher.ENCRYPT_MODE, key);
            encryptedData = cipher.doFinal(dataToEncrypt);

        } else if(mode.equals("GCM")){
            //IV Generation
            SecureRandom secureRandom = new SecureRandom();
            byte[] iv = new byte[12];
            secureRandom.nextBytes(iv);

            //GCM Inicialization
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
            byte[] finalData = cipher.doFinal(dataToEncrypt);
            //Packet with the IV and encrypted data
            encryptedData = join(iv, finalData);
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(readConfig.getIV()));
                encryptedData = cipher.doFinal(dataToEncrypt);
            }
        return encryptedData;  
    }

    @SuppressWarnings("unlikely-arg-type")
    protected byte[] decrypt(byte[] dataToDecrypt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
        //Get cipherSuit and algorithm from the CipherSuit
        Cipher cipher       = Cipher.getInstance(readConfig.getCipherSuit().trim());
        String algorithm    = readConfig.getCipherSuit().split("/")[0];
        String mode         = "NULL";
        byte[] decryptedData;

        if(readConfig.getCipherSuit().contains("/")){
            mode = readConfig.getCipherSuit().split("/")[1];
        }

        //Key related to the algorithm
        SecretKey key = new SecretKeySpec(readConfig.getSymmetricKey(), algorithm);
        if (readConfig.getIV().equals("NULL") && !"GCM".equals(mode)){
            cipher.init(Cipher.DECRYPT_MODE, key);
            decryptedData = cipher.doFinal(dataToDecrypt);

        } else if(mode.equals("GCM")){
            byte[] iv = Arrays.copyOfRange(dataToDecrypt, 0, 12);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);


            //Packet without the IV
            //System.out.println(Utils.toString(iv));
            byte[] noIvData = Arrays.copyOfRange(dataToDecrypt, 12, dataToDecrypt.length );


            decryptedData   = cipher.doFinal(noIvData);

            } else {
                cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(readConfig.getIV()));
                decryptedData = cipher.doFinal(dataToDecrypt);
            }

        return decryptedData; 
    }
    
    //Normal Hash
    protected byte[] hashH(byte[] dataPacket) throws NoSuchAlgorithmException {
        MessageDigest hash = MessageDigest.getInstance(readConfig.getHashAlgorithm().trim());
        hash.update(dataPacket);
        return hash.digest();
    }

    //Keyed Hash
    protected byte[] hashHMAC(byte[] dataPacket) throws NoSuchAlgorithmException, InvalidKeyException {
        
        Mac mac = Mac.getInstance(readConfig.getMACAlgorithm().trim());
        SecretKey macKey = new SecretKeySpec(readConfig.getMACKey(), readConfig.getMACAlgorithm().trim());
        mac.init(macKey);
        return mac.doFinal(dataPacket);
    }

    //Function to join the message + the hashed message(either just Hash or Keyed Hash)
    //The final byte[] will be byte1+byte2
    protected byte[] join(byte[] byte1, byte[] byte2) throws IOException {
        byte[] join = new byte[byte1.length + byte2.length];
        System.arraycopy(byte1, 0, join, 0, byte1.length);
        System.arraycopy(byte2, 0, join, byte1.length, byte2.length);
        return join;
    }

    //Helper function to determine the lenght of the hashed message
    protected int getHashsize() throws NoSuchAlgorithmException {
        if (readConfig.getIntegrity().trim().equals("HMAC")) {
            Mac mac = Mac.getInstance(readConfig.getMACAlgorithm()); 
            return mac.getMacLength();
        } else { 
            MessageDigest hash = MessageDigest.getInstance(readConfig.getHashAlgorithm());  
            return hash.getDigestLength();
        }
    }
    

}
