package DSTP;
import java.io.IOException;
import java.net.SocketException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.util.Arrays;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.net.NetworkInterface;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.security.Security;


public class DSTPSocketMulticast extends DSTPSocket{

    private MulticastSocket multicastSocket;
    private ReadConfig readConfig;
    NetworkInterface networkInterface;
     

    public DSTPSocketMulticast(int port) throws SocketException, IOException {
        super();
        this.multicastSocket = new MulticastSocket(port);
        this.readConfig = new ReadConfig("cryptoconfig.txt");
        this.networkInterface = NetworkInterface.getByName("eth4");
    }

    public DSTPSocketMulticast() throws SocketException, IOException {
        super();
        this.multicastSocket = new MulticastSocket(0);
        this.readConfig = new ReadConfig("cryptoconfig.txt");
        this.networkInterface = NetworkInterface.getByName("eth4");
    }
    
    public void joinGroup(InetSocketAddress addr, NetworkInterface networkInterface ) throws IOException{
        multicastSocket.joinGroup(addr, networkInterface);
    }

    public void close() {
        multicastSocket.close();
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

        byte[] dataPlusHash = join(unProtectedPacketData,hashedData);
        byte[] encryptedData = encrypt(dataPlusHash);

        //Final Packet
        DatagramPacket encryptedPacket = new DatagramPacket(encryptedData, encryptedData.length, packet.getAddress(), packet.getPort());
        multicastSocket.send(encryptedPacket);
    }

    public void receive(DatagramPacket packet) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
        
        
        multicastSocket.receive(packet);

        //Decrytpion of the Packet
        byte[] protectedData = Arrays.copyOfRange(packet.getData(), 0, packet.getLength());
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

}
