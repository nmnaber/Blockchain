/*--------------------------------------------------------

1. Name / Date:

Nick Naber 10/23/2018

2. Java version used, if not the official version for the class:

Developed in IntelliJ on MacOS 10.13.3

Java build 1.8.0_152

3. Precise command-line compilation examples / instructions:

javac Blockchain.java

4. Precise examples / instructions to run this program:

Applescript from Unix example was used-

tell application "iTerm"

	create window with profile "Blockchain" command "java Blockchain 0"
	create window with profile "Blockchain" command "java Blockchain 1"
	create window with profile "Blockchain" command "java Blockchain 2"

end tell

Commands only work from process 0
'c' for verifying process of each block
'l' for block number, timestamp, and data line

5. List of files needed for running the program.

Blockchain.java
BlockInput0.txt, BlockInput1.txt, BlockInput2.txt

5. Notes:

XMLparse class was created with the help of this tutorial "https://www.tutorialspoint.com/java_xml/java_dom_parse_document.htm"

----------------------------------------------------------*/



import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import java.io.*;
import java.io.File;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.ThreadLocalRandom;
import java.io.OutputStream;


import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.NoSuchAlgorithmException;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;
import javax.swing.text.Document;
import javax.xml.bind.*;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.soap.Node;

class Work {

    public String doWork (String hasheddata, String seed) { //taken from example and modified - NN

        String randString = "";
        String concatString = hasheddata+seed;
        String stringOut = "";
        byte[] seedByte = new byte[256];

        int workNumber = 0;

        try {

            for(int i=1; i<30; i++){

                new Random().nextBytes(seedByte);
                String seedString = Base64.getEncoder().encodeToString(seedByte);

                randString = seedString; //get 256 bit seed string -NN

                concatString = hasheddata + randString; //concat the hasheddata and first seed guess -NN
                MessageDigest MD = MessageDigest.getInstance("SHA-256");
                byte[] bytesHash = MD.digest(concatString.getBytes("UTF-8")); //hashvalue of concated string - NN
                stringOut = DatatypeConverter.printHexBinary(bytesHash); // Turn into a string of hex values
                //System.out.println("Hash is: " + stringOut);
                workNumber = Integer.parseInt(stringOut.substring(0,4),16); // Between 0000 (0) and FFFF (65535)
                //System.out.println("First 16 bits " + stringOut.substring(0,4) +": " + workNumber + "\n");
                if (workNumber < 20000){  // lower number = more work.
                    //System.out.println("Puzzle solved!");
                    //System.out.println("The seed was: " + randString);
                    break;
                }
                //TODO work abandon
                try{Thread.sleep(1000);}catch(Exception e){}
            }
        }catch(Exception ex) {ex.printStackTrace();}

        String seedString = Base64.getEncoder().encodeToString(seedByte);
        return seedString;
    }
}

class XMLparse {

    static boolean updated = false;

    //fixes XML ledger becuase was getting incorrect output / file needs one more set of class <> </> to be parsed correctly -NN

    public void parse () throws IOException {

        if (!updated) {

            File startingfile = new File("BlockchainLedger.xml");

            String content = "";

            content = new String(Files.readAllBytes(Paths.get("BlockchainLedger.xml")));

            startingfile.delete();

            File finishfile = new File("BlockchainLedger.xml");

            BufferedWriter bw =
                    new BufferedWriter(new FileWriter("BlockchainLedger.xml", true));

            bw.write("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><unvarBlockBuilder>");


            bw.write(content);

            bw.write("</unvarBlockBuilder>");

            bw.flush();
            bw.close();

            updated = true;
        }
    }

    public void PrintverId() {

                try {
                    File inputFile = new File("BlockchainLedger.xml");
                    DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
                    DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
                    org.w3c.dom.Document doc = dBuilder.parse(inputFile);
                    doc.getDocumentElement().normalize();
                    System.out.println("Root element : " + doc.getDocumentElement().getNodeName());
                    NodeList nList = doc.getElementsByTagName("unvarBlockBuilder");

                    for (int temp = 2; temp < nList.getLength(); temp++) {
                        org.w3c.dom.Node nNode = nList.item(temp);

                        if (nNode.getNodeType() == org.w3c.dom.Node.ELEMENT_NODE) {
                            Element eElement = (Element) nNode;

                            System.out.println("Block Number : "
                                    + eElement
                                    .getElementsByTagName("blockNumber")

                                    .item(0)
                                    .getTextContent());

                            System.out.println("Verifier ID : "
                                    + eElement
                                    .getElementsByTagName("verID")

                                    .item(0)
                                    .getTextContent());

                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

    public void PrintTimeAndData() {

        try {
            File inputFile = new File("BlockchainLedger.xml");
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            org.w3c.dom.Document doc = dBuilder.parse(inputFile);
            doc.getDocumentElement().normalize();
            System.out.println("Root element : " + doc.getDocumentElement().getNodeName());
            NodeList nList = doc.getElementsByTagName("unvarBlockBuilder");

            for (int temp = 2; temp < nList.getLength(); temp++) {
                org.w3c.dom.Node nNode = nList.item(temp);

                if (nNode.getNodeType() == org.w3c.dom.Node.ELEMENT_NODE) {
                    Element eElement = (Element) nNode;

                    System.out.println("Block Number : "
                            + eElement
                            .getElementsByTagName("blockNumber")

                            .item(0)
                            .getTextContent());

                    System.out.println("TimeStamp : "
                            + eElement
                            .getElementsByTagName("timeStamp")

                            .item(0)
                            .getTextContent());
                    System.out.println("Data Line: "
                            + eElement
                            .getElementsByTagName("dataLine")

                            .item(0)
                            .getTextContent());

                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


}


class XMLtoString {

    //takes XML string and parses it into a new block object with the help of JAXB

    public Blockchain.UnvarBlockBuilder XMLStringtoObject (String XMLString) throws JAXBException {

        JAXBContext jaxbContext = JAXBContext.newInstance(Blockchain.UnvarBlockBuilder.class);
        Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
        StringReader reader = new StringReader(XMLString);
        Blockchain.UnvarBlockBuilder backtoblock = (Blockchain.UnvarBlockBuilder) jaxbUnmarshaller.unmarshal(reader);

        //1.UUID
        backtoblock.unvarUUID = backtoblock.getunvarUUID();
        //2.cpID of creating process
        backtoblock.cpID = backtoblock.getcpID();
        //3.TimeStamp
        backtoblock.timeStamp = backtoblock.gettimeStamp();
        //4.signedUUID
        backtoblock.signedUUID = backtoblock.getsignedUUID();
        //5.Data String from file
        backtoblock.dataLine = backtoblock.getdataLine();
        //6.Hash of data
        backtoblock.hashedData = backtoblock.gethashedData();
        //7.Block Number -
        backtoblock.blockNumber = backtoblock.getblockNumber();
        //8. Seed - random 256 string,
        backtoblock.Seed = backtoblock.getSeed();
        //9.Previous hash from the last block
        backtoblock.PrevHash = backtoblock.getPrevHash();
        //10.VerficationID
        backtoblock.VerID = backtoblock.getVerID();
        //11. Hash of parts 1-10
        backtoblock.CurrentHash = backtoblock.getCurrentHash();
        //12. Sign part 11
        backtoblock.SignedCurrentHash = backtoblock.getSignedCurrentHash();

        return backtoblock;
    }
}

class verifySignedElements {

    boolean verifySignedUUID (Blockchain.UnvarBlockBuilder signedblock ) throws Exception {

        boolean verUUID = false;

        PublicKey pubKey = null;

        String cpIDfromSignedBlock = signedblock.getcpID();

        int cpIDfromSignedBlockint = Integer.valueOf(cpIDfromSignedBlock);

        ProcessBlockArray newProcessBlockArray = ProcessBlockArray.getProcessBlockInfo();

        ArrayList<ProcessBlock> pulledProcessBlockArray=
                new ArrayList<ProcessBlock>(newProcessBlockArray.getPBArrayList());

        //get public key from correct process -NN

        for (ProcessBlock pb : pulledProcessBlockArray) {

            if (pb.getProcessID() == cpIDfromSignedBlockint) {

                pubKey = pb.getPubKey();
            }
        }

        //pull data from block to process -NN
        String rawdata  = signedblock.getunvarUUID();

        String sigdata = signedblock.getsignedUUID();

        byte[] rawdatabytes = rawdata.getBytes();

        byte[] sigdatabytes = Base64.getDecoder().decode(sigdata);

        verUUID = Blockchain.verifySig(rawdatabytes,pubKey,sigdatabytes);

      return verUUID;


    }
}


class getMyKeys { //singleton class to hold Keys for entire process.

    private static getMyKeys single_instance = null;

    private static PrivateKey myPrivateKey;
    private static PublicKey myPublicKey;

    public PrivateKey getMyPrivateKey() {
        return myPrivateKey;
    }

    public PublicKey getMyPublicKey() {
        return myPublicKey;
    }

    public static getMyKeys newPrivateKeyStorage() {
        if (single_instance == null)
            single_instance = new getMyKeys();
        return single_instance;
    }

    public void setMyPrivateKey (PrivateKey pKey) {
        myPrivateKey = pKey;
    }

    public void setMyPublicKey (PublicKey pubKey) {
        myPublicKey = pubKey;
    }

}

class checkBlockChainLedgerforUUID {

    public Boolean checkthisUUID(String UUIDtoCheck) throws FileNotFoundException {
        String find = "";
        Boolean UUIDfound = false;
        File XMLedger = new File("BlockchainLedger.xml"); //should have used a temp object copy, not the official xml one - NN
        Scanner scantheLedger = new Scanner(XMLedger);
        find = scantheLedger.findInLine(UUIDtoCheck); // search for UUID in the ledger -NN


        if (find != null) {
            UUIDfound = true ;
            System.out.println("This UUID: " + UUIDtoCheck + " is already in the ledger ");
        }
        return UUIDfound;

    }

}

class ProcessBlockArray { //singleton class to hold the process information in an array and call when needed - NN

    private static ProcessBlockArray single_instance = null;

    private ArrayList<ProcessBlock> PBArray ; // a slot for each process - NN

    private ProcessBlockArray() {

        PBArray = new ArrayList <ProcessBlock> ();

    }

    public static ProcessBlockArray getProcessBlockInfo() {
        if (single_instance == null)
            single_instance = new ProcessBlockArray();

        return single_instance;

    }

    public void addBlock (ProcessBlock newProcess) {

        PBArray.add(newProcess);

    }

    public int ProcessBlockSize() {

        int size = PBArray.size();

        return size;
    }

    public ArrayList<ProcessBlock> getPBArrayList() {

        return PBArray;
    }
}

class ProcessBlock {

    private int processID;
    private PublicKey pubKey;

    //takes entire String from server and parses out the PID and Key String -NN

    public void datatoBlock (String data) throws InvalidKeySpecException, NoSuchAlgorithmException {

        String PID =  data.substring(21,22) ;

        setProcessID(PID);
        setPubKey(data);


    }

  public void setProcessID(String idInput) {
      int convertInt = Integer.parseInt(idInput);
      processID = convertInt;
  }

  public int getProcessID (){

        return processID;
  }

  public void setPubKey(String keyInput) throws InvalidKeySpecException, NoSuchAlgorithmException {

      PublicKey stringtoKey = StringtoPublicKey(keyInput);

      pubKey = stringtoKey;

  }

  public PublicKey getPubKey() {

        return pubKey;
  }

    //String to public key through Base64 and X509. Encoded with Base64 on the other end. -NN

    public PublicKey StringtoPublicKey (String stringtoCovert) throws NoSuchAlgorithmException, InvalidKeySpecException {

        String Key =  stringtoCovert.substring(30,stringtoCovert.length());

        byte[] data = Base64.getDecoder().decode(Key);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
        KeyFactory fact = KeyFactory.getInstance("RSA"); //regenerate key from the decoded byte data -NN

        PublicKey pub = fact.generatePublic(spec);

        return pub;
    }

  }


class Ports{
    public static int KeyServerPortBase = 6050;
    public static int UnverifiedBlockServerPortBase = 6051;
    public static int BlockchainServerPortBase = 6052;

    public static int KeyServerPort;
    public static int UnverifiedBlockServerPort;
    public static int BlockchainServerPort;

    public void setPorts(){
        KeyServerPort = KeyServerPortBase + (Blockchain.PID * 1000);
        UnverifiedBlockServerPort = UnverifiedBlockServerPortBase + (Blockchain.PID * 1000);
        BlockchainServerPort = BlockchainServerPortBase + (Blockchain.PID * 1000);


    }
} //unchanged from example code - NN

class PublicKeyWorker extends Thread {
    Socket sock;
    PublicKeyWorker (Socket s) {sock = s;}
    public void run(){
        try{
            BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
            String data = in.readLine ();
            System.out.println("Got key: " + data.substring(0,30));
            ProcessBlock newProcess = new ProcessBlock(); //store process data (PID and publickey) in the process block array -NN
            newProcess.datatoBlock(data);
            ProcessBlockArray ProcessArrayInfo = ProcessBlockArray.getProcessBlockInfo();
            ProcessArrayInfo.addBlock(newProcess);

            int ArraySize = ProcessArrayInfo.ProcessBlockSize();

            System.out.println("Process Block Array Size is : " + ArraySize);

            sock.close();
        } catch (IOException x){x.printStackTrace();} catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}

class PublicKeyServer implements Runnable {


    public void run(){
        int q_len = 6;
        Socket sock;
        System.out.println("Starting Key Server input thread using " + Integer.toString(Ports.KeyServerPort));
        try{
            ServerSocket servsock = new ServerSocket(Ports.KeyServerPort, q_len);
            while (true) {
                sock = servsock.accept();
                new PublicKeyWorker (sock).start();
            }
        }catch (IOException ioe) {System.out.println(ioe);}
    }
}

class UnverifiedBlockServer implements Runnable {
    BlockingQueue<String> queue;
    UnverifiedBlockServer(BlockingQueue<String> queue){
        this.queue = queue;
    }

    //XML strings parsed from text file are send to this worker and placed in the blocking queue for
    //later use by the consumer - NN

    class UnverifiedBlockWorker extends Thread {
        Socket sock;
        UnverifiedBlockWorker (Socket s) {sock = s;}
        public void run(){
            try{
                BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
                String data = in.readLine (); //collecting XML data from all of the processes and placing in queue- NN
                System.out.println("Put in priority queue: XML DATA ");
                queue.put(data);
                sock.close();
            } catch (Exception x){x.printStackTrace();}
        }
    }

    public void run(){
        int q_len = 6;
        Socket sock;
        System.out.println("Starting the Unverified Block Server input thread using " +
                Integer.toString(Ports.UnverifiedBlockServerPort));
        try{
            ServerSocket servsock = new ServerSocket(Ports.UnverifiedBlockServerPort, q_len);
            while (true) {
                sock = servsock.accept();
                new UnverifiedBlockWorker(sock).start();
            }
        }catch (IOException ioe) {System.out.println(ioe);}
    }
}

class UnverifiedBlockConsumer implements Runnable {
    BlockingQueue<String> queue;
    int PID;
    UnverifiedBlockConsumer(BlockingQueue<String> queue){
        this.queue = queue;
    }

    public Blockchain.UnvarBlockBuilder XMLStringtoObject (String XMLString) throws JAXBException {

        JAXBContext jaxbContext = JAXBContext.newInstance(Blockchain.UnvarBlockBuilder.class);
        Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
        StringReader reader = new StringReader(XMLString);
        Blockchain.UnvarBlockBuilder backtoblock = (Blockchain.UnvarBlockBuilder) jaxbUnmarshaller.unmarshal(reader);

        //1.UUID
        backtoblock.unvarUUID = backtoblock.getunvarUUID();
        //2.cpID of creating process
        backtoblock.cpID = backtoblock.getcpID();
        //3.TimeStamp
        backtoblock.timeStamp = backtoblock.gettimeStamp();
        //4.signedUUID
        backtoblock.signedUUID = backtoblock.getsignedUUID();
        //5.Data String from file
        backtoblock.dataLine = backtoblock.getdataLine();
        //6.Hash of data
        backtoblock.hashedData = backtoblock.gethashedData();
        //7.Block Number - TODO set before adding to chain
        backtoblock.blockNumber = backtoblock.getblockNumber();
        //8. Seed - random 256 string,
        backtoblock.Seed = backtoblock.getSeed();
        //9.Previous hash from the last block, TODO create in file reader, pull ledger
        backtoblock.PrevHash = backtoblock.getPrevHash();
        //10.VerficationID //TODO set from worker on complete work
        backtoblock.VerID = backtoblock.getVerID();
        //11. Hash of parts 1-10 //TODO set from worker on complete work
        backtoblock.CurrentHash = backtoblock.getCurrentHash();
        //12. Sign part 11 //TODO set from worker on complete work
        backtoblock.SignedCurrentHash = backtoblock.getSignedCurrentHash();

        return backtoblock;
    }

    public void run(){
        String data;
        PrintStream toServer;
        Socket sock;

        //three step check to verify the block: -NN
        Boolean blockPartofLedger = true; //1. is it in the ledger? -NN
        Boolean signedBlockIDverified = false; //2. can the signed UUID be verified using the public key on file for this process -NN
        Boolean signedBlockHashverified = true; //TODO change //not impliemented, but would check the sig on the hashed data -NN

        String seedString = "";

        System.out.println("Starting the Unverified Block Priority Queue Consumer thread.\n");
        try{
            while(true){
                data = queue.take();
                Blockchain.UnvarBlockBuilder blocktoVarify = XMLStringtoObject(data); //take XML record and covert it back to an object -NN

                String veronUUID = blocktoVarify.getunvarUUID();
                System.out.println("Verifying this Block - UUID : " + veronUUID);

                //check if block is part of blockchain already, if it is, throw it out -NN
                blockPartofLedger = new checkBlockChainLedgerforUUID().checkthisUUID(blocktoVarify.getunvarUUID()) ; //1. is it in the ledger? -NN
                signedBlockIDverified = new verifySignedElements().verifySignedUUID(blocktoVarify); //2. can the signed UUID be verified using the public key on file for this process -NN
                //TODO Verify the creator-process-signed SHA-256 hash of the data -NN

                //IF statement all 3 pass -NN

                if ( !blockPartofLedger & signedBlockIDverified & signedBlockHashverified) {

                    try {
                        seedString =  new Work().doWork(blocktoVarify.gethashedData(), blocktoVarify.getSeed());
                    }
                    catch (Exception x){

                    }

                    Blockchain.UnvarBlockBuilder VarifiedBlock = new Blockchain.UnvarBlockBuilder();

                    VarifiedBlock = blocktoVarify;

                    System.out.println("This Block is verified and Work Complete - UUID : " + VarifiedBlock.getunvarUUID());

                    blockPartofLedger = new checkBlockChainLedgerforUUID().checkthisUUID(blocktoVarify.getunvarUUID()) ;

                    if (!blockPartofLedger) { //check again if UUID is in the ledger - NN

                        System.out.println("Completing Block - UUID : " + VarifiedBlock.getunvarUUID()); //Finish the block with all of the post work information - NN

                        VarifiedBlock.setVerID(String.valueOf(Blockchain.PID) ); //set verify process on block -NN
                        VarifiedBlock.setSeed(seedString); //get the seed that solved the puzzle - NN

                        String VarObjecttoXMLforCurrent = new Blockchain.createXMLfile().ObjecttoXMLString(VarifiedBlock);

                        String hashedCurrentData =  new Blockchain.txttoXMLconverter().DataHash(VarObjecttoXMLforCurrent);

                        getMyKeys getPrivate = getMyKeys.newPrivateKeyStorage();
                        PrivateKey privateKey = getPrivate.getMyPrivateKey();

                        String signedhashedCurrentData = new Blockchain.txttoXMLconverter().UUIDsigner(hashedCurrentData, privateKey);

                        VarifiedBlock.setCurrentHash(hashedCurrentData);
                        VarifiedBlock.setSignedCurrentHash(signedhashedCurrentData);

                        String VarObjecttoXML = new Blockchain.createXMLfile().ObjecttoXMLString(VarifiedBlock); //convert verified block back to XML -NN

                        System.out.println("Sending Verified Block as XML"); //send ver blocks to all processes - NN
                        for(int i=0; i < Blockchain.numProcesses; i++){
                            sock = new Socket(Blockchain.serverName, Ports.BlockchainServerPortBase + (i * 1000));
                            toServer = new PrintStream(sock.getOutputStream());
                            toServer.println(VarObjecttoXML);
                            toServer.flush();
                            sock.close();
                        }

                        Thread.sleep(1500);
                    }
                }
            }
        }catch (Exception e) {System.out.println(e);}
    }
}

//collect verified blocks and update local and master ledgers - NN
class BlockchainWorker extends Thread { // Class definition
    Socket sock; // Class member, socket, local to Worker.
    static Integer blockNumber = 0;
    static String tempChains = "";
    static String previousHash = "dummy data";


    BlockchainWorker (Socket s) {sock = s;}
    public void run(){
        try{
            Boolean blockPartofLedger = true;

            StringBuilder sb = new StringBuilder();
            BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
            String data = in.readLine();

            XMLtoString xmltoString = new XMLtoString();

            Blockchain.UnvarBlockBuilder FinalCheck = xmltoString.XMLStringtoObject(data); //take the ver'ed XML blocks back to objects -NN

            blockPartofLedger = new checkBlockChainLedgerforUUID().checkthisUUID(FinalCheck.getunvarUUID()); //check again for UUID in ledger -NN

            if (!blockPartofLedger) {

                blockNumber = blockNumber + 1;
                String blocknum = blockNumber.toString();
                FinalCheck.setblockNumber(blocknum);
                FinalCheck.setPrevHash(previousHash); //set the previous hash block on varified block -NN
                previousHash = FinalCheck.gethashedData(); //updated previous hash to last hashblock -NN

                String VarObjecttoXML = new Blockchain.createXMLfile().ObjecttoXMLString(FinalCheck);


                if (Blockchain.PID == 0) {

                    System.out.println("----Updating BlockchainLedger.xml-----");
                    new Blockchain.createXMLfile().writeXMLfile(VarObjecttoXML);
                    //new Blockchain.createXMLfile().writeTester(FinalCheck);
                } else {
                    System.out.println("----Updating My Temp Chain-----");
                    sb.append(VarObjecttoXML);
                    tempChains = sb.toString();
                }

            }

            sock.close();
        } catch (IOException x){x.printStackTrace();} catch (JAXBException e) {
            e.printStackTrace();
        }
        {

        }
    }
}

class BlockchainServer implements Runnable {
    public void run(){
        int q_len = 6; /* Number of requests for OpSys to queue */
        Socket sock;
        System.out.println("Starting the blockchain server input thread using " + Integer.toString(Ports.BlockchainServerPort));
        try{
            ServerSocket servsock = new ServerSocket(Ports.BlockchainServerPort, q_len);
            while (true) {
                sock = servsock.accept();
                new BlockchainWorker (sock).start();
            }
        }catch (IOException ioe) {System.out.println(ioe);}
    }
}

// Class Blockchain for BlockChain
public class Blockchain {
    static String serverName = "localhost";
    static int numProcesses = 3; // Set this to match your batch execution file that starts N processes with args 0,1,2,...N
    static int PID = 0; // Our process ID

    public void sendXMLblocks(Queue<String> unVarXMLqueue) {
        Queue<String> unVarXML = unVarXMLqueue;
        while (unVarXML.peek() != null) {
            String unvarBlock = unVarXML.remove();
            new Blockchain().MultiSend(unvarBlock);
        }
    }

    public void MultiSend (String sendingString) { // Multicast some data to each of the processes.
        Socket sock;
        PrintStream toServer;

            try {

                for (int i = 0; i < numProcesses; i++) {// Send a sample unverified block A to each server
                    sock = new Socket(serverName, Ports.UnverifiedBlockServerPortBase + (i * 1000));
                    toServer = new PrintStream(sock.getOutputStream());


                    toServer.println(sendingString);
                    toServer.flush();
                    sock.close();
                }

            } catch (Exception x) {
                x.printStackTrace();
            }




    }

    public void MultiSendKeys (){ // Multicast some data to each of the processes.
        Socket sock;
        PrintStream toServer;


        try{
            for(int i=0; i< numProcesses; i++){// Send our key to all servers.
                sock = new Socket(serverName, Ports.KeyServerPortBase + (i * 1000));
                toServer = new PrintStream(sock.getOutputStream());

                getMyKeys myPrivateKeyStorage = getMyKeys.newPrivateKeyStorage();

                PublicKey myPublicKey = myPrivateKeyStorage.getMyPublicKey();

                String myPublicKeytoString = PublicKeytoString(myPublicKey);

                toServer.println("Public key from PID: " + Blockchain.PID + " stored!" + myPublicKeytoString);

                toServer.flush();

               /* if (!myPublicKey.equals(pub)) {
                    System.out.println("not equals");
                }
                else if (myPublicKey.equals(pub)) {
                    System.out.println("the keys match");
                }*/

                sock.close();
            }
            Thread.sleep(1000); // wait for keys to settle, normally would wait for an ack

        }catch (Exception x) {x.printStackTrace ();}
    }

    public static KeyPair generateKeyPair(long seed) throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rng.setSeed(seed);
        keyGenerator.initialize(1024, rng);

        return (keyGenerator.generateKeyPair());
    }

    public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initVerify(key);
        signer.update(data);

        return (signer.verify(sig));
    }

    public String PublicKeytoString (PublicKey inputKey) {

        byte[] encodePublicKey = inputKey.getEncoded();

        String publicKey = Base64.getEncoder().encodeToString( encodePublicKey );

        return publicKey;


    }

    @XmlRootElement
    public static class UnvarBlockBuilder {
        //1.UUID
        String unvarUUID = "dummy data";
        //2.cpID of creating process
        String cpID = "dummy data";
        //3.TimeStamp
        String timeStamp = "dummy data";
        //4.signedUUID
        String signedUUID = "dummy data";
        //5.Data String from file
        String dataLine = "dummy data";
        //6.Hash of data
        String hashedData = "dummy data";
        //7.Block Number - TODO set before adding to chain
        String blockNumber = "dummy data";
        //8. Seed - random 256 string,
        String Seed = "dummy data";
        //9.Previous hash from the last block, TODO create in file reader, pull ledger
        String PrevHash = "dummy data";
        //10.VerficationID //TODO set from worker on complete work
        String VerID = "dummy data";
        //11. Hash of parts 1-10 //TODO set from worker on complete work
        String CurrentHash = "dummy data";
        //12. Sign part 11 //TODO set from worker on complete work
        String SignedCurrentHash = "dummy data";


        public String getunvarUUID() {return unvarUUID;}
        @XmlElement
        public void setunvarUUID (String unvarID){this.unvarUUID = unvarID;}

        public String getcpID() {return cpID;}
        @XmlElement
        public void setcpID (String pID){this.cpID = pID;}

        public String gettimeStamp() {return timeStamp;}
        @XmlElement
        public void settimeStamp (String tS){this.timeStamp = tS;}

        public String getsignedUUID() {return signedUUID;}
        @XmlElement
        public void setsignedUUID (String signID){this.signedUUID = signID;}

        public String getdataLine() {return dataLine;}
        @XmlElement
        public void setdataLine (String dataL){this.dataLine = dataL;}

        public String gethashedData() {return hashedData;}
        @XmlElement
        public void sethashedData (String hashD){this.hashedData = hashD;}

        public String getblockNumber() {return blockNumber;}
        @XmlElement
        public void setblockNumber (String blockN){this.blockNumber = blockN;}

        public String getSeed() {return Seed;}
        @XmlElement
        public void setSeed (String seedData){this.Seed = seedData;}

        public String getPrevHash() {return PrevHash;}
        @XmlElement
        public void setPrevHash (String prevh){this.PrevHash = prevh;}

        public String getVerID() {return VerID;}
        @XmlElement
        public void setVerID (String vid){this.VerID = vid;}

        public String getCurrentHash() {return CurrentHash;}
        @XmlElement
        public void setCurrentHash (String currhashD){this.CurrentHash = currhashD;}

        public String getSignedCurrentHash() {return SignedCurrentHash;}
        @XmlElement
        public void setSignedCurrentHash (String signedcurrhashD){this.SignedCurrentHash = signedcurrhashD;}

    }

    public static class txttoXMLconverter {

        static int cpID;

        public void setcpIDforLocalFile(int inputcpID) {

            cpID = inputcpID;
        }

        public Queue<String> loadFile() throws IOException {

            Queue<String> inputFilesFromFile = new LinkedList<String>();
            //select local file from cpID --NN
            File localFile = new File("BlockInput" + cpID + ".txt");
            BufferedReader buffRead = new BufferedReader(new FileReader(localFile));
            String inputLine = null;
            //read lines into a queue -NN
            while ((inputLine = buffRead.readLine()) != null) {
                inputFilesFromFile.add(inputLine);
            }
            return inputFilesFromFile;
        }

        public byte[] signData(byte[] data, PrivateKey key) throws Exception {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initSign(key);
            signer.update(data);
            return (signer.sign());
        }

        public String UUIDcreater() {
            //create a UUID
            UUID newBlockUUID = UUID.randomUUID();
            String StringnewBlockUUID = UUID.randomUUID().toString();
            return StringnewBlockUUID;
        }

        public String newBlockcpID() {
            Integer newBlockcpID = cpID;
            String cpIDstring = newBlockcpID.toString();
            return cpIDstring;
        }

        public String timeStamper() {
            //the current timestamp
            Date date = new Date();
            //String T1 = String.format("%1$s %2$tF.%2$tT", "Timestamp:", date);
            String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
            String TimeStampString = T1 + "." + cpID ; // No timestamp collisions!
            return  TimeStampString;
        }

        public String UUIDsigner(String UUIDstring, PrivateKey pKey) throws Exception {
            String encodedUUID = Base64.getEncoder().encodeToString(UUIDstring.getBytes());

            byte[] decodeUUID = Base64.getDecoder().decode(encodedUUID);

            byte[] blockSig = signData(decodeUUID, pKey);

            String signedUUIDString = Base64.getEncoder().encodeToString(blockSig);

            return signedUUIDString;

        }

        public String DataHash(String dataLine) throws NoSuchAlgorithmException {
            //optionally an SHA-256 hash of the input data is placed in the DataHash field for auditing purposes—see below under DataHash

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update (dataLine.getBytes());
            byte byteDataLine[] = md.digest();

            String DataHashString = Base64.getEncoder().encodeToString(byteDataLine);
            return DataHashString;

        }

        public KeyPair generateKeyPair(long seed) throws Exception {
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
            SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
            rng.setSeed(seed);
            keyGenerator.initialize(1024, rng);

            return (keyGenerator.generateKeyPair());
        }

        public String getSeed() {

            byte[] seedByte = new byte[256];
            new Random().nextBytes(seedByte);
            String seedString = Base64.getEncoder().encodeToString(seedByte);
            return seedString;

        }

        public PrivateKey getPrivateKey() {
            getMyKeys myPrivateKeyStorage = getMyKeys.newPrivateKeyStorage();
            PrivateKey myPrivateKey = myPrivateKeyStorage.getMyPrivateKey();
            return myPrivateKey;
        }



        public BlockingQueue<String> GenerateQueue() throws Exception {

            Queue<String> inputFilesFromFile = new txttoXMLconverter().loadFile();

            BlockingQueue<String> unvarXML = new PriorityBlockingQueue<String>();

            while (inputFilesFromFile.peek() != null) {

                UnvarBlockBuilder blockRecord = new UnvarBlockBuilder();

                String UUID = UUIDcreater();
                String cpID = new txttoXMLconverter().newBlockcpID();
                String TimeStamp = new txttoXMLconverter().timeStamper();
                String SignedUUID = new txttoXMLconverter().UUIDsigner(UUID, new txttoXMLconverter().getPrivateKey());
                String dataLine = inputFilesFromFile.remove();
                String hashedData = new txttoXMLconverter().DataHash(dataLine);
                String seed = new txttoXMLconverter().getSeed();
                String prevHash = "TODO" ;


                blockRecord.setunvarUUID(UUID);
                blockRecord.setcpID(cpID);
                blockRecord.settimeStamp(TimeStamp);
                blockRecord.setsignedUUID(SignedUUID);
                blockRecord.setdataLine(dataLine);
                blockRecord.sethashedData(hashedData);
                blockRecord.setSeed(seed);
                blockRecord.setPrevHash(prevHash);

                /* The XML conversion tools: */
                JAXBContext jaxbContext = JAXBContext.newInstance(UnvarBlockBuilder.class);
                Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
                StringWriter sw = new StringWriter();

                // CDE Make the output pretty printed:
                //jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

                /* CDE We marshal the block object into an XML string so it can be sent over the network: */
                jaxbMarshaller.marshal(blockRecord, sw);
                String stringXML = sw.toString();


                System.out.println("Loading to local XML queue to multicast:" + stringXML.substring(299,330)); // Show what it looks like.

                unvarXML.add(stringXML);

            }
            return unvarXML;
        }


    }

    public static class createXMLfile {

        public void createNewXMLfile() throws JAXBException, IOException {

            UnvarBlockBuilder blockRecord = new UnvarBlockBuilder();

            File file = new File ( "BlockchainLedger.xml");

            //JAXBContext jaxbContext = JAXBContext.newInstance(UnvarBlockBuilder.class);
            //Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
            //StringWriter sw = new StringWriter();

            //jaxbMarshaller.marshal(blockRecord, file);

            String XMLString = ObjecttoXMLString(blockRecord);

            writeXMLfile(XMLString);


            // CDE Make the output pretty printed:
            //jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        }

        public void writeXMLfile(String XMLinput) throws JAXBException, IOException {

            FileWriter fileWrite = new FileWriter("BlockchainLedger.xml",true);
            //System.out.println(XMLinput);
            fileWrite.flush();
            //fileWrite.write("\n");
            fileWrite.write(XMLinput.substring(55,XMLinput.length())); //should exclude header another way through XML -NN
            //fileWrite.write("\n");
            fileWrite.close();

        }

        public void writeTester (UnvarBlockBuilder block) throws JAXBException, IOException {

            FileWriter fileWrite = new FileWriter("BlockchainLedger.xml",true);

            fileWrite.flush();


            JAXBContext jaxbContext = JAXBContext.newInstance(UnvarBlockBuilder.class);
            Marshaller jaxbMarshaller = jaxbContext.createMarshaller();

            jaxbMarshaller.marshal(block, fileWrite);

            fileWrite.close();

        }

        public String ObjecttoXMLString (UnvarBlockBuilder blocktoDecomp) throws JAXBException, IOException {

            JAXBContext jaxbContext = JAXBContext.newInstance(UnvarBlockBuilder.class);
            Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
            Writer sw = new StringWriter();



            jaxbMarshaller.marshal(blocktoDecomp, sw);

            String newXMLStringfromObject = sw.toString();

            sw.write(newXMLStringfromObject);

            sw.close();

            return newXMLStringfromObject;
        }

    }

    static class GetInputFromUser {

        static XMLparse parse = new XMLparse();

        public void PrintCredit() throws IOException {

            parse.parse();
            parse.PrintverId();
        }

        public void PrintTimeData() throws IOException {

            parse.parse();
            parse.PrintTimeAndData();

        }

        public void run() throws IOException {
            // Using Scanner for Getting Input from User
            Scanner in = new Scanner(System.in);

            boolean running = true;

            while (running) {
                System.out.println("Commandlist following process 0 completion");
                System.out.println("'c' for verifying process of each block ");
                System.out.println("'l' for block number, timestamp, and data line");

                String userInput = in.nextLine();

                userInput.trim();

                switch (userInput) {

                    case "c":
                        PrintCredit();
                        break;

                    case "l":
                        PrintTimeData();
                        break;
                }


            }
        }
    }

    public static void main(String args[]) throws Exception {
        int q_len = 6; /* Number of requests for OpSys to queue. Not interesting. */
        PID = (args.length < 1) ? 0 : Integer.parseInt(args[0]); // Process ID
        System.out.println("Nick Naber's BlockFramework control-c to quit.\n");
        System.out.println("Using processID " + PID + "\n");

        KeyPair keyPair = generateKeyPair(999);

        getMyKeys myPrivateKeyStorage = getMyKeys.newPrivateKeyStorage();

        myPrivateKeyStorage.setMyPrivateKey(keyPair.getPrivate());
        myPrivateKeyStorage.setMyPublicKey(keyPair.getPublic());

        final BlockingQueue<String> queue = new PriorityBlockingQueue<>(); // Concurrent queue for unverified blocks

        Queue<String> unVarXMLqueue = new PriorityBlockingQueue<>();

        new Ports().setPorts(); // Establish OUR port number scheme, based on PID

        new Thread(new PublicKeyServer()).start(); // New thread to process incoming public keys
        new Thread(new UnverifiedBlockServer(queue)).start(); // New thread to process incoming unverified blocks
        new Thread(new BlockchainServer()).start(); // New thread to process incomming new blockchains


        try{Thread.sleep(1000);}catch(Exception e){} // Wait for servers to start.

        if (PID == 0) {

            File deletefile = new File("Blockchainledger.xml");

            if(deletefile.delete()) {
                System.out.println("Old ledger deleted. Starting a new Blockchainledger.xml");
            }
            else {
                System.out.println("Blockchainledger.xml not present or could not be deleted. Starting a new Blockchainledger.xml");
            }

            new Blockchain.createXMLfile().createNewXMLfile();
        }

        txttoXMLconverter fileReader = new txttoXMLconverter(); //start new file reader class -NN

        fileReader.setcpIDforLocalFile(PID); //set PID to pick the correct local file to pull from and set creating process ID - NN

        unVarXMLqueue =  fileReader.GenerateQueue(); //generate queue of XML String converted records from local file -NN

        new Blockchain().MultiSendKeys(); //send public keys to all processes - NN

        //TODO, only when process everyone has keys
        try{Thread.sleep(3000);}catch(Exception e){}

        new Blockchain().sendXMLblocks(unVarXMLqueue); //send the queued unver XML blocks to all processes - NN

        try{Thread.sleep(1000);}catch(Exception e){}

        new Thread(new UnverifiedBlockConsumer(queue)).start();

        if (PID == 0) { //only runs on p0 becuase I had to modify the XML to work with the parser -NN
            System.out.println("------Controls-------\n");
            new GetInputFromUser().run();
            System.out.println("------Controls-------\n");
        }

    }

}

