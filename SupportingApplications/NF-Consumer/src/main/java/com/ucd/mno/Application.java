package com.ucd.mno;

import com.ucd.util.Constants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.hyperledger.fabric.gateway.Contract;
import org.hyperledger.fabric.gateway.Gateway;
import org.hyperledger.fabric.gateway.Network;
import org.hyperledger.fabric.gateway.Wallet;
import org.hyperledger.fabric.gateway.Wallets;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.sql.Timestamp;
import java.time.Instant;


public class Application {

    private static final Logger logger = LogManager.getLogger(Application.class);
    public static KeyPair keyPair;
    public static String nrfhost = "10.0.2.15";
    public static String nfprod = "10.0.2.15";
    public static int nrfport = 9501;
    public static int nfProdPort = 9500;
    public static final boolean isBC = true;

    static {
        System.setProperty("org.hyperledger.fabric.sdk.service_discovery.as_localhost", "true");
    }

    // helper function for getting connected to the gateway
    public static Gateway connect() throws Exception {
        // Load a file system based wallet for managing identities.
        Path walletPath = Paths.get("wallet");
        Wallet wallet = Wallets.newFileSystemWallet(walletPath);
        // load a CCP
        Path networkConfigPath = Paths.get("connection-acme.json");

        Gateway.Builder builder = Gateway.createBuilder();
        builder.identity(wallet, Constants.MNO_NAME).networkConfig(networkConfigPath).discovery(true);
        return builder.connect();
    }

    public static void main(String[] args) throws Exception {

        try {
            Files.write(Paths.get("results"), ("with BC \n").getBytes(), StandardOpenOption.APPEND);
        } catch (IOException error) {
            //exception handling left as an exercise for the reader
        }
        for (int i = 0; i < 20; i++) {
            long time = getService();
            logger.info(time);
            try {
                Files.write(Paths.get("results"), (String.valueOf(time) + "\n").getBytes(), StandardOpenOption.APPEND);
            } catch (IOException error) {
                //exception handling left as an exercise for the reader
            }
        }

    }

    public static long getService() throws Exception {
        // enrolls the admin and registers the user
        System.out.println("starting app ");

        try {
            EnrollAdmin.enrollAdmin(null);
            RegisterUser.enrollUser(null);
        } catch (Exception e) {
            System.err.println(e);
        }

        // connect to the network and invoke the smart contract
        try (Gateway gateway = connect()) {

            // get the network and contract
            Network network = gateway.getNetwork("mychannel");
            System.out.println(network.getChannel().getPeers());
            Contract contract = network.getContract("basic");

            byte[] result;

            Socket NRFSocket = new Socket(nrfhost, nrfport);
            InputStream is = NRFSocket.getInputStream();
            OutputStream os = NRFSocket.getOutputStream();

            BufferedReader in =
                    new BufferedReader(new InputStreamReader(is));
            PrintWriter out = new PrintWriter(os, true);

            if (isBC) {
                long startTime = getTimestamp();
                out.println("Certificate");


                String nrfCert = in.readLine();
                logger.info("NRFCert: " + nrfCert);
                result = contract.evaluateTransaction("ValidateCert", nrfCert);
                logger.info("Cert response: " + new String(result));


                out.println("AuthRequest||nf||slice1");
                String authToken = in.readLine();

                in.close();
                out.close();
                NRFSocket.close();

                Socket nfSocket = new Socket(nfprod, nfProdPort);
                is = nfSocket.getInputStream();
                os = nfSocket.getOutputStream();

                in = new BufferedReader(new InputStreamReader(is));
                out = new PrintWriter(os, true);

                out.println("NFCcert");
                String nfCert = in.readLine();
                logger.info("Received result from producer: " + nfCert);
                result = contract.evaluateTransaction("ValidateCert", nfCert);
                logger.info("NFP cert Validation: " + new String(result));

                out.println("serviceReq||" + authToken + "||slice10");
                logger.info("Service request Sent");
                String service = in.readLine();
                logger.info("Service response: " + service);

                long endTime = getTimestamp();
                logger.info("Total time " + (endTime - startTime));
                return (endTime - startTime);
            } else {
                logger.info("Execution without BC");
                long startTime = getTimestamp();
                out.println("Certificate");


                String nrfCert = in.readLine();
                logger.info("NRFCert: " + nrfCert);
                result = "success".getBytes();
                logger.info("Cert response: " + new String(result));


                out.println("AuthRequest||nf||slice1");
                String authToken = in.readLine();

                in.close();
                out.close();
                NRFSocket.close();

                Socket nfSocket = new Socket(nfprod, nfProdPort);
                is = nfSocket.getInputStream();
                os = nfSocket.getOutputStream();

                in = new BufferedReader(new InputStreamReader(is));
                out = new PrintWriter(os, true);

                out.println("NFCcert");
                String nfCert = in.readLine();
                logger.info("Received result from producer: " + nfCert);
                result = "success".getBytes();
                logger.info("NFP cert Validation: " + new String(result));

                out.println("serviceReq||" + authToken + "||slice10");
                logger.info("Service request Sent");
                String service = in.readLine();
                logger.info("Service response: " + service);

                long endTime = getTimestamp();
                logger.info("Total time " + (endTime - startTime));
                return (endTime - startTime);
            }
        } catch (Exception e) {
            System.err.println(e);
            throw new Exception(e);
        }

    }

    private static long getTimestamp() {
        Timestamp ts = Timestamp.from(Instant.now());
        return ts.getTime();
    }

}
