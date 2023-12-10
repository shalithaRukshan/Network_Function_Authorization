package com.ucd.mno;

import com.ucd.util.Constants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.hyperledger.fabric.gateway.Contract;
import org.hyperledger.fabric.gateway.ContractException;
import org.hyperledger.fabric.gateway.Gateway;
import org.hyperledger.fabric.gateway.Network;
import org.hyperledger.fabric.gateway.Wallet;
import org.hyperledger.fabric.gateway.Wallets;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;


public class Application {

    private static final Logger logger = LogManager.getLogger(Application.class);
    public static KeyPair keyPair;
    public static String host = "10.0.2.15";
    public static int port = 9501;
    public static Contract contract = null;
    public static boolean isBC = true;

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
            contract = network.getContract("basic");

            byte[] result;

            System.out.println("\n");
            result = contract.evaluateTransaction("GetAllMNOs");
            System.out.println("Evaluate Transaction: GetAllAssets, result: " + new String(result));

            handlesocket();
        } catch (Exception e) {
            System.err.println(e);
        }


    }

    public static void handlesocket() {

        try {
            ServerSocket serverSocket = new ServerSocket(port);
            Socket socket = null;
            while (true) {
                try {
                    socket = serverSocket.accept();
                } catch (IOException e) {
                    System.out.println("I/O error: " + e);
                }
                // new thread for a client
                new NRFThread(socket).start();
            }

        } catch (Exception e) {
            logger.error(e.getMessage());
        }
    }

    public static class NRFThread extends Thread {
        protected Socket socket;

        public NRFThread(Socket clientSocket) {
            this.socket = clientSocket;
        }

        public void run() {
            try {
                BufferedReader in = new BufferedReader(
                        new InputStreamReader(socket.getInputStream()));

                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                byte[] result;

                String cert = in.readLine();
                if (isBC) {
                    result = contract.evaluateTransaction("ValidateCert", cert);
                    logger.info("Response fro certificate validation: " + new String(result));
                    if (new String(result).equals("success")) {
                        out.println("Certificate");
                        String authRequest = in.readLine();
                        logger.info("Request for authorization: " + authRequest);
                        String[] authParts = authRequest.split("\\|\\|");
                        String auth = authParts[0];
                        String otherP = authParts[1];
                        if (auth.equals("AuthRequest")) {
                            result = contract.evaluateTransaction("ValidateSlice", otherP, otherP);
                            logger.info("Response for validating slice: " + new String(result));
                            if (new String(result).equals("success")) {
                                logger.info("Auth token sent");
                                out.println("AuthToken");

                            }
                        } else if (auth.equals("AuthValidate")) {
                            logger.info("Auth validation request came");
                            out.println("success");
                        } else {
                            //todo
                        }

                    }


                    in.close();
                    out.close();
                    socket.close();
                    logger.info("Connections closed");
                } else {
                    logger.info("Without BC execution");
                    result = "success".getBytes();
                    logger.info("Response fro certificate validation: " + new String(result));
                    if (new String(result).equals("success")) {
                        out.println("Certificate");
                        String authRequest = in.readLine();
                        logger.info("Request for authorization: " + authRequest);
                        String[] authParts = authRequest.split("\\|\\|");
                        String auth = authParts[0];
                        String otherP = authParts[1];
                        if (auth.equals("AuthRequest")) {
                            result = "success".getBytes();
                            logger.info("Response for validating slice: " + new String(result));
                            if (new String(result).equals("success")) {
                                logger.info("Auth token sent");
                                out.println("AuthToken");

                            }
                        } else if (auth.equals("AuthValidate")) {
                            logger.info("Auth validation request came");
                            out.println("success");
                        } else {
                            //todo
                        }

                    }


                    in.close();
                    out.close();
                    socket.close();
                    logger.info("Connections closed");
                }
            } catch (IOException | ContractException e) {
                e.printStackTrace();
            }
        }
    }

}
