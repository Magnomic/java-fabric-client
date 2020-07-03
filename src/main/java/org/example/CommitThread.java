package org.example;

import org.hyperledger.fabric.gateway.*;
import org.hyperledger.fabric.sdk.Peer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeoutException;

/**
 * Created by Du on 2020/7/1.
 */
public class CommitThread extends Thread {

    private Gateway.Builder builder;
    private String message;

    public CommitThread(Gateway.Builder builder, String message) {
        this.builder = builder;
        this.message = message;
    }

    @Override
    public void run() {
        try (Gateway gateway = builder.connect()) {

            // get the network and contract
            Network network = gateway.getNetwork("mychannel");

            Contract contract = network.getContract("mycc");
            byte[] result;
            List<Peer> peerList = new ArrayList<>(network.getChannel().getPeers());
            List<Peer> endorsers = new ArrayList<>();
            Collections.shuffle(peerList);
            for (Peer peer : peerList){
                if (peer.getName().contains("org1")) {
                    endorsers.add(peer);
                    break;
                }
            }
            for (Peer peer : peerList){
                if (peer.getName().contains("org2")) {
                    endorsers.add(peer);
                    break;
                }
            }

            Transaction transaction = contract.createTransaction("addRecord");
            transaction.setEndorsingPeers(endorsers);
            transaction.submit("test1538" + message);

            gateway.close();
            System.out.println("success");
        } catch (Exception e){
            e.printStackTrace();
        }

    }


}
