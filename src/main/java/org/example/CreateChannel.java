package org.example;

import org.hyperledger.fabric.gateway.Contract;
import org.hyperledger.fabric.gateway.Gateway;
import org.hyperledger.fabric.gateway.Network;
import org.hyperledger.fabric.sdk.*;
import org.hyperledger.fabric.sdk.exception.*;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.security.CryptoSuiteFactory;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Path;

import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static java.lang.String.format;
import static org.hyperledger.fabric.sdk.Channel.PeerOptions.createPeerOptions;
import static org.junit.Assert.*;

/**
 * Created by Du on 2020/7/2.
 */
public class CreateChannel {

    static void out(String format, Object... args) {

        System.err.flush();
        System.out.flush();

        System.out.println(format(format, args));
        System.err.flush();
        System.out.flush();

    }

    public String getGRPCUrl(String type, String name){
        switch (type) {
            case "peer":
                Integer peerId = Integer.parseInt(name.split("peer")[1].split("\\.")[0]);
                Integer orgId = Integer.parseInt(name.split("org")[1].split("\\.")[0]);
                return "grpcs://localhost:" + (20000+1000*orgId+peerId);
            case "orderer":
                Integer ordererId = Integer.parseInt(name.split("orderer")[1].split("\\.")[0].equals("")? "0": name.split("orderer")[1].split("\\.")[0]);
                return "grpcs://localhost:" + (18000+ordererId);
            default:

        }
        return "";
    }

    public Orderer getOrderer(HFClient hfClient, String ordererName) throws InvalidArgumentException {
        Properties ordererProperties = getEndPointProperties("orderer", ordererName);
        ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveTime", new Object[] {5L, TimeUnit.MINUTES});
        ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveTimeout", new Object[] {8L, TimeUnit.SECONDS});
        ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveWithoutCalls", new Object[] {true});
        Orderer orderer = hfClient.newOrderer(ordererName,getGRPCUrl("orderer", ordererName),ordererProperties);
//        System.out.println(orderer.getName());
//        System.out.println(orderer.getProperties());
//        System.out.println(orderer.getUrl());
        return orderer;
    }

    public Channel getChannel(HFClient client, String channelName, String orgName) throws InvalidArgumentException, TransactionException, IOException {
        // initialize channel
        // peer name and endpoint in fabcar network
        // channel name in fabcar network
        Channel channel = client.newChannel(channelName);
        channel.addOrderer(getOrderer(client, "orderer.example.com"));
//        for (int i=0;i<10;i++){
//            Properties peerProperties = getEndPointProperties("peer", "peer"+i+"."+orgName);
//            peerProperties.put("grpc.NettyChannelBuilderOption.maxInboundMessageSize", 9000000);
//            Peer peer = client.newPeer("peer"+i+"."+orgName, getGRPCUrl("peer", "peer"+i+"."+orgName), peerProperties);
//            channel.addPeer(peer);
//        }
        channel.initialize();
        byte[] serializedChannelBytes = channel.serializeChannel();
        return channel;
    }

    private String getDomainName(final String name) {
        int dot = name.indexOf(".");
        if (-1 == dot) {
            return null;
        } else {
            return name.substring(dot + 1);
        }

    }

    public Properties getEndPointProperties(final String type, final String name) {
        Properties ret = new Properties();

        final String domainName = getDomainName(name);

        File cert = Paths.get("../../first-network", "crypto-config/ordererOrganizations".replace("orderer", type), domainName, type + "s",
                name, "tls/server.crt").toFile();
        if (!cert.exists()) {
            throw new RuntimeException(String.format("Missing cert file for: %s. Could not find at location: %s", name,
                    cert.getAbsolutePath()));
        }

        File clientCert;
        File clientKey;
        if ("orderer".equals(type)) {
            clientCert = Paths.get("../../first-network", "crypto-config/ordererOrganizations/example.com/users/Admin@example.com/tls/client.crt").toFile();

            clientKey = Paths.get("../../first-network", "crypto-config/ordererOrganizations/example.com/users/Admin@example.com/tls/client.key").toFile();
        } else {
            clientCert = Paths.get("../../first-network", "crypto-config/peerOrganizations/", domainName, "users/User1@" + domainName, "tls/client.crt").toFile();
            clientKey = Paths.get("../../first-network", "crypto-config/peerOrganizations/", domainName, "users/User1@" + domainName, "tls/client.key").toFile();
        }

        if (!clientCert.exists()) {
            throw new RuntimeException(String.format("Missing  client cert file for: %s. Could not find at location: %s", name,
                    clientCert.getAbsolutePath()));
        }

        if (!clientKey.exists()) {
            throw new RuntimeException(String.format("Missing  client key file for: %s. Could not find at location: %s", name,
                    clientKey.getAbsolutePath()));
        }
        ret.setProperty("clientCertFile", clientCert.getAbsolutePath());
        ret.setProperty("clientKeyFile", clientKey.getAbsolutePath());


        ret.setProperty("pemFile", cert.getAbsolutePath());

        ret.setProperty("hostnameOverride", name);
        ret.setProperty("sslProvider", "openSSL");
        ret.setProperty("negotiationType", "TLS");

        return ret;
    }


    public Channel createChannel(String channelName, HFClient hfClient, User admin, String orgName) throws InvalidArgumentException, IOException, TransactionException, ProposalException {
        // get TX and configure file
        File configTxFile = Paths.get("../../first-network","channel-artifacts",channelName+".tx").toFile();
        ChannelConfiguration configuration = new ChannelConfiguration(configTxFile);
        // get orderer
        Orderer orderer = getOrderer(hfClient, "orderer.example.com");
        // create channel
        Channel newChannel = hfClient.newChannel(channelName, orderer, configuration, hfClient.getChannelConfigurationSignature(configuration, admin));
        // get end point
        for (int i=0;i<10;i++){
            Properties peerProperties = getEndPointProperties("peer", "peer"+i+"."+orgName);
            peerProperties.put("grpc.NettyChannelBuilderOption.maxInboundMessageSize", 9000000);
            Peer peer = hfClient.newPeer("peer"+i+"."+orgName, getGRPCUrl("peer", "peer"+i+"."+orgName), peerProperties);
            newChannel.addPeer(peer);
        }
        newChannel.addOrderer(orderer);
        newChannel.initialize();
        // test if channel is properly initialized
        byte[] serializedChannelBytes = newChannel.serializeChannel();
        return newChannel;
    }

    public void peerJoinChannel(HFClient hfClient, Channel channel, String peerName) throws ProposalException, InvalidArgumentException {
        Properties peerProperties = getEndPointProperties("peer", peerName);
        peerProperties.put("grpc.NettyChannelBuilderOption.maxInboundMessageSize", 9000000);
        Peer peer = hfClient.newPeer(peerName, getGRPCUrl("peer", peerName), peerProperties);
        channel.joinPeer(peer, createPeerOptions().setPeerRoles(EnumSet.of(Peer.PeerRole.ENDORSING_PEER, Peer.PeerRole.LEDGER_QUERY, Peer.PeerRole.CHAINCODE_QUERY, Peer.PeerRole.EVENT_SOURCE))); //Default is all roles.
    }

    CompletableFuture<BlockEvent.TransactionEvent> lifecycleApproveChaincodeDefinitionForMyOrg(HFClient client, Channel channel,
                                                                                               Collection<Peer> peers, long sequence,
                                                                                               String chaincodeName, String chaincodeVersion, LifecycleChaincodeEndorsementPolicy chaincodeEndorsementPolicy, ChaincodeCollectionConfiguration chaincodeCollectionConfiguration, boolean initRequired, String org1ChaincodePackageID) throws InvalidArgumentException, ProposalException {

        LifecycleApproveChaincodeDefinitionForMyOrgRequest lifecycleApproveChaincodeDefinitionForMyOrgRequest = client.newLifecycleApproveChaincodeDefinitionForMyOrgRequest();
        lifecycleApproveChaincodeDefinitionForMyOrgRequest.setSequence(sequence);
        lifecycleApproveChaincodeDefinitionForMyOrgRequest.setChaincodeName(chaincodeName);
        lifecycleApproveChaincodeDefinitionForMyOrgRequest.setChaincodeVersion(chaincodeVersion);
        lifecycleApproveChaincodeDefinitionForMyOrgRequest.setInitRequired(initRequired);

        if (null != chaincodeCollectionConfiguration) {
            lifecycleApproveChaincodeDefinitionForMyOrgRequest.setChaincodeCollectionConfiguration(chaincodeCollectionConfiguration);
        }

        if (null != chaincodeEndorsementPolicy) {
            lifecycleApproveChaincodeDefinitionForMyOrgRequest.setChaincodeEndorsementPolicy(chaincodeEndorsementPolicy);
        }

        lifecycleApproveChaincodeDefinitionForMyOrgRequest.setPackageId(org1ChaincodePackageID);

        Collection<LifecycleApproveChaincodeDefinitionForMyOrgProposalResponse> lifecycleApproveChaincodeDefinitionForMyOrgProposalResponse = channel.sendLifecycleApproveChaincodeDefinitionForMyOrgProposal(lifecycleApproveChaincodeDefinitionForMyOrgRequest,
                peers);

        return channel.sendTransaction(lifecycleApproveChaincodeDefinitionForMyOrgProposalResponse);

    }


    public void chaincodeCreate(HFClient hfClient, Channel channel, String chaincodeName, String chaincodeVersion) throws IOException, InvalidArgumentException, ChaincodeEndorsementPolicyParseException, ProposalException, InterruptedException, ExecutionException, TimeoutException {
        Collection<Peer> peers = channel.getPeers();

//        verifyNoInstalledChaincodes(hfClient, peers);

//        Thread.sleep(100000L);

        LifecycleChaincodePackage lifecycleChaincodePackage = LifecycleChaincodePackage.fromSource("foochaincode", Paths.get("../../chaincode/gocc/sample1"),
                TransactionRequest.Type.GO_LANG,"github.com/example_cc", null);

        assertEquals("foochaincode", lifecycleChaincodePackage.getLabel()); // what we expect ?
        assertEquals(TransactionRequest.Type.GO_LANG, lifecycleChaincodePackage.getType());
        assertEquals("github.com/example_cc", lifecycleChaincodePackage.getPath());

        LifecycleChaincodeEndorsementPolicy chaincodeEndorsementPolicy = LifecycleChaincodeEndorsementPolicy.fromSignaturePolicyYamlFile(Paths.get(
                "../../","/first-network/foochannelchaincodeendorsementpolicy.yaml"));

        LifecycleInstallChaincodeRequest installProposalRequest = hfClient.newLifecycleInstallChaincodeRequest();
        installProposalRequest.setLifecycleChaincodePackage(lifecycleChaincodePackage);
        installProposalRequest.setProposalWaitTime(120000L);


        Collection<LifecycleInstallChaincodeProposalResponse> responses = hfClient.sendLifecycleInstallChaincodeRequest(installProposalRequest, peers);

        Collection<ProposalResponse> successful = new LinkedList<>();
        Collection<ProposalResponse> failed = new LinkedList<>();
        String packageID = null;
        for (LifecycleInstallChaincodeProposalResponse response : responses) {
            if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                out("Successful install proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                successful.add(response);
                if (packageID == null) {
                    packageID = response.getPackageId();
                    assertNotNull(format("Hashcode came back as null from peer: %s ", response.getPeer()), packageID);
                } else {
                    assertEquals("Miss match on what the peers returned back as the packageID", packageID, response.getPackageId());
                }
            } else {
                out(response.getMessage());
                failed.add(response);
            }
        }

        out(packageID);
        assertTrue(packageID.contains("foochaincode"));
        out(lifecycleChaincodePackage.getLabel());

        final QueryLifecycleQueryChaincodeDefinitionRequest queryLifecycleQueryChaincodeDefinitionRequest = hfClient.newQueryLifecycleQueryChaincodeDefinitionRequest();
        queryLifecycleQueryChaincodeDefinitionRequest.setChaincodeName(chaincodeName);
        long sequence = -1L;
        Collection<LifecycleQueryChaincodeDefinitionProposalResponse> firstQueryDefininitions = channel.lifecycleQueryChaincodeDefinition(queryLifecycleQueryChaincodeDefinitionRequest, peers);
        for (LifecycleQueryChaincodeDefinitionProposalResponse firstDefinition : firstQueryDefininitions) {
            if (firstDefinition.getStatus() == ProposalResponse.Status.SUCCESS) {
                sequence = firstDefinition.getSequence() + 1L; //Need to bump it up to the next.
                break;
            } else { //Failed but why?
                if (404 == firstDefinition.getChaincodeActionResponseStatus()) {
                    // not found .. done set sequence to 1;
                    sequence = 1;
                    break;
                }
            }
        }
        Peer anPeer = peers.iterator().next();
        out(anPeer.getName());
        BlockEvent.TransactionEvent transactionEvent = lifecycleApproveChaincodeDefinitionForMyOrg(hfClient, channel,
                peers,  //support approve on multiple peers but really today only need one. Go with minimum.
                    sequence, chaincodeName, chaincodeVersion, chaincodeEndorsementPolicy, null, true, packageID)
                    .get(1, TimeUnit.SECONDS);
    }

    public void addAnchorPeer(Channel channel, User admin, HFClient hfClient) throws Exception {
        //         add anchor peer
        Channel.AnchorPeersConfigUpdateResult configUpdateAnchorPeers =
                channel.getConfigUpdateAnchorPeers(
                        channel.getPeers().iterator().next(),
                        admin,
                        Arrays.asList("peer0.org1.example.com:21000"),
                        null);

        channel.updateChannelConfiguration(configUpdateAnchorPeers.getUpdateChannelConfiguration(),
                hfClient.getUpdateChannelConfigurationSignature(configUpdateAnchorPeers.getUpdateChannelConfiguration(), admin));

        Thread.sleep(3000);
    }


    public void createChannel() throws Exception {
        HFClient hfClient = HFClient.createNewInstance();
        hfClient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
        User admin = EnrollAdmin.admins.get("Org1");
        hfClient.setUserContext(admin);
        Channel fooChannel;
        try {
            fooChannel = createChannel("foochannel", hfClient, admin, "org1.example.com");
        } catch (TransactionException e){
            // channel has been set up
            out("channel has been set up");
            fooChannel = getChannel(hfClient, "foochannel", "org1.example.com");
        }
//        Channel fooChannel = getChannel(hfClient, "foochannel", "org1.example.com");
        System.out.println(fooChannel.getPeers().size());
        for (int i = 0; i < 10; i++) {
            try {
                peerJoinChannel(hfClient, fooChannel, "peer" + i + ".org1.example.com");
            } catch (ProposalException e) {
                out("peer" + i + ".org1.example.com has joined channel");
                Properties peerProperties = getEndPointProperties("peer", "peer"+i+"."+"org1.example.com");
                peerProperties.put("grpc.NettyChannelBuilderOption.maxInboundMessageSize", 9000000);
                Peer peer = hfClient.newPeer("peer"+i+"."+"org1.example.com", getGRPCUrl("peer", "peer"+i+"."+"org1.example.com"), peerProperties);
                fooChannel.addPeer(peer);
            }
        }
//
//        addAnchorPeer(fooChannel, admin, hfClient);


//        admin = EnrollAdmin.admins.get("Org2");
//        hfClient.setUserContext(admin);
//        System.out.println(fooChannel.getPeers().size());
//        for (int i = 0; i < 10; i++) {
//            try {
//                peerJoinChannel(hfClient, fooChannel, "peer" + i + ".org2.example.com");
//            } catch (ProposalException e) {
//                out("peer" + i + ".org2.example.com has joined channel");
//                Properties peerProperties = getEndPointProperties("peer", "peer"+i+"."+"org2.example.com");
//                peerProperties.put("grpc.NettyChannelBuilderOption.maxInboundMessageSize", 9000000);
//                Peer peer = hfClient.newPeer("peer"+i+"."+"org2.example.com", getGRPCUrl("peer", "peer"+i+"."+"org2.example.com"), peerProperties);
//                fooChannel.addPeer(peer);
//            }
//        }
//        System.out.print(fooChannel.getPeers());

        admin = EnrollAdmin.admins.get("Org1");
        hfClient.setUserContext(admin);
        chaincodeCreate(hfClient, fooChannel,"foochaincode", "1.0");

//        admin = EnrollAdmin.admins.get("Org2");
//        hfClient.setUserContext(admin);
//        Channel barChannel = createChannel("barchannel", hfClient, admin,"peer0.org2.example.com");
//
//        for (int i=1;i<10;i++) {
//            peerJoinChannel(hfClient, barChannel, "peer"+i+".org2.example.com");
//        }
//        admin = EnrollAdmin.admins.get("Org3");
//        hfClient.setUserContext(admin);
//        for (int i=0;i<10;i++) {
//            peerJoinChannel(hfClient, barChannel, "peer"+i+".org3.example.com");
//        }
    }
}
