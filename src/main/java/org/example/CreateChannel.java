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

    public void peerJoinChannel(HFClient hfClient, Channel channel, Collection<Peer> peerOrg2, String peerName) throws ProposalException, InvalidArgumentException {
        Properties peerProperties = getEndPointProperties("peer", peerName);
        peerProperties.put("grpc.NettyChannelBuilderOption.maxInboundMessageSize", 9000000);
        Peer peer = hfClient.newPeer(peerName, getGRPCUrl("peer", peerName), peerProperties);
        channel.joinPeer(peer, createPeerOptions().setPeerRoles(EnumSet.of(Peer.PeerRole.ENDORSING_PEER, Peer.PeerRole.LEDGER_QUERY, Peer.PeerRole.CHAINCODE_QUERY, Peer.PeerRole.EVENT_SOURCE))); //Default is all roles.
        peerOrg2.add(peer);
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

    // Lifecycle Queries to used to verify code...

    private void verifyByCheckCommitReadinessStatus(HFClient client, Channel channel, long definitionSequence, String chaincodeName,
                                                    String chaincodeVersion, LifecycleChaincodeEndorsementPolicy chaincodeEndorsementPolicy,
                                                    ChaincodeCollectionConfiguration chaincodeCollectionConfiguration, boolean initRequired, Collection<Peer> org1MyPeers,
                                                    Set<String> expectedApproved, Set<String> expectedUnApproved) throws InvalidArgumentException, ProposalException {
        LifecycleCheckCommitReadinessRequest lifecycleCheckCommitReadinessRequest = client.newLifecycleSimulateCommitChaincodeDefinitionRequest();
        lifecycleCheckCommitReadinessRequest.setSequence(definitionSequence);
        lifecycleCheckCommitReadinessRequest.setChaincodeName(chaincodeName);
        lifecycleCheckCommitReadinessRequest.setChaincodeVersion(chaincodeVersion);
        if (null != chaincodeEndorsementPolicy) {
            lifecycleCheckCommitReadinessRequest.setChaincodeEndorsementPolicy(chaincodeEndorsementPolicy);
        }
        if (null != chaincodeCollectionConfiguration) {
            lifecycleCheckCommitReadinessRequest.setChaincodeCollectionConfiguration(chaincodeCollectionConfiguration);
        }
        lifecycleCheckCommitReadinessRequest.setInitRequired(initRequired);

        Collection<LifecycleCheckCommitReadinessProposalResponse> lifecycleSimulateCommitChaincodeDefinitionProposalResponse = channel.sendLifecycleCheckCommitReadinessRequest(lifecycleCheckCommitReadinessRequest, org1MyPeers);
        for (LifecycleCheckCommitReadinessProposalResponse resp : lifecycleSimulateCommitChaincodeDefinitionProposalResponse) {
            final Peer peer = resp.getPeer();
            assertEquals(ChaincodeResponse.Status.SUCCESS, resp.getStatus());
            assertEquals(format("Approved orgs failed on %s", peer), expectedApproved, resp.getApprovedOrgs());
            assertEquals(format("UnApproved orgs failed on %s", peer), expectedUnApproved, resp.getUnApprovedOrgs());
        }
    }

    CompletableFuture<BlockEvent.TransactionEvent> executeChaincode(HFClient client, User userContext, Channel channel, String fcn, Boolean doInit, String chaincodeName, TransactionRequest.Type chaincodeType, String... args) throws InvalidArgumentException, ProposalException {

        final ExecutionException[] executionExceptions = new ExecutionException[1];

        Collection<ProposalResponse> successful = new LinkedList<>();
        Collection<ProposalResponse> failed = new LinkedList<>();

        TransactionProposalRequest transactionProposalRequest = client.newTransactionProposalRequest();
        transactionProposalRequest.setChaincodeName(chaincodeName);
        transactionProposalRequest.setChaincodeLanguage(chaincodeType);
        transactionProposalRequest.setUserContext(userContext);

        transactionProposalRequest.setFcn(fcn);
        transactionProposalRequest.setProposalWaitTime(120000L);
        transactionProposalRequest.setArgs(args);
        if (null != doInit) {
            transactionProposalRequest.setInit(doInit);
        }

        //  Collection<ProposalResponse> transactionPropResp = channel.sendTransactionProposalToEndorsers(transactionProposalRequest);
        Collection<ProposalResponse> transactionPropResp = channel.sendTransactionProposal(transactionProposalRequest, channel.getPeers());
        for (ProposalResponse response : transactionPropResp) {
            if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                out("Successful transaction proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                successful.add(response);
            } else {
                failed.add(response);
            }
        }

        out("Received %d transaction proposal responses. Successful+verified: %d . Failed: %d",
                transactionPropResp.size(), successful.size(), failed.size());
        if (failed.size() > 0) {
            ProposalResponse firstTransactionProposalResponse = failed.iterator().next();
            fail("Not enough endorsers for executeChaincode(move a,b,100):" + failed.size() + " endorser error: " +
                    firstTransactionProposalResponse.getMessage() +
                    ". Was verified: " + firstTransactionProposalResponse.isVerified());
        }
        out("Successfully received transaction proposal responses.");

        //  System.exit(10);

        ////////////////////////////
        // Send Transaction Transaction to orderer
        out("Sending chaincode transaction(move a,b,100) to orderer.");
        return channel.sendTransaction(successful);

    }

    private void verifyByQueryChaincodeDefinition(HFClient client, Channel channel, String chaincodeName, Collection<Peer> peers, long expectedSequence, boolean expectedInitRequired, byte[] expectedValidationParameter,
                                                  ChaincodeCollectionConfiguration expectedChaincodeCollectionConfiguration) throws ProposalException, InvalidArgumentException, ChaincodeCollectionConfigurationException {

        final QueryLifecycleQueryChaincodeDefinitionRequest queryLifecycleQueryChaincodeDefinitionRequest = client.newQueryLifecycleQueryChaincodeDefinitionRequest();
        queryLifecycleQueryChaincodeDefinitionRequest.setChaincodeName(chaincodeName);

        Collection<LifecycleQueryChaincodeDefinitionProposalResponse> queryChaincodeDefinitionProposalResponses = channel.lifecycleQueryChaincodeDefinition(queryLifecycleQueryChaincodeDefinitionRequest, peers);

        assertNotNull(queryChaincodeDefinitionProposalResponses);
        assertEquals(peers.size(), queryChaincodeDefinitionProposalResponses.size());
        for (LifecycleQueryChaincodeDefinitionProposalResponse response : queryChaincodeDefinitionProposalResponses) {
            assertEquals(ChaincodeResponse.Status.SUCCESS, response.getStatus());
            assertEquals(expectedSequence, response.getSequence());
            if (expectedValidationParameter != null) {
                byte[] validationParameter = response.getValidationParameter();
                assertNotNull(validationParameter);
                assertArrayEquals(expectedValidationParameter, validationParameter);
            }

            if (null != expectedChaincodeCollectionConfiguration) {
                final ChaincodeCollectionConfiguration chaincodeCollectionConfiguration = response.getChaincodeCollectionConfiguration();
                assertNotNull(chaincodeCollectionConfiguration);
                assertArrayEquals(expectedChaincodeCollectionConfiguration.getAsBytes(), chaincodeCollectionConfiguration.getAsBytes());
            }

            ChaincodeCollectionConfiguration collections = response.getChaincodeCollectionConfiguration();
            assertEquals(expectedInitRequired, response.getInitRequired());
            assertEquals("escc", response.getEndorsementPlugin());
            assertEquals("vscc", response.getValidationPlugin());
        }
    }

    private void verifyByQueryInstalledChaincode(HFClient client, Collection<Peer> peers, String packageId, String expectedLabel) throws ProposalException, InvalidArgumentException {

        final LifecycleQueryInstalledChaincodeRequest lifecycleQueryInstalledChaincodeRequest = client.newLifecycleQueryInstalledChaincodeRequest();
        lifecycleQueryInstalledChaincodeRequest.setPackageID(packageId);

        Collection<LifecycleQueryInstalledChaincodeProposalResponse> responses = client.sendLifecycleQueryInstalledChaincode(lifecycleQueryInstalledChaincodeRequest, peers);
        assertNotNull(responses);
        assertEquals("responses not same as peers", peers.size(), responses.size());

        for (LifecycleQueryInstalledChaincodeProposalResponse response : responses) {
            assertEquals(ChaincodeResponse.Status.SUCCESS, response.getStatus());
            String peerName = response.getPeer().getName();
            assertEquals(format("Peer %s returned back bad status code", peerName), ChaincodeResponse.Status.SUCCESS, response.getStatus());
            assertEquals(format("Peer %s returned back different label", peerName), expectedLabel, response.getLabel());

        }
    }

    private void verifyByQueryInstalledChaincodes(HFClient client, Collection<Peer> peers, String excpectedChaincodeLabel, String excpectedPackageId) throws ProposalException, InvalidArgumentException {

        Collection<LifecycleQueryInstalledChaincodesProposalResponse> results = client.sendLifecycleQueryInstalledChaincodes(client.newLifecycleQueryInstalledChaincodesRequest(), peers);
        assertNotNull(results);
        assertEquals(peers.size(), results.size());

        for (LifecycleQueryInstalledChaincodesProposalResponse peerResults : results) {
            boolean found = false;
            final String peerName = peerResults.getPeer().getName();

            assertEquals(format("Peer returned back bad status %s", peerName), peerResults.getStatus(), ChaincodeResponse.Status.SUCCESS);

            for (LifecycleQueryInstalledChaincodesProposalResponse.LifecycleQueryInstalledChaincodesResult lifecycleQueryInstalledChaincodesResult : peerResults.getLifecycleQueryInstalledChaincodesResult()) {
                out(lifecycleQueryInstalledChaincodesResult.getPackageId());
                if (excpectedPackageId.equals(lifecycleQueryInstalledChaincodesResult.getPackageId())) {
                    assertEquals(format("Peer %s had chaincode lable mismatch", peerName), excpectedChaincodeLabel, lifecycleQueryInstalledChaincodesResult.getLabel());
                    found = true;
                    break;
                }

            }
            assertTrue(format("Chaincode label %s, packageId %s not found on peer %s ", excpectedChaincodeLabel, excpectedPackageId, peerName), found);

        }
        return;

    }


    private CompletableFuture<BlockEvent.TransactionEvent> commitChaincodeDefinitionRequest(HFClient client, Channel channel, long definitionSequence, String chaincodeName, String chaincodeVersion,
                                                                                            LifecycleChaincodeEndorsementPolicy chaincodeEndorsementPolicy,
                                                                                            ChaincodeCollectionConfiguration chaincodeCollectionConfiguration,
                                                                                            boolean initRequired, Collection<Peer> endorsingPeers) throws ProposalException, InvalidArgumentException, InterruptedException, ExecutionException, TimeoutException {
        LifecycleCommitChaincodeDefinitionRequest lifecycleCommitChaincodeDefinitionRequest = client.newLifecycleCommitChaincodeDefinitionRequest();

        lifecycleCommitChaincodeDefinitionRequest.setSequence(definitionSequence);
        lifecycleCommitChaincodeDefinitionRequest.setChaincodeName(chaincodeName);
        lifecycleCommitChaincodeDefinitionRequest.setChaincodeVersion(chaincodeVersion);
        if (null != chaincodeEndorsementPolicy) {
            lifecycleCommitChaincodeDefinitionRequest.setChaincodeEndorsementPolicy(chaincodeEndorsementPolicy);
        }
        if (null != chaincodeCollectionConfiguration) {
            lifecycleCommitChaincodeDefinitionRequest.setChaincodeCollectionConfiguration(chaincodeCollectionConfiguration);
        }
        lifecycleCommitChaincodeDefinitionRequest.setInitRequired(initRequired);

        Collection<LifecycleCommitChaincodeDefinitionProposalResponse> lifecycleCommitChaincodeDefinitionProposalResponses = channel.sendLifecycleCommitChaincodeDefinitionProposal(lifecycleCommitChaincodeDefinitionRequest,
                endorsingPeers);

        for (LifecycleCommitChaincodeDefinitionProposalResponse resp : lifecycleCommitChaincodeDefinitionProposalResponses) {

            final Peer peer = resp.getPeer();
            assertEquals(format("%s had unexpected status.", peer.toString()), ChaincodeResponse.Status.SUCCESS, resp.getStatus());
            assertTrue(format("%s not verified.", peer.toString()), resp.isVerified());
        }

        return channel.sendTransaction(lifecycleCommitChaincodeDefinitionProposalResponses);

    }

    public void chaincodeCreate(HFClient hfClient, Channel channel, String chaincodeName, String chaincodeVersion,
                                Collection<Peer> peerOrg1, Collection<Peer> peerOrg2) throws IOException, InvalidArgumentException, ChaincodeEndorsementPolicyParseException, ProposalException, InterruptedException, ExecutionException, TimeoutException, ChaincodeCollectionConfigurationException {
        Collection<Peer> peers = channel.getPeers();

//        verifyNoInstalledChaincodes(hfClient, peers);

//        Thread.sleep(100000L);

        LifecycleChaincodePackage lifecycleChaincodePackage = LifecycleChaincodePackage.fromSource(chaincodeName, Paths.get("../../chaincode/gocc/sample1"),
                TransactionRequest.Type.GO_LANG,"github.com/example_cc", Paths.get("meta-infs/end2endit"));

        assertEquals(chaincodeName, lifecycleChaincodePackage.getLabel()); // what we expect ?
        assertEquals(TransactionRequest.Type.GO_LANG, lifecycleChaincodePackage.getType());
        assertEquals("github.com/example_cc", lifecycleChaincodePackage.getPath());

        LifecycleChaincodeEndorsementPolicy chaincodeEndorsementPolicy = LifecycleChaincodeEndorsementPolicy.fromSignaturePolicyYamlFile(Paths.get(
                "../../","/first-network/foochannelchaincodeendorsementpolicy.yaml"));

        LifecycleInstallChaincodeRequest installProposalRequest = hfClient.newLifecycleInstallChaincodeRequest();
        installProposalRequest.setLifecycleChaincodePackage(lifecycleChaincodePackage);
        installProposalRequest.setProposalWaitTime(120000L);


        Collection<LifecycleInstallChaincodeProposalResponse> responses = hfClient.sendLifecycleInstallChaincodeRequest(installProposalRequest, peerOrg1);

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
        assertTrue(packageID.contains(chaincodeName));
        out(lifecycleChaincodePackage.getLabel());

        verifyByQueryInstalledChaincodes(hfClient, peerOrg1, chaincodeName, packageID);
        // another query test if it works
        verifyByQueryInstalledChaincode(hfClient, peerOrg1, packageID, chaincodeName);

        final QueryLifecycleQueryChaincodeDefinitionRequest queryLifecycleQueryChaincodeDefinitionRequest = hfClient.newQueryLifecycleQueryChaincodeDefinitionRequest();
        queryLifecycleQueryChaincodeDefinitionRequest.setChaincodeName(chaincodeName);

        long sequence = -1L;
        Collection<LifecycleQueryChaincodeDefinitionProposalResponse> firstQueryDefininitions = channel.lifecycleQueryChaincodeDefinition(queryLifecycleQueryChaincodeDefinitionRequest, peers);
        for (LifecycleQueryChaincodeDefinitionProposalResponse firstDefinition : firstQueryDefininitions) {
            if (firstDefinition.getStatus() == ProposalResponse.Status.SUCCESS) {
                sequence = firstDefinition.getSequence() + 1L; //Need to bump it up to the next.
                break;
            } else { //Failed but why?
                out(firstDefinition.getMessage());
                if (404 == firstDefinition.getChaincodeActionResponseStatus()) {
                    // not found .. done set sequence to 1;
                    sequence = 1;
                    break;
                }
            }
        }
        Peer anPeer = peerOrg1.iterator().next();
        out(anPeer.getName());
        BlockEvent.TransactionEvent transactionEvent = lifecycleApproveChaincodeDefinitionForMyOrg(hfClient, channel,
                peerOrg1,  //support approve on multiple peers but really today only need one. Go with minimum.
                    sequence, chaincodeName, chaincodeVersion, chaincodeEndorsementPolicy, null, true, packageID)
                    .get(100, TimeUnit.SECONDS);

        assertTrue(transactionEvent.isValid());

        verifyByCheckCommitReadinessStatus(hfClient, channel, sequence, chaincodeName, chaincodeVersion,
                chaincodeEndorsementPolicy, null, true, peers,
                new HashSet<>(Arrays.asList("Org1MSP")), // Approved
                new HashSet<>(Arrays.asList("Org2MSP"))); // Un approved.

        //Serialize these to bytes to give to other organizations.
        byte[] chaincodePackageBtyes = lifecycleChaincodePackage.getAsBytes();
        final byte[] chaincodeEndorsementPolicyAsBytes = chaincodeEndorsementPolicy == null ? null : chaincodeEndorsementPolicy.getSerializedPolicyBytes();

        transactionEvent = commitChaincodeDefinitionRequest(hfClient, channel, sequence, chaincodeName, chaincodeVersion,
                chaincodeEndorsementPolicy, null, true, peers)
                .get(100, TimeUnit.SECONDS);

        assertTrue(transactionEvent.isValid());

        verifyByQueryChaincodeDefinition(hfClient, channel, chaincodeName, peers, sequence, true,
                chaincodeEndorsementPolicyAsBytes, null);

        transactionEvent = executeChaincode(hfClient, EnrollAdmin.admins.get("Org1"), channel, "init",
                true, // doInit don't even specify it has it should default to false
                chaincodeName, TransactionRequest.Type.GO_LANG, "a,", "100", "b", "300").get(100, TimeUnit.SECONDS);
        assertTrue(transactionEvent.isValid());

    }

    public void addAnchorPeer(Channel channel, User admin, HFClient hfClient, String orgSeq) throws Exception {
        //         add anchor peer
        Channel.AnchorPeersConfigUpdateResult configUpdateAnchorPeers =
                channel.getConfigUpdateAnchorPeers(
                        channel.getPeers().iterator().next(),
                        admin,
                        Arrays.asList("peer0.org"+orgSeq+".example.com:2"+orgSeq+"000"),
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
        Collection<Peer> peerOrg1 = new LinkedList<>();
//        Channel fooChannel = getChannel(hfClient, "foochannel", "org1.example.com");
        System.out.println(fooChannel.getPeers().size());
        for (int i = 0; i < 10; i++) {
            try {
                peerJoinChannel(hfClient, fooChannel, peerOrg1, "peer" + i + ".org1.example.com");
            } catch (ProposalException e) {
                out("peer" + i + ".org1.example.com has joined channel");
                Properties peerProperties = getEndPointProperties("peer", "peer"+i+"."+"org1.example.com");
                peerProperties.put("grpc.NettyChannelBuilderOption.maxInboundMessageSize", 9000000);
                Peer peer = hfClient.newPeer("peer"+i+"."+"org1.example.com", getGRPCUrl("peer", "peer"+i+"."+"org1.example.com"), peerProperties);
                fooChannel.addPeer(peer);
                peerOrg1.add(peer);
            }
        }
//
        addAnchorPeer(fooChannel, admin, hfClient,"1");

        Collection<Peer> peerOrg2 = new LinkedList<>();
        admin = EnrollAdmin.admins.get("Org2");
        hfClient.setUserContext(admin);
        System.out.println(fooChannel.getPeers().size());
        for (int i = 0; i < 10; i++) {
            try {
                peerJoinChannel(hfClient, fooChannel, peerOrg2, "peer" + i + ".org2.example.com");
            } catch (ProposalException e) {
                out("peer" + i + ".org2.example.com has joined channel");
                Properties peerProperties = getEndPointProperties("peer", "peer"+i+"."+"org2.example.com");
                peerProperties.put("grpc.NettyChannelBuilderOption.maxInboundMessageSize", 9000000);
                Peer peer = hfClient.newPeer("peer"+i+"."+"org2.example.com", getGRPCUrl("peer", "peer"+i+"."+"org2.example.com"), peerProperties);
                fooChannel.addPeer(peer);
                peerOrg2.add(peer);
            }
        }
        addAnchorPeer(fooChannel, admin, hfClient,"2");

        System.out.print(fooChannel.getPeers());

        admin = EnrollAdmin.admins.get("Org1");
        hfClient.setUserContext(admin);
        chaincodeCreate(hfClient, fooChannel,"foochaincode", "1.0",peerOrg1,peerOrg2);

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
