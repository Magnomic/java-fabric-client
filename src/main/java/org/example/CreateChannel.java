package org.example;

import org.hyperledger.fabric.gateway.Contract;
import org.hyperledger.fabric.gateway.Gateway;
import org.hyperledger.fabric.gateway.Network;
import org.hyperledger.fabric.sdk.*;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.exception.TransactionException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.security.CryptoSuiteFactory;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.EnumSet;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import static org.hyperledger.fabric.sdk.Channel.PeerOptions.createPeerOptions;

/**
 * Created by Du on 2020/7/2.
 */
public class CreateChannel {

    User user;

    public CreateChannel(User admin){
        this.user = admin;
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

        File cert = Paths.get("/", "crypto-config/ordererOrganizations".replace("orderer", type), domainName, type + "s",
                name, "tls/server.crt").toFile();
        if (!cert.exists()) {
            throw new RuntimeException(String.format("Missing cert file for: %s. Could not find at location: %s", name,
                    cert.getAbsolutePath()));
        }

        File clientCert;
        File clientKey;
        if ("orderer".equals(type)) {
            clientCert = Paths.get("/", "crypto-config/ordererOrganizations/example.com/users/Admin@example.com/tls/client.crt").toFile();

            clientKey = Paths.get("/", "crypto-config/ordererOrganizations/example.com/users/Admin@example.com/tls/client.key").toFile();
        } else {
            clientCert = Paths.get("/", "crypto-config/peerOrganizations/", domainName, "users/User1@" + domainName, "tls/client.crt").toFile();
            clientKey = Paths.get("/", "crypto-config/peerOrganizations/", domainName, "users/User1@" + domainName, "tls/client.key").toFile();
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



    public void createChannel() throws IOException, InvalidArgumentException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException, CryptoException, TransactionException, ProposalException {
        HFClient hfClient = HFClient.createNewInstance();
        hfClient.setUserContext(user);
        Properties ordererProperties = getEndPointProperties("orderer", "orderer.example.com");
        ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveTime", new Object[] {5L, TimeUnit.MINUTES});
        ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveTimeout", new Object[] {8L, TimeUnit.SECONDS});
        ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveWithoutCalls", new Object[] {true});
        Orderer orderer = hfClient.newOrderer("orderer.example.com","grpcs://localhost:18000",ordererProperties);
        File configTxFile = Paths.get("channel-artifact","fooChannel.tx").toFile();
        ChannelConfiguration configuration = new ChannelConfiguration(configTxFile);
        Channel newChannel = hfClient.newChannel("foochannel", orderer, configuration, hfClient.getChannelConfigurationSignature(configuration, user));
        Properties peerProperties = getEndPointProperties("peer", "peer0.org2.example.com");
        peerProperties.put("grpc.NettyChannelBuilderOption.maxInboundMessageSize", 9000000);
        Peer peer = hfClient.newPeer("peer0.org2.example.com", "grpcs://localhost:22000", peerProperties);
        newChannel.joinPeer(peer, createPeerOptions().setPeerRoles(EnumSet.of(Peer.PeerRole.ENDORSING_PEER, Peer.PeerRole.LEDGER_QUERY, Peer.PeerRole.CHAINCODE_QUERY, Peer.PeerRole.EVENT_SOURCE))); //Default is all roles.
        newChannel.addOrderer(orderer);
        newChannel.initialize();
        byte[] serializedChannelBytes = newChannel.serializeChannel();
    }
}
