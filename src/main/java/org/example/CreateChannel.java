package org.example;

import org.hyperledger.fabric.gateway.Contract;
import org.hyperledger.fabric.gateway.Gateway;
import org.hyperledger.fabric.gateway.Network;
import org.hyperledger.fabric.sdk.*;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.TransactionException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.security.CryptoSuiteFactory;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

/**
 * Created by Du on 2020/7/2.
 */
public class CreateChannel {

    User user;

    public CreateChannel(User admin){
        this.user = admin;
    }

    public Properties getEndPointProperties() {
        Properties ret = new Properties();

        String name = "orderer.example.com";

        final String domainName = "example.com";

        File cert = Paths.get("/", "crypto-config/ordererOrganizations", domainName, "orderers",
                "orderer.example.com", "tls/server.crt").toFile();
        if (!cert.exists()) {
            throw new RuntimeException(String.format("Missing cert file for: %s. Could not find at location: %s", name,
                    cert.getAbsolutePath()));
        }

        File clientCert;
        File clientKey;

        clientCert = Paths.get("/", "crypto-config/ordererOrganizations/example.com/users/Admin@example.com/tls/client.crt").toFile();

        clientKey = Paths.get("/", "crypto-config/ordererOrganizations/example.com/users/Admin@example.com/tls/client.key").toFile();


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



    public void createChannel() throws IOException, InvalidArgumentException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException, CryptoException, TransactionException {
        HFClient hfClient = HFClient.createNewInstance();
        hfClient.setUserContext(user);
        Properties ordererProperties = getEndPointProperties();
        ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveTime", new Object[] {5L, TimeUnit.MINUTES});
        ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveTimeout", new Object[] {8L, TimeUnit.SECONDS});
        ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveWithoutCalls", new Object[] {true});
        Orderer orderer = hfClient.newOrderer("orderer.example.com","grpcs://localhost:18000",ordererProperties);
        File configTxFile = Paths.get("channel-artifact","fooChannel.tx").toFile();
        ChannelConfiguration configuration = new ChannelConfiguration(configTxFile);
        Channel newChannel = hfClient.newChannel("foochannel", orderer, configuration, hfClient.getChannelConfigurationSignature(configuration, user));
    }
}
