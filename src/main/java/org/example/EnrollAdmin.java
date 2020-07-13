/*
SPDX-License-Identifier: Apache-2.0
*/

package org.example;

import java.io.*;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;

public class EnrollAdmin {

	public static Map<String, User> admins = new HashMap<>();
	public static String CERTIFICATE_ORG1 = "../../first-network/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/signcerts/Admin@org1.example.com-cert.pem";
	public static String CERTIFICATE_ORG2 = "../../first-network/crypto-config/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp/signcerts/Admin@org2.example.com-cert.pem";
	public static String CERTIFICATE_ORG3 = "../../first-network/crypto-config/peerOrganizations/org3.example.com/users/Admin@org3.example.com/msp/signcerts/Admin@org3.example.com-cert.pem";
	public static String PRIVATE_KEY_ORG1 = "../../first-network/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore/11f8f1c317d3322b229011847f15520932398326233d6f14d0aac04418e11aca_sk";
	public static String PRIVATE_KEY_ORG2 = "../../first-network/crypto-config/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp/keystore/99857fd10090f19f53870d094ea9098595f626dc57fd7476f25b423ed0080ef1_sk";
	public static String PRIVATE_KEY_ORG3 = "../../first-network/crypto-config/peerOrganizations/org3.example.com/users/Admin@org3.example.com/msp/keystore/ded8f8fb0b93d1f8d462c0336b4be5a2e76fb844d56da1bfbe037ff2f1c14a60_sk";

	static void createAdmin(String certificate, String privateKey, String org) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {

		String cert = new String(IOUtils.toByteArray(new FileInputStream(Paths.get(certificate).toFile())), "UTF-8");
		PrivateKey pk = getPrivateKeyFromBytes(IOUtils.toByteArray(new FileInputStream(Paths.get(privateKey).toFile())));

		admins.put(org, new User() {
			@Override
			public String getName() {
				return org+"Admin";
			}

			@Override
			public Set<String> getRoles() {
				return null;
			}

			@Override
			public String getAccount() {
				return null;
			}

			@Override
			public String getAffiliation() {
				return null;
			}

			@Override
			public Enrollment getEnrollment() {
				return new Enrollment() {
					@Override
					public PrivateKey getKey() {
						return pk;
					}

					@Override
					public String getCert() {
						return cert;
					}
				};
			}

			@Override
			public String getMspId() {
				return org+"MSP";
			}
		});
	}

	static PrivateKey getPrivateKeyFromBytes(byte[] data) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
		final Reader pemReader = new StringReader(new String(data));

		final PrivateKeyInfo pemPair;
		try (PEMParser pemParser = new PEMParser(pemReader)) {
			pemPair = (PrivateKeyInfo) pemParser.readObject();
		}
		Security.addProvider(new BouncyCastleProvider());
		PrivateKey privateKey = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getPrivateKey(pemPair);

		return privateKey;
	}

	public static void main() throws Exception {
		createAdmin(CERTIFICATE_ORG1, PRIVATE_KEY_ORG1, "Org1");
		createAdmin(CERTIFICATE_ORG2, PRIVATE_KEY_ORG2, "Org2");
		createAdmin(CERTIFICATE_ORG3, PRIVATE_KEY_ORG3, "Org3");
//		// Create a CA client for interacting with the CA.
//		Properties props = new Properties();
//		props.put("pemFile",
//			"/resources/peerOrganizations/org3.example.com/ca/ca.org3.example.com-cert.pem");
//		props.put("allowAllHostNames", "true");
//		HFCAClient caClient = HFCAClient.createNewInstance("https://localhost:19003", props);
//		CryptoSuite cryptoSuite = CryptoSuiteFactory.getDefault().getCryptoSuite();
//		caClient.setCryptoSuite(cryptoSuite);
//
//		// Create a wallet for managing identities
//		Wallet wallet = Wallet.createFileSystemWallet(Paths.get("wallet"));
//
//		// Check to see if we've already enrolled the admin user.
//		boolean adminExists = wallet.exists("admin");
//        if (adminExists) {
//            System.out.println("An identity for the admin user \"admin\" already exists in the wallet");
//            return;
//        }
//
//        // Enroll the admin user, and import the new identity into the wallet.
//        final EnrollmentRequest enrollmentRequestTLS = new EnrollmentRequest();
//        enrollmentRequestTLS.addHost("localhost");
//        enrollmentRequestTLS.setProfile("tls");
//        Enrollment enrollment = caClient.enroll("admin", "adminpw", enrollmentRequestTLS);
//        Identity user = Identity.createIdentity("Org3MSP", enrollment.getCert(), enrollment.getKey());
//        wallet.put("admin", user);
//		System.out.println("Successfully enrolled user \"admin\" and imported it into the wallet");
//
//		final EnrollmentRequest enrollmentRequestTLS1 = new EnrollmentRequest();
//		enrollmentRequestTLS.addHost("localhost");
//		enrollmentRequestTLS.setProfile("tls");

	}
}
