/*
SPDX-License-Identifier: Apache-2.0
*/

package org.example;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;

import org.apache.commons.io.IOUtils;
import org.hyperledger.fabric.gateway.*;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.security.CryptoSuiteFactory;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;

import static org.example.EnrollAdmin.PRIVATE_KEY_ORG1;
import static org.example.EnrollAdmin.getPrivateKeyFromBytes;

public class RegisterUser {


	public static User main() throws Exception {

		// Create a CA client for interacting with the CA.
		Properties props = new Properties();
		props.put("pemFile",
			"../../first-network/crypto-config/peerOrganizations/org1.example.com/ca/ca.org1.example.com-cert.pem");
		props.put("allowAllHostNames", "true");
		HFCAClient caClient = HFCAClient.createNewInstance("https://localhost:19001", props);
		CryptoSuite cryptoSuite = CryptoSuiteFactory.getDefault().getCryptoSuite();
		caClient.setCryptoSuite(cryptoSuite);

		// Create a wallet for managing identities
		Wallet wallet = Wallets.newFileSystemWallet(Paths.get("wallet"));

		// Check to see if we've already enrolled the user.
		boolean userExists = wallet.get("user1") != null;
		if (userExists) {
			System.out.println("An identity for the user \"user1\" already exists in the wallet");
			return null;
		}

		userExists = wallet.get("admin") != null;
		if (!userExists) {
			System.out.println("\"admin\" needs to be enrolled and added to the wallet first");
			return null;
		}

		X509Identity adminIdentity = (X509Identity)wallet.get("admin");
		User admin = new User() {

			@Override
			public String getName() {
				return "admin";
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
				return "org1.department1";
			}

			@Override
			public Enrollment getEnrollment() {
				return new Enrollment() {

					@Override
					public PrivateKey getKey() {
						return adminIdentity.getPrivateKey();
					}

					@Override
					public String getCert() {
					    return Identities.toPemString(adminIdentity.getCertificate());
					}
				};
			}

			@Override
			public String getMspId() {
				return "Org1MSP";
			}

		};

		// Register the user, enroll the user, and import the new identity into the wallet.
		RegistrationRequest registrationRequest = new RegistrationRequest("user1");
		registrationRequest.setAffiliation("org1.department1");
		registrationRequest.setEnrollmentID("user1");
		String enrollmentSecret = caClient.register(registrationRequest, admin);
		Enrollment enrollment = caClient.enroll("user1", enrollmentSecret);
		Identity user = Identities.newX509Identity("Org1MSP", enrollment);
		wallet.put("user1", user);
		System.out.println("Successfully enrolled user \"user1\" and imported it into the wallet");
		return admin;
	}

}
