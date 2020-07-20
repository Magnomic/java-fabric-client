/*
SPDX-License-Identifier: Apache-2.0
*/

package org.example;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.hyperledger.fabric.gateway.*;
import org.hyperledger.fabric.sdk.Peer;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.exception.TransactionException;

public class ClientApp{


	public void out(Object obj){
		System.out.println(obj);
	}

	public void run(String org) throws Exception {

		Long time = System.currentTimeMillis();
		out(System.currentTimeMillis()-time);
			// Load a file system based wallet for managing identities.
		Path walletPath = Paths.get("wallet");
		Wallet wallet = null;
		try {
			wallet = Wallets.newFileSystemWallet(walletPath);
		} catch (IOException e) {
			e.printStackTrace();
		}

		out(System.currentTimeMillis()-time);
		// load a CCP
		Path networkConfigPath = Paths.get("..", "..", "first-network", "my-connection.yaml");

		Gateway.Builder builder = Gateway.createBuilder();

//		CreateChannel createChannel = new CreateChannel();
//		createChannel.createChannel();

		try {
			builder.identity(wallet, "user1").networkConfig(networkConfigPath).discovery(true);
		} catch (IOException e) {
			e.printStackTrace();
		}
		for (int i=0;i<1000;i++) {
			Thread.sleep(1);
			CommitThread commitThread = new CommitThread(builder, Long.toString(System.currentTimeMillis()));
			commitThread.start();
		}
		Thread.sleep(2000*1000L);
	}
}
