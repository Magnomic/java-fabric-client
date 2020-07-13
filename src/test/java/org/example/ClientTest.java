/*
SPDX-License-Identifier: Apache-2.0
*/

package org.example;

import org.junit.Test;

public class ClientTest {

	@Test
	public void testFabCar() throws Exception {
		String org = "org2";
		EnrollAdmin.main();
		ClientApp clientApp = new ClientApp();
		clientApp.run(org);

	}
}
