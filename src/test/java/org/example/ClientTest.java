/*
SPDX-License-Identifier: Apache-2.0
*/

package org.example;

import org.junit.Test;

public class ClientTest {

	@Test
	public void testFabCar() throws Exception {
		String org = "org2";
		EnrollAdmin.main(org);
		ClientApp clientApp = new ClientApp(RegisterUser.main(org));
		clientApp.run(org);

	}
}
