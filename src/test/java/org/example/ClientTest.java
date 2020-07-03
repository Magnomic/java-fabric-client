/*
SPDX-License-Identifier: Apache-2.0
*/

package org.example;

import org.junit.Test;

public class ClientTest {

	@Test
	public void testFabCar() throws Exception {
		EnrollAdmin.main();
		ClientApp clientApp = new ClientApp(RegisterUser.main());
		clientApp.run();

	}
}
