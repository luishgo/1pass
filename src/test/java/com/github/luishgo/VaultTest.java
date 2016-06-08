package com.github.luishgo;

import java.io.FileNotFoundException;

import org.junit.Test;

import junit.framework.Assert;

public class VaultTest {
	
	@Test public void shouldOpenVault() throws FileNotFoundException {
		new Vault("src/test/resources/demo.agilekeychain");
	}
	
	@Test(expected=FileNotFoundException.class) public void shouldNotOpenVault() throws FileNotFoundException {
		new Vault("crap");
	}
	
	@Test public void shouldReadEncryptionKeys() throws FileNotFoundException {
		Vault vault = new Vault("src/test/resources/demo.agilekeychain");
		Assert.assertEquals(2, vault.keys.size());
	}

	@Test public void shouldReadItems() throws FileNotFoundException {
		Vault vault = new Vault("src/test/resources/demo.agilekeychain");
		Assert.assertEquals(1, vault.getItems().size());
	}
	
	@Test public void shouldDecryptItem() throws FileNotFoundException {
		Vault vault = new Vault("src/test/resources/demo.agilekeychain");
		vault.unlock("demo");
		Assert.assertEquals("{\"password\":\"teste\",\"sections\":[{\"title\":\"Related Items\",\"name\":\"linked items\"}]}", vault.getDecryptedDataFrom("teste"));
	}
	
	@Test public void shouldEncryptItem() throws FileNotFoundException {
		Vault vault = new Vault("src/test/resources/demo.agilekeychain");
		vault.unlock("demo");
		String encodedPassword = "U2FsdGVkX188xHPQvxV+Ru9cydhl9bMRNhpu1MeVVANSHY/DJrpPdzDUGauLsUz1RQSAHgV5W8LjqZkHtn1JJNejePdjkdf0oD7Q74TqlueH0QT9Ab0eadyaN4GzkU3iEW/12jieg5LzaQ1hwK93Jw==";
		Assert.assertEquals(encodedPassword, vault.getEncryptedDataFrom("teste", "{\"password\":\"teste\",\"sections\":[{\"title\":\"Related Items\",\"name\":\"linked items\"}]}"));
	}
	


}
