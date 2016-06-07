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


}
