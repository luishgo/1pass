package com.github.luishgo;

import java.io.IOException;
import java.nio.file.Paths;

import org.junit.Test;

import junit.framework.Assert;

public class EncryptionKeysTest {

	@Test public void shouldReadEncryptionKeys() throws IOException {
		EncryptionKeys keys = EncryptionKeys.open(Paths.get("src/test/resources/demo.agilekeychain/data/default/encryptionKeys.js"));
		Assert.assertEquals(2, keys.keys.size());
	}
	
	@Test public void shouldGeneratePLIST() throws IOException {
		EncryptionKeys keys = EncryptionKeys.open(Paths.get("src/test/resources/demo.agilekeychain/data/default/encryptionKeys.js"));
		System.out.println(keys.toPLISTString());
	}
	
}
