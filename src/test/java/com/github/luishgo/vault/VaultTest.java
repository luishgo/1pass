package com.github.luishgo.vault;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.Test;

import com.github.luishgo.vault.Vault;

import junit.framework.Assert;

public class VaultTest {
	
	@Test public void shouldOpenVault() throws IOException {
		Vault.open("src/test/resources/demo.agilekeychain");
	}
	
	@Test public void shouldCreateVault() throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Vault.create("src/test/resources/tmp.agilekeychain", "tmp");
		
		Vault vault = Vault.open("src/test/resources/tmp.agilekeychain");
		vault.unlock("tmp");
		
		try (Stream<Path> files = Files.walk(Paths.get("src/test/resources/tmp.agilekeychain"))) {
			files.sorted((p1, p2) -> Integer.compare(p2.toString().length(), p1.toString().length())).forEach(f -> {
				try {
					Files.deleteIfExists(f);
				} catch (IOException e) {
					e.printStackTrace();
				}
			});
		}
	}
	
	@Test(expected=FileNotFoundException.class) public void shouldNotOpenVault() throws IOException {
		Vault.open("crap");
	}
	
	@Test public void shouldListItemsData() throws IOException {
		Vault vault = Vault.open("src/test/resources/demo.agilekeychain");
		List<ItemData> itemsData = vault.getItemsData();
		Assert.assertEquals(1, itemsData.size());
		Assert.assertEquals("teste", itemsData.get(0).getTitle());
	}
	
	@Test public void shouldListItems() throws IOException {
		Vault vault = Vault.open("src/test/resources/demo.agilekeychain");
		List<Item> items = vault.getItems();
		Assert.assertEquals(1, items.size());
		Assert.assertEquals("teste", items.get(0).getTitle());
		Assert.assertEquals("SL5", items.get(0).getData().getSecurityLevel());
	}
	
	@Test public void shouldDecryptItem() throws IOException {
		Vault vault = Vault.open("src/test/resources/demo.agilekeychain");
		vault.unlock("demo");
		Assert.assertEquals("{\"password\":\"teste\",\"sections\":[{\"title\":\"Related Items\",\"name\":\"linked items\"}]}", vault.getDecryptedDataFrom("teste"));
	}
	
	@Test public void shouldEncryptItem() throws IOException {
		Vault vault = Vault.open("src/test/resources/demo.agilekeychain");
		vault.unlock("demo");
		String encodedPassword = "U2FsdGVkX188xHPQvxV+Ru9cydhl9bMRNhpu1MeVVANSHY/DJrpPdzDUGauLsUz1RQSAHgV5W8LjqZkHtn1JJNejePdjkdf0oD7Q74TqlueH0QT9Ab0eadyaN4GzkU3iEW/12jieg5LzaQ1hwK93Jw==";
		Assert.assertEquals(encodedPassword, vault.getEncryptedDataFrom("teste", "{\"password\":\"teste\",\"sections\":[{\"title\":\"Related Items\",\"name\":\"linked items\"}]}"));
	}

}
