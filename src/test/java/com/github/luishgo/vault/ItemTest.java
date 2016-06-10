package com.github.luishgo.vault;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.Test;

import com.google.gson.GsonBuilder;

public class ItemTest {
	
	@Test public void shouldListAsJSON() throws IOException {
		Vault vault = Vault.open("src/test/resources/demo.agilekeychain");
		vault.unlock("demo");
		vault.getItems().stream().forEach(i -> {
			System.out.println(new GsonBuilder().setPrettyPrinting().excludeFieldsWithoutExposeAnnotation().create().toJson(i));
		});
		
	}
	
	@Test public void shouldGetItemAsJSON() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Vault vault = Vault.open("src/test/resources/demo.agilekeychain");
		vault.unlock("demo");
		System.out.println(new GsonBuilder().setPrettyPrinting().excludeFieldsWithoutExposeAnnotation().create().toJson(vault.getItemDecrypted("teste").get()));
	}
	

}
