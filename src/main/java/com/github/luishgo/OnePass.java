package com.github.luishgo;

import java.io.Console;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.github.luishgo.vault.Item;
import com.github.luishgo.vault.Vault;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

public class OnePass {

	public static void main(String[] args) {
		if (args.length < 2) {
			System.err.println("Usage: <vault path> list | get <item title>");
			System.exit(1);
		}
		
		Console c = System.console();
		if (c == null) {
			System.err.println("No console.");
			System.exit(1);
		}
		
		try {
			Vault vault = Vault.open(args[0]);
			
			char[] masterPassword = c.readPassword("Enter your Master Password: ");
			vault.unlock(new String(masterPassword));
			
			Gson gson = new GsonBuilder().setPrettyPrinting().excludeFieldsWithoutExposeAnnotation().create();
			if (args[1].equalsIgnoreCase("list")) {
				vault.getItems().stream().forEach(i -> {
					System.out.println(gson.toJson(i));
				});
			} 
			if (args[1].equalsIgnoreCase("get")) {
				String title = args[2];
				Optional<Item> possibleItem = vault.getItemDecrypted(title);
				if (possibleItem.isPresent()) {
					Item item = possibleItem.get();		
					System.out.println(item.getUUID());
					System.out.println(gson.toJson(item));
				} else {
					System.err.println("Item not found");
					System.exit(1);
				}
			}
		} catch (IOException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
			System.err.println(e.getMessage());
			System.exit(1);
		}

	}

}