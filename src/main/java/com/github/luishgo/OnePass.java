package com.github.luishgo;

import java.io.Console;
import java.io.IOException;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

public class OnePass {

	public static void main(String[] args) {
		if (args.length < 2) {
			System.err.println("Usage: <vault path> <item title>");
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
			String result = vault.getDecryptedDataFrom(args[1]);
			
			if (result != null) {
				JsonParser parser = new JsonParser();
				JsonElement element = parser.parse(result);
				System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(element));
			} else {
				System.err.println("Item not found");
				System.exit(1);
			}
			
		} catch (IOException e) {
			System.err.println(e.getMessage());
			System.exit(1);
		}

	}

}