package com.github.luishgo;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;

public class Vault {

	private Path vaultPath;
	protected List<EncryptionKey> keys;

	public Vault(String path) throws FileNotFoundException {
		vaultPath = Paths.get(path);
		if (!vaultPath.toFile().isDirectory()) {
			throw new FileNotFoundException("Vault not found. Must be a .agilekeychain directory");
		}
        
        try (Stream<String> stream = Files.lines(vaultPath.resolve("data/default/encryptionKeys.js"))) {
        	parseEncryptionKeys(stream.findFirst().get());
        } catch (IOException e) {
			e.printStackTrace();
		}
	}

	private void parseEncryptionKeys(String json) {
		JsonObject obj = new JsonParser().parse(json).getAsJsonObject();
		Type encryptionKeyList = new TypeToken<List<EncryptionKey>>() {}.getType();
		keys = new GsonBuilder().create().fromJson(obj.get("list"), encryptionKeyList);
	}

	public void unlock(String masterPassword) {
		EncryptionKey sl3 = getKeyAlreadyExtracted("SL3", masterPassword);
		EncryptionKey sl5 = getKeyAlreadyExtracted("SL5", masterPassword);
	}
	
	private EncryptionKey getKeyAlreadyExtracted(String level, String masterPassword) {
		EncryptionKey key = keys.stream().filter(k -> k.getLevel().equals(level)).findFirst().get();
		try {
			key.extractKeyRaw(masterPassword);
		} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		return key;
	}

	public String getDecryptedDataFrom(String title) {
		ItemData itemData = getItems().stream().filter(i -> title.equals(i.getTitle())).findFirst().get();
		EncryptionKey key = keys.stream().filter(k -> k.getLevel().equals(itemData.getSecurityLevel())).findFirst().get();
		try {
			itemData.decrypt(key);
			return itemData.getDecrypted();
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}

	public List<ItemData> getItems() {
        try (Stream<Path> stream = Files.walk(vaultPath.resolve("data/default"))) {
        	return parseItems(stream);
        } catch (IOException e) {
			e.printStackTrace();
		}
		
		return null;
	}
	
	private List<ItemData> parseItems(Stream<Path> stream) {
		Gson gson = new GsonBuilder().create();
		return stream.filter(p -> p.toFile().getName().endsWith(".1password")).map(p -> {
			try(Stream<String> content = Files.lines(p)) {
				String json = content.findFirst().get();
				return gson.fromJson(json, ItemData.class);
		    } catch (IOException e) {
				e.printStackTrace();
			}
			return null;
		}).collect(Collectors.toList());
	}


}