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
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

public class Vault {

	private Path vaultPath;
	protected EncryptionKeys keys;
	
	public static Vault open(String path) throws IOException {
		Vault vault = new Vault(path);
		vault.checkIfExists();
		vault.openEncryptionKeys();
		return vault;
	}
	
	public static Vault create(String path, String masterPassword) throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Vault vault = new Vault(path);
		vault.create(masterPassword);
		return vault;
	}
	
	private void create(String masterPassword) throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Files.createDirectories(vaultPath.resolve("data/default"));
		this.keys = EncryptionKeys.generate(masterPassword);
		Files.write(Files.createFile(vaultPath.resolve("data/default/encryptionKeys.js")), keys.toJSONString().getBytes());
		Files.createFile(vaultPath.resolve("data/default/contents.js"));
		Files.write(Files.createFile(vaultPath.resolve("data/default/1password.keys")), keys.toPLISTString().getBytes());
	}

	private Vault(String path) {
		this.vaultPath = Paths.get(path);
	}
	
	private void openEncryptionKeys() throws IOException {
		this.keys = EncryptionKeys.open(vaultPath.resolve("data/default/encryptionKeys.js"));
	}
	
	private void checkIfExists() throws FileNotFoundException {
		if (!vaultPath.toFile().isDirectory()) {
			throw new FileNotFoundException("Vault not found. Must be a .agilekeychain directory");
		}
	}

	public void unlock(String masterPassword) {
		this.keys.unlock(masterPassword);
	}
	
	public String getDecryptedDataFrom(String title) {
		Optional<ItemData> possibleItemData = getItemsData().stream().filter(i -> title.equalsIgnoreCase(i.getTitle())).findFirst();
		if (possibleItemData.isPresent()) {
			ItemData itemData = possibleItemData.get();
			EncryptionKey key = keys.getKey(itemData.getSecurityLevel());
			try {
				itemData.decrypt(key);
				return itemData.getDecrypted();
			} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
					| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
				e.printStackTrace();
			}
		}
		return null;
	}
	
	public String getEncryptedDataFrom(String title, String data) {
		Optional<ItemData> possibleItemData = getItemsData().stream().filter(i -> title.equalsIgnoreCase(i.getTitle())).findFirst();
		if (possibleItemData.isPresent()) {
			ItemData itemData = possibleItemData.get();
			EncryptionKey key = keys.getKey(itemData.getSecurityLevel());
			try {
				return itemData.encrypt(key, data);
			} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
					| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException | IOException e) {
				e.printStackTrace();
			}
		}		
		return null;
	}

	public List<ItemData> getItemsData() {
		Gson gson = new GsonBuilder().create();
		
        try (Stream<Path> files = Files.walk(vaultPath.resolve("data/default"))) {
    		return files.filter(p -> p.toFile().getName().endsWith(".1password")).map(p -> {
    			try(Stream<String> content = Files.lines(p)) {
    				String json = content.findFirst().get();
    				return gson.fromJson(json, ItemData.class);
    		    } catch (IOException e) {
    				e.printStackTrace();
    			}
    			return null;
    		}).collect(Collectors.toList());
        } catch (IOException e) {
			e.printStackTrace();
		}
		
		return null;
	}
	
	public List<Item> getItems() {
		List<Item> items = new ArrayList<Item>();
        try (Stream<String> lines = Files.lines(vaultPath.resolve("data/default/contents.js"))) {
        	JsonElement contents = new JsonParser().parse(lines.findFirst().get());
        	contents.getAsJsonArray().forEach(c -> {
        		items.add(Item.newFromJSONArray(c.getAsJsonArray(), vaultPath.resolve("data/default")));
        	});
        } catch (IOException e) {
			e.printStackTrace();
		}
		return items;
	}
	
	public Optional<Item> getItemDecrypted(String title) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Optional<Item> possibleItem = getItems().stream().filter(i -> i.getTitle().equalsIgnoreCase(title)).findFirst();
		if (possibleItem.isPresent()) {
			Item item = possibleItem.get();
			ItemData itemData = item.getData();
			EncryptionKey key = keys.getKey(itemData.getSecurityLevel());
			itemData.decrypt(key);
			return Optional.of(item);
		}
		return possibleItem;
	}

	


}