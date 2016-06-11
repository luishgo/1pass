package com.github.luishgo.vault;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.stream.Stream;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.github.luishgo.util.UUID;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.annotations.Expose;

public class Item {
	
	@Expose private String uuid;
	
	@Expose String typeName;
	
	@Expose private String title;
	
	@Expose String domain;
	
	@Expose long updatedAt;
	
	@Expose String folderUUID;
	
	@Expose int passwordStrength = 0;
	
	@Expose String trashed;
	
	@Expose protected ItemData data;

	private Path basePath;

	public Item(Path basePath) {
		this.basePath = basePath;
	}

	public Item() {
	}

	public static Item newFromJSONArray(JsonArray array, Path basePath) {
		Item item = new Item(basePath);
		item.uuid = array.get(0).getAsString();
		item.typeName = array.get(1).getAsString();
		item.title = array.get(2).getAsString();
		item.domain = array.get(3).getAsString();
		item.updatedAt = array.get(4).getAsLong();
		item.folderUUID = array.get(5).getAsString();
		item.passwordStrength = array.get(6).getAsInt();
		item.trashed = array.get(7).getAsString();
		
		return item;
	}
	
	public static Item createPassword(String title, String password) {
		Item item = new Item();
		item.uuid = UUID.generate();
		item.typeName = "passwords.Password";
		item.title = title;
		item.domain = "";
		item.updatedAt = new Date().getTime()/1000L; 
		item.folderUUID = "";
		item.passwordStrength = 0;
		item.trashed = "N";
		
		item.createData(password);
		
		return item;
	}

	private void createData(String password) {
		this.data = new ItemData();
		this.data.uuid = this.uuid;
		this.data.title = this.title;
		this.data.decrypted = new JsonParser().parse("{\"password\": \""+password+"\"}");
		this.data.updatedAt = this.updatedAt;
		this.data.createdAt = this.updatedAt;
		this.data.typeName = this.typeName;
		this.data.securityLevel = "SL5";
	}

	public String getTitle() {
		return title;
	}
	
	public String getUUID() {
		return uuid;
	}
	
	public Path getDataPath() {
		return basePath.resolve(this.uuid+".1password");
	}
	
	public ItemData getData() {
		if (this.data == null) {
			Gson gson = new GsonBuilder().create();
			try (Stream<String> details =Files.lines(getDataPath())) {
				this.data = gson.fromJson(details.findFirst().get(), ItemData.class);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return this.data;
	}

	public void encryptData(EncryptionKey key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		this.data.encrypt(key);
	}

	public void save() throws IOException {
		Gson gson = new GsonBuilder().excludeFieldsWithoutExposeAnnotation().create();
		JsonElement decrypted = data.decrypted;
		data.decrypted = null;
		Files.write(Files.createFile(getDataPath()), gson.toJson(data).getBytes());
		data.decrypted = decrypted;
	}

	public void setBasePath(Path basePath) {
		this.basePath = basePath;
	}
	
}
