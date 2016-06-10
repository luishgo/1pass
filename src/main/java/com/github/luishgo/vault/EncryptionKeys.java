package com.github.luishgo.vault;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.stream.Stream;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.github.mustachejava.DefaultMustacheFactory;
import com.github.mustachejava.Mustache;
import com.github.mustachejava.MustacheFactory;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class EncryptionKeys {
	
	protected Map<String, EncryptionKey> keys = new HashMap<String, EncryptionKey>(2);
	
	public static EncryptionKeys open(Path encryptionKeysPath) throws IOException {
		EncryptionKeys keys = new EncryptionKeys();
        try (Stream<String> json = Files.lines(encryptionKeysPath)) {
    		JsonObject obj = new JsonParser().parse(json.findFirst().get()).getAsJsonObject();
    		Gson gson = new GsonBuilder().create();
    		JsonArray keysJSON = obj.getAsJsonArray("list");
    		keysJSON.forEach(keyJSON -> {
    			EncryptionKey key = gson.fromJson(keyJSON, EncryptionKey.class);
    			keys.keys.put(key.getLevel(), key);
    		});
        }
		
		return keys;
	}

	public static EncryptionKeys generate(String masterPassword) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		EncryptionKeys keys = new EncryptionKeys();
		int iterations = new Random().nextInt(50000);
		keys.keys.put("SL5", EncryptionKey.generate(masterPassword, iterations, "SL5"));
		keys.keys.put("SL3", EncryptionKey.generate(masterPassword, iterations, "SL3"));
		return keys;
	}
	
	public void unlock(String masterPassword) {
		keys.forEach((k,v) -> {
			try {
				v.decryptKey(masterPassword);
			} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException
					| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
				e.printStackTrace();
			}
		});
	}

	public EncryptionKey getKey(String securityLevel) {
		return this.keys.get(securityLevel);
	}

	public String toJSONString() {
		JsonObject encryptionKeys = new JsonObject();
		JsonArray list = new JsonArray();
		keys.forEach((level, key) -> {
			encryptionKeys.addProperty(level, key.getIdentifier());
			list.add(key.toJSON());
		});
		
		encryptionKeys.add("list", list);
		return encryptionKeys.toString();
	}

	public String toPLISTString() {
		Map<String, Object> scopes = new HashMap<String, Object>();
	    scopes.put("keys", keys.values());

	    Writer writer = new StringWriter();
	    MustacheFactory mf = new DefaultMustacheFactory();
	    Mustache mustache = mf.compile("1password.keys.mustache");
	    mustache.execute(writer, scopes);
	    try {
			writer.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	    return writer.toString();
	}
	
}
