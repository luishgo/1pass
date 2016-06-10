package com.github.luishgo.vault;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.github.luishgo.crypto.SaltedData;
import com.github.luishgo.crypto.SaltedKey;
import com.github.luishgo.util.UUID;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

public class EncryptionKey {
	
	private String data;
	
	private String validation;
	
	private String level;
	
	private String identifier;
	
	private int iterations;
	
	private byte[] decryptedKey;
	
	public static EncryptionKey generate(String masterPassword, int iterations, String securityLevel) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		EncryptionKey key = new EncryptionKey();
		key.identifier = UUID.generate();
		key.level = securityLevel;
		key.iterations = iterations;
		key.generate(masterPassword);
		
		return key;
	}
	
	private void generate(String masterPassword) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		SaltedKey saltedKey = SaltedKey.newRandom();
		saltedKey.encryptKey(masterPassword, iterations);
		this.data = saltedKey.getEncoded();
		
		SaltedData validationSaltedData = SaltedData.newFromDecrypted(saltedKey.getDecryptedKey());
		validationSaltedData.encryptData(saltedKey.getDecryptedKey());
		this.validation = validationSaltedData.getEncoded();
	}
	
	public String getData() {
		return data;
	}
	
	public String getValidation() {
		return validation;
	}
	
	public String getLevel() {
		return level;
	}
	
	public String getIdentifier() {
		return identifier;
	}

	public int getIterations() {
		return iterations;
	}
	
	public byte[] getDecryptedKey() {
		return decryptedKey;
	}
	
	public void decryptKey(String masterPassword)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		SaltedKey decodedKey = SaltedKey.newFromEncoded(data);
		decryptedKey = decodedKey.decryptKey(masterPassword, iterations);
		
		byte[] decryptedValidation = SaltedData.newFromEncoded(validation).decryptData(decryptedKey);
		
		if (!new String(decryptedValidation).equalsIgnoreCase(new String(decryptedKey))) {
			throw new InvalidKeyException("Key Data != Validation!!");
		}
	}
	
	public JsonElement toJSON() {
		return new JsonParser().parse(new Gson().toJson(this));
	}

}