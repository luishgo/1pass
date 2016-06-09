package com.github.luishgo;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

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
		SaltedData saltedKey = SaltedData.newRandom();
		byte[] derivedKey = deriveKey(masterPassword, iterations, saltedKey.getSalt());
		saltedKey.encryptKey(derivedKey);
		this.data = saltedKey.getEncoded();
		
		SaltedData validationSaltedData = SaltedData.newFromDecrypted(saltedKey.getDecryptedData());
		validationSaltedData.encryptData(saltedKey.getDecryptedData());
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
		SaltedData decodedKey = SaltedData.newFromEncoded(data);
		
		byte[] derivedKey = deriveKey(masterPassword, iterations, decodedKey.getSalt());
		
		decryptedKey = decodedKey.decryptKey(derivedKey);
		
		byte[] decryptedValidation = SaltedData.newFromEncoded(validation).decryptData(decryptedKey);
		
		if (!new String(decryptedValidation).equalsIgnoreCase(new String(decryptedKey))) {
			throw new InvalidKeyException("Key Data != Validation!!");
		}
	}
	
	private byte[] deriveKey(String masterpass, int iterations, byte[] keySalt) throws NoSuchAlgorithmException, InvalidKeySpecException {
		PBEKeySpec spec = new PBEKeySpec(masterpass.toCharArray(), keySalt, iterations, 32*8);
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		return skf.generateSecret(spec).getEncoded();
	}

	public JsonElement toJSON() {
		return new JsonParser().parse(new Gson().toJson(this));
	}

}