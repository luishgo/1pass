package com.github.luishgo;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Random;

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
	
	private byte[] keyRaw;
	
	public static EncryptionKey generate(String masterPassword, int iterations, String securityLevel) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		EncryptionKey key = new EncryptionKey();
		key.identifier = UUID.generate();
		key.level = securityLevel;
		key.iterations = iterations;
		key.generate(masterPassword);
		
		return key;
	}
	
	private void generate(String masterPassword) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		byte[] keySalt = Crypto.randomByteArray(8);
		byte[] keyData = Crypto.randomByteArray(1024);
		
		byte[] derivedKey = deriveKey(masterPassword, iterations, keySalt);
		
		this.data = Base64.encodeSaltedKey(keySalt, Crypto.encryptKey(keyData, derivedKey));
		
		byte[] validationSalt = Crypto.randomByteArray(8);
		
		this.validation = Base64.encodeSaltedKey(validationSalt, Crypto.encryptData(keyData, keyData, validationSalt));
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
	
	public byte[] getKeyRaw() {
		return keyRaw;
	}
	
	public void extractKeyRaw(String masterPassword)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] key = Base64.decode(data);
		
		byte[] keySalt = Arrays.copyOfRange(key, 8, 16);
		byte[] keyData = Arrays.copyOfRange(key, 16, key.length);
		
		byte[] derivedKey = deriveKey(masterPassword, iterations, keySalt);
		
		keyRaw = Crypto.decryptKey(keyData, derivedKey);
		
		byte[] validationDecoded = Base64.decode(validation);
		
		byte[] validationSalt = Arrays.copyOfRange(validationDecoded, 8, 16);
		byte[] validationData = Arrays.copyOfRange(validationDecoded, 16, validationDecoded.length);
		
		byte[] validationRaw = Crypto.decryptData(validationData, keyRaw, validationSalt);
		
		if (!new String(validationRaw).equalsIgnoreCase(new String(keyRaw))) {
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