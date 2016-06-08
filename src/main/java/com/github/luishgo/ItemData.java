package com.github.luishgo;

import java.beans.Transient;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.google.gson.Gson;

public class ItemData {
	
	private static final String SALTED = "Salted__";

	private String uuid;
	
	private String updatedAt;
	
	private String securityLevel;
	
	private String contentsHash;
	
	private String title;
	
	private String encrypted;
	
	private String txTimestamp;
	
	private String createdAt;
	
	private String typeName;
	
	private String decrypted;
	
	@Transient
	public String getDecrypted() {
		return decrypted;
	}
	
	public String getSecurityLevel() {
		return securityLevel;
	}
	
	public String getTitle() {
		return title;
	}
	
	@Override
	public String toString() {
		return new Gson().toJson(this);
	}

	public void decrypt(EncryptionKey key) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] password = Base64.decode(encrypted);
		
		byte[] passwordSalt = Arrays.copyOfRange(password, 8, 16);
		byte[] passwordData = Arrays.copyOfRange(password, 16, password.length);
		
		byte[] keyRaw = key.getKeyRaw();
		byte[] passwordKey = deriveAESKey(keyRaw, passwordSalt);
		byte[] passwordIV = deriveAESKey(passwordKey, keyRaw, passwordSalt);
		
		byte[] passwordRaw = Crypto.decrypt(passwordData, passwordKey, passwordIV);
		
		decrypted = new String(passwordRaw);
	}
	
	public String encrypt(EncryptionKey key, String data) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		byte[] passwordSalt = Base64.decode("PMRz0L8VfkY=");
		
		byte[] keyRaw = key.getKeyRaw();
		byte[] passwordKey = deriveAESKey(keyRaw, passwordSalt);
		byte[] passwordIV = deriveAESKey(passwordKey, keyRaw, passwordSalt);

		byte[] dataRaw = Crypto.encrypt(data.getBytes(), passwordKey, passwordIV);
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream(passwordSalt.length + dataRaw.length + SALTED.length());
		baos.write(SALTED.getBytes());
		baos.write(passwordSalt);
		baos.write(dataRaw);
		
		return Base64.encode(baos.toByteArray());
	}	
	
	private byte[] deriveAESKey(byte[]... data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("MD5");
		Arrays.stream(data).forEach(d -> md.update(d));
		return md.digest();
	}
	
}
