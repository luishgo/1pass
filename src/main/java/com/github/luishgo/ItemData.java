package com.github.luishgo;

import java.beans.Transient;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.google.gson.Gson;

public class ItemData {

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
	
	private byte[] deriveAESKey(byte[]... data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("MD5");
		Arrays.stream(data).forEach(d -> md.update(d));
		return md.digest();
	}
	
}
