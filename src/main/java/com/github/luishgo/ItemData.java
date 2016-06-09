package com.github.luishgo;

import java.beans.Transient;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

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
		SaltedData saltedData = new SaltedData(encrypted);
		decrypted = new String(Crypto.decryptData(saltedData.getEncryptedData(), key.getDecryptedKey(), saltedData.getSalt()));
	}
	
	public String encrypt(EncryptionKey key, String data) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		byte[] passwordSalt = Base64.decode("PMRz0L8VfkY=");
		
		return new SaltedData(passwordSalt, Crypto.encryptData(data.getBytes(), key.getDecryptedKey(), passwordSalt)).getEncoded();
	}	
	
}
