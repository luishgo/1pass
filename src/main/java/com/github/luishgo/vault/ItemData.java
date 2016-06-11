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
import com.github.luishgo.util.Base64;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.annotations.Expose;

public class ItemData {

	@Expose String uuid;
	
	@Expose long updatedAt;
	
	@Expose String securityLevel;
	
	@Expose private String contentsHash;
	
	@Expose String title;
	
	@Expose private String encrypted;
	
	@Expose private long txTimestamp;
	
	@Expose long createdAt;
	
	@Expose String typeName;
	
	@Expose JsonElement decrypted;

	public String getDecrypted() {
		return decrypted.toString();
	}
	
	public String getSecurityLevel() {
		return securityLevel != null && !"".equals(securityLevel) ? securityLevel : "SL5";
	}
	
	public String getTitle() {
		return title;
	}
	
	@Override
	public String toString() {
		return new Gson().toJson(this);
	}

	public void decrypt(EncryptionKey key) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		SaltedData saltedData = SaltedData.newFromEncoded(encrypted);
		saltedData.decryptData(key.getDecryptedKey());
		decrypted = new JsonParser().parse(new String(saltedData.getDecryptedData()));
	}
	
	@Deprecated
	public String encrypt(EncryptionKey key, String data) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		SaltedData saltedData = SaltedData.newFromSaltAndDecrypted(Base64.decode("PMRz0L8VfkY="), data.getBytes());
		saltedData.encryptData(key.getDecryptedKey());
		return saltedData.getEncoded();		
	}

	public void encrypt(EncryptionKey key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		SaltedData saltedData = SaltedData.newFromDecrypted(decrypted.toString().getBytes());
		saltedData.encryptData(key.getDecryptedKey());
		encrypted = saltedData.getEncoded();		
	}	
	
//	var TYPE_WEBFORMS='webforms.WebForm', 
//		TYPE_FOLDERS='system.folder.Regular', 
//		TYPE_NOTES='securenotes.SecureNote', 
//		TYPE_IDENTITIES='identities.Identity', 
//		TYPE_PASSWORDS='passwords.Password', 
//		TYPE_WALLET='wallet', 
//		TYPE_SOFTWARE_LICENSES='wallet.computer.License', 
//		TYPE_TRASHED='trashed', 
//		TYPE_ACCOUNT='account', 
//		TYPE_ACCOUNT_ONLINESERVICE='wallet.onlineservices.', 
//		TYPE_ACCOUNT_COMPUTER='wallet.computer.';
	
}
