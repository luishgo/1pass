package com.github.luishgo.vault;

import java.beans.Transient;
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
		decrypted = new String(SaltedData.newFromEncoded(encrypted).decryptData(key.getDecryptedKey()));
	}
	
	public String encrypt(EncryptionKey key, String data) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		SaltedData saltedData = SaltedData.newFromSaltAndDecrypted(Base64.decode("PMRz0L8VfkY="), data.getBytes());
		saltedData.encryptData(key.getDecryptedKey());
		return saltedData.getEncoded();		
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
