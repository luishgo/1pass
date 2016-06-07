package com.github.luishgo;

import java.beans.Transient;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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
		byte[] password = decodeBase64(encrypted);
		
		byte[] passwordSalt = Arrays.copyOfRange(password, 8, 16);
		byte[] passwordData = Arrays.copyOfRange(password, 16, password.length);
		
		byte[] keyRaw = key.getKeyRaw();
		byte[] passwordKey = deriveAESKey(keyRaw, passwordSalt);
		byte[] passwordIV = deriveAESKey(passwordKey, keyRaw, passwordSalt);
		
		byte[] passwordRaw = decrypt(passwordData, passwordKey, passwordIV);
		
		decrypted = new String(passwordRaw);
	}
	
	private byte[] deriveAESKey(byte[]... data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("MD5");
		Arrays.stream(data).forEach(d -> md.update(d));
		return md.digest();
	}
	
	private byte[] decrypt(byte[] keyData, byte[] aesKey, byte[] aesIV) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKeySpec keyspec = new SecretKeySpec(aesKey, "AES");
		IvParameterSpec ivspec = new IvParameterSpec(aesIV);
		cipher.init(Cipher.DECRYPT_MODE, keyspec, ivspec);
		return cipher.doFinal(keyData);
	}
	
	private byte[] decodeBase64(String data) {
		//Necessário remover todos os backslashs para a conversão funcionar
		return Base64.getDecoder().decode(data.replace("\\", ""));
	}
	
	
}
