package com.github.luishgo.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class SaltedData extends BaseSaltedData {
	
	public static SaltedData newFromEncoded(String base64Encoded) {
		return BaseSaltedData.newFromEncoded(base64Encoded, new SaltedData());
	}
	
	public static SaltedData newFromSaltAndDecrypted(byte[] salt, byte[] decrypted) {
		return BaseSaltedData.newFromSaltAndDecrypted(salt, decrypted, new SaltedData());
	}
	
	public static SaltedData newFromDecrypted(byte[] decrypted) {
		return newFromSaltAndDecrypted(randomByteArray(8), decrypted);
	}
	
	public static SaltedData newRandom() {
		return newFromSaltAndDecrypted(randomByteArray(8), randomByteArray(1024));
	}
	
	private SaltedData() {}

	public byte[] getEncryptedData() {
		return encrypted;
	}
	
	public byte[] getDecryptedData() {
		return decrypted;
	}
	
	public byte[] decryptData(byte[] key) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] aesKey = deriveAESKey(key, salt);
		byte[] aesIV = deriveAESKey(aesKey, key, salt);
		
		this.decrypted = decrypt(encrypted, aesKey, aesIV);
		
		return this.decrypted;
	}
	
	public byte[] encryptData(byte[] key) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] aesKey = deriveAESKey(key, salt);
		byte[] aesIV = deriveAESKey(aesKey, key, salt);
		
		this.encrypted = encrypt(decrypted, aesKey, aesIV);
		
		return this.encrypted;
	}
	
	private byte[] deriveAESKey(byte[]... data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("MD5");
		Arrays.stream(data).forEach(d -> md.update(d));
		return md.digest();
	}
	
}
