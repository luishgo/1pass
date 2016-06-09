package com.github.luishgo;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SaltedData {
	
	private static final String SALTED = "Salted__";

	private byte[] salt;
	private byte[] encryptedData;
	private byte[] decryptedData;

	public static SaltedData newFromEncoded(String base64Encoded) {
		byte[] decoded = Base64.decode(base64Encoded);
		
		SaltedData data = new SaltedData();
		data.salt = Arrays.copyOfRange(decoded, 8, 16);
		data.encryptedData = Arrays.copyOfRange(decoded, 16, decoded.length);
		return data;
	}
	
	public static SaltedData newFromSaltAndDecrypted(byte[] salt, byte[] decryptedData) {
		SaltedData data = new SaltedData();
		data.salt = salt;
		data.decryptedData = decryptedData;
		return data;
	}
	
	public static SaltedData newFromDecrypted(byte[] decryptedData) {
		return newFromSaltAndDecrypted(randomByteArray(8), decryptedData);
	}
	
	public static SaltedData newRandom() {
		return newFromSaltAndDecrypted(randomByteArray(8), randomByteArray(1024));
	}
	
	private SaltedData() {}

	public byte[] getSalt() {
		return salt;
	}
	
	public byte[] getEncryptedData() {
		return encryptedData;
	}
	
	public byte[] getDecryptedData() {
		return decryptedData;
	}
	
	public byte[] decryptData(byte[] key) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] aesKey = deriveAESKey(key, salt);
		byte[] aesIV = deriveAESKey(aesKey, key, salt);
		
		this.decryptedData = decrypt(encryptedData, aesKey, aesIV);
		
		return this.decryptedData;
	}
	
	public byte[] decryptKey(byte[] derivedKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] aesKey = Arrays.copyOfRange(derivedKey, 0, 16);
		byte[] aesIV = Arrays.copyOfRange(derivedKey, 16, 32);

		this.decryptedData = decrypt(encryptedData, aesKey, aesIV);
		
		return this.decryptedData;
	}
	
	public byte[] encryptData(byte[] key) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] aesKey = deriveAESKey(key, salt);
		byte[] aesIV = deriveAESKey(aesKey, key, salt);
		
		this.encryptedData = encrypt(decryptedData, aesKey, aesIV);
		
		return this.encryptedData;
	}
	
	public byte[] encryptKey(byte[] derivedKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] aesKey = Arrays.copyOfRange(derivedKey, 0, 16);
		byte[] aesIV = Arrays.copyOfRange(derivedKey, 16, 32);
		
		this.encryptedData = encrypt(decryptedData, aesKey, aesIV);
		
		return this.encryptedData;
	}
	
	
	public String getEncoded() throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream(salt.length + encryptedData.length + SALTED.length());
		baos.write(SALTED.getBytes());
		baos.write(salt);
		baos.write(encryptedData);
		
		return Base64.encode(baos.toByteArray());
	}
	
	private byte[] deriveAESKey(byte[]... data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("MD5");
		Arrays.stream(data).forEach(d -> md.update(d));
		return md.digest();
	}
	
	private byte[] decrypt(byte[] data, byte[] aesKey, byte[] aesIV) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKeySpec keyspec = new SecretKeySpec(aesKey, "AES");
		IvParameterSpec ivspec = new IvParameterSpec(aesIV);
		cipher.init(Cipher.DECRYPT_MODE, keyspec, ivspec);
		return cipher.doFinal(data);
	}

	private byte[] encrypt(byte[] data, byte[] aesKey, byte[] aesIV) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKeySpec keyspec = new SecretKeySpec(aesKey, "AES");
		IvParameterSpec ivspec = new IvParameterSpec(aesIV);
		cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);
		return cipher.doFinal(data);
	}
	
	private static byte[] randomByteArray(int size) {
		byte[] array = new byte[size];
		new Random().nextBytes(array);
		return array;
	}

}
