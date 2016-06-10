package com.github.luishgo;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class BaseSaltedData {

	private static final String SALTED = "Salted__";

	protected byte[] salt;
	protected byte[] encrypted;
	protected byte[] decrypted;
	
	public static <T extends BaseSaltedData> T newFromEncoded(String base64Encoded, T baseSaltedData) {
		byte[] decoded = Base64.decode(base64Encoded);
		
		baseSaltedData.salt = Arrays.copyOfRange(decoded, 8, 16);
		baseSaltedData.encrypted = Arrays.copyOfRange(decoded, 16, decoded.length);
		return baseSaltedData; 
	}
	
	public static <T extends BaseSaltedData> T newFromSaltAndDecrypted(byte[] salt, byte[] decrypted, T baseSaltedData) {
		baseSaltedData.salt = salt;
		baseSaltedData.decrypted = decrypted;
		return baseSaltedData;
	}

	public byte[] getSalt() {
		return salt;
	}
	
	public String getEncoded() throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream(salt.length + encrypted.length + SALTED.length());
		baos.write(SALTED.getBytes());
		baos.write(salt);
		baos.write(encrypted);

		return Base64.encode(baos.toByteArray());
	}

	protected byte[] decrypt(byte[] data, byte[] aesKey, byte[] aesIV) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKeySpec keyspec = new SecretKeySpec(aesKey, "AES");
		IvParameterSpec ivspec = new IvParameterSpec(aesIV);
		cipher.init(Cipher.DECRYPT_MODE, keyspec, ivspec);
		return cipher.doFinal(data);
	}

	protected byte[] encrypt(byte[] data, byte[] aesKey, byte[] aesIV) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKeySpec keyspec = new SecretKeySpec(aesKey, "AES");
		IvParameterSpec ivspec = new IvParameterSpec(aesIV);
		cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);
		return cipher.doFinal(data);
	}
	
	protected static byte[] randomByteArray(int size) {
		byte[] array = new byte[size];
		new Random().nextBytes(array);
		return array;
	}

}