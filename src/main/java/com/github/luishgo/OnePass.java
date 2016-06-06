package com.github.luishgo;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class OnePass {
	
	private static final String SALTED = "Salted__";
	private int iterations;
	private byte[] key;

	public OnePass(String encodedKey, int iterations) {
		this.key = decodeBase64(encodedKey);
		this.iterations = iterations;
		
		printVar("key", key);
	}
	
	public String encrypt(String masterpass, String data) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		byte[] passwordSalt = decodeBase64("PMRz0L8VfkY=");
		printVar("passwordSalt", passwordSalt);
		
		byte[] keyRaw = extractKeyRaw(masterpass);
		byte[] passwordKey = deriveAESKey(keyRaw, passwordSalt);
		byte[] passwordIV = deriveAESKey(passwordKey, keyRaw, passwordSalt);

		byte[] dataRaw = encrypt(data.getBytes(), passwordKey, passwordIV);
		printVar("dataRaw", dataRaw);
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream(passwordSalt.length + dataRaw.length + SALTED.length());
		baos.write(SALTED.getBytes());
		baos.write(passwordSalt);
		baos.write(dataRaw);
		
		return Base64.getEncoder().encodeToString(baos.toByteArray());
	}

	private byte[] extractKeyRaw(String masterpass)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] keySalt = Arrays.copyOfRange(key, 8, 16);
		byte[] keyData = Arrays.copyOfRange(key, 16, key.length);
		
		printVar("keySalt", keySalt);
		printVar("keyData", keyData);
		
		byte[] derivedKey = deriveKey(masterpass, iterations, keySalt);
		
		printVar("derivedKey", derivedKey);
		
		byte[] aesKey = Arrays.copyOfRange(derivedKey, 0, 16);
		byte[] aesIV = Arrays.copyOfRange(derivedKey, 16, 32);

		printVar("aesKey", aesKey);
		printVar("aesIV", aesIV);
		
		byte[] keyRaw = decrypt(keyData, aesKey, aesIV);
		
		printVar("keyRaw", keyRaw);
		return keyRaw;
	}
	
	public String decrypt(String masterpass, String encodedPassword) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] password = decodeBase64(encodedPassword);
		printVar("password", password);
		
		byte[] passwordSalt = Arrays.copyOfRange(password, 8, 16);
		byte[] passwordData = Arrays.copyOfRange(password, 16, password.length);
		
		printVar("passwordSalt", passwordSalt);
		printVar("passwordData", passwordData);
		
		byte[] keyRaw = extractKeyRaw(masterpass);
		byte[] passwordKey = deriveAESKey(keyRaw, passwordSalt);
		byte[] passwordIV = deriveAESKey(passwordKey, keyRaw, passwordSalt);
		
		printVar("passwordKey", passwordKey);
		printVar("passwordIV", passwordIV);
		
		byte[] passwordRaw = decrypt(passwordData, passwordKey, passwordIV);
		
		return new String(passwordRaw);
	}
	
	private byte[] decodeBase64(String data) {
		//Necessário remover todos os backslashs para a conversão funcionar
		return Base64.getDecoder().decode(data.replace("\\", ""));
	}
	
	private String encodeHex(byte[] data) {
		return String.format("%040x", new BigInteger(data));
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
	
	private byte[] encrypt(byte[] data, byte[] aesKey, byte[] aesIV) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKeySpec keyspec = new SecretKeySpec(aesKey, "AES");
		IvParameterSpec ivspec = new IvParameterSpec(aesIV);
		cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);
		return cipher.doFinal(data);
	}

	private byte[] deriveKey(String masterpass, int iterations, byte[] keySalt) throws NoSuchAlgorithmException, InvalidKeySpecException {
		PBEKeySpec spec = new PBEKeySpec(masterpass.toCharArray(), keySalt, iterations, 32*8);
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		return skf.generateSecret(spec).getEncoded();
	}

	private void printVar(String label, byte[] var) {
		System.out.println(label + ": " + var.length);
		System.out.println(encodeHex(var));
		System.out.println(Base64.getEncoder().encodeToString(var));
	}

}