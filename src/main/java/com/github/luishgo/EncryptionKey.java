package com.github.luishgo;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
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

import com.google.gson.Gson;

public class EncryptionKey {
	
	private String data;
	
	private String validation;
	
	private String level;
	
	private String identifier;
	
	private int iterations;
	
	private byte[] keyRaw;
	
	public String getLevel() {
		return level;
	}
	
	public byte[] getKeyRaw() {
		return keyRaw;
	}
	
	public void extractKeyRaw(String masterpass)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] key = decodeBase64(data);
		
		byte[] keySalt = Arrays.copyOfRange(key, 8, 16);
		byte[] keyData = Arrays.copyOfRange(key, 16, key.length);
		
		byte[] derivedKey = deriveKey(masterpass, iterations, keySalt);
		
		byte[] aesKey = Arrays.copyOfRange(derivedKey, 0, 16);
		byte[] aesIV = Arrays.copyOfRange(derivedKey, 16, 32);

		keyRaw = decrypt(keyData, aesKey, aesIV);
	}
	
	private byte[] decrypt(byte[] keyData, byte[] aesKey, byte[] aesIV) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKeySpec keyspec = new SecretKeySpec(aesKey, "AES");
		IvParameterSpec ivspec = new IvParameterSpec(aesIV);
		cipher.init(Cipher.DECRYPT_MODE, keyspec, ivspec);
		return cipher.doFinal(keyData);
	}
	
	private byte[] deriveKey(String masterpass, int iterations, byte[] keySalt) throws NoSuchAlgorithmException, InvalidKeySpecException {
		PBEKeySpec spec = new PBEKeySpec(masterpass.toCharArray(), keySalt, iterations, 32*8);
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		return skf.generateSecret(spec).getEncoded();
	}
	
	private byte[] decodeBase64(String data) {
		//Necessário remover todos os backslashs para a conversão funcionar
		return Base64.getDecoder().decode(data.replace("\\", ""));
	}
	
	@Override
	public String toString() {
		return new Gson().toJson(this);
	}

}