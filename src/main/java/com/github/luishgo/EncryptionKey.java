package com.github.luishgo;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

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
		byte[] key = Base64.decode(data);
		
		byte[] keySalt = Arrays.copyOfRange(key, 8, 16);
		byte[] keyData = Arrays.copyOfRange(key, 16, key.length);
		
		byte[] derivedKey = deriveKey(masterpass, iterations, keySalt);
		
		byte[] aesKey = Arrays.copyOfRange(derivedKey, 0, 16);
		byte[] aesIV = Arrays.copyOfRange(derivedKey, 16, 32);

		keyRaw = Crypto.decrypt(keyData, aesKey, aesIV);
	}
	
	private byte[] deriveKey(String masterpass, int iterations, byte[] keySalt) throws NoSuchAlgorithmException, InvalidKeySpecException {
		PBEKeySpec spec = new PBEKeySpec(masterpass.toCharArray(), keySalt, iterations, 32*8);
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		return skf.generateSecret(spec).getEncoded();
	}
	
	@Override
	public String toString() {
		return new Gson().toJson(this);
	}

}