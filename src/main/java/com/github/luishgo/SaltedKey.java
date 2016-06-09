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

public class SaltedKey extends BaseSaltedData {
	
	public static SaltedKey newFromEncoded(String base64Encoded) {
		return BaseSaltedData.newFromEncoded(base64Encoded, new SaltedKey());
	}
	
	public static SaltedKey newRandom() {
		return BaseSaltedData.newFromSaltAndDecrypted(randomByteArray(8), randomByteArray(1024), new SaltedKey());
	}
	
	private SaltedKey() {}

	public byte[] getEncryptedKey() {
		return encrypted;
	}
	
	public byte[] getDecryptedKey() {
		return decrypted;
	}
	
	public byte[] decryptKey(String masterPassword, int iterations) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
		byte[] derivedKey = deriveKey(masterPassword, iterations);		
		
		byte[] aesKey = Arrays.copyOfRange(derivedKey, 0, 16);
		byte[] aesIV = Arrays.copyOfRange(derivedKey, 16, 32);

		this.decrypted = decrypt(encrypted, aesKey, aesIV);
		
		return this.decrypted;
	}
	
	public byte[] encryptKey(String masterPassword, int iterations) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
		byte[] derivedKey = deriveKey(masterPassword, iterations);
		
		byte[] aesKey = Arrays.copyOfRange(derivedKey, 0, 16);
		byte[] aesIV = Arrays.copyOfRange(derivedKey, 16, 32);
		
		this.encrypted = encrypt(decrypted, aesKey, aesIV);
		
		return this.encrypted;
	}
	
	private byte[] deriveKey(String masterPassword, int iterations) throws NoSuchAlgorithmException, InvalidKeySpecException {
		PBEKeySpec spec = new PBEKeySpec(masterPassword.toCharArray(), salt, iterations, 32*8);
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		return skf.generateSecret(spec).getEncoded();
	}

}
