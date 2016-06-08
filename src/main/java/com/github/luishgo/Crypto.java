package com.github.luishgo;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypto {

	static byte[] decrypt(byte[] keyData, byte[] aesKey, byte[] aesIV) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKeySpec keyspec = new SecretKeySpec(aesKey, "AES");
		IvParameterSpec ivspec = new IvParameterSpec(aesIV);
		cipher.init(Cipher.DECRYPT_MODE, keyspec, ivspec);
		return cipher.doFinal(keyData);
	}

	public static byte[] encrypt(byte[] data, byte[] aesKey, byte[] aesIV) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKeySpec keyspec = new SecretKeySpec(aesKey, "AES");
		IvParameterSpec ivspec = new IvParameterSpec(aesIV);
		cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);
		return cipher.doFinal(data);
	}

}
