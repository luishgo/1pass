package com.github.luishgo;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

public class SaltedData {
	
	private static final String SALTED = "Salted__";

	private byte[] salt;
	private byte[] encryptedData;

	public SaltedData(String base64Encoded) {
		byte[] decoded = Base64.decode(base64Encoded);
		
		this.salt = Arrays.copyOfRange(decoded, 8, 16);
		this.encryptedData = Arrays.copyOfRange(decoded, 16, decoded.length);
	}
	
	public SaltedData(byte[] salt, byte[] encryptedData) {
		this.salt = salt;
		this.encryptedData = encryptedData;
	}

	public byte[] getSalt() {
		return salt;
	}
	
	public byte[] getEncryptedData() {
		return encryptedData;
	}
	
	public String getEncoded() throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream(salt.length + encryptedData.length + SALTED.length());
		baos.write(SALTED.getBytes());
		baos.write(salt);
		baos.write(encryptedData);
		
		return Base64.encode(baos.toByteArray());
	}
	
}
