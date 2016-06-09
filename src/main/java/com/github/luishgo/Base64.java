package com.github.luishgo;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class Base64 {
	
	private static final String SALTED = "Salted__";

	public static byte[] decode(String data) {
		//Necessário remover todos os backslashs para a conversão funcionar
		return java.util.Base64.getDecoder().decode(data.replace("\\", ""));
	}

	public static String encode(byte[] byteArray) {
		return java.util.Base64.getEncoder().encodeToString(byteArray);
	}

	public static String encodeSaltedKey(byte[] salt, byte[] raw) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream(salt.length + raw.length + SALTED.length());
		baos.write(SALTED.getBytes());
		baos.write(salt);
		baos.write(raw);
		
		return Base64.encode(baos.toByteArray());
	}
	
}
