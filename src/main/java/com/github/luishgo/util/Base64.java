package com.github.luishgo.util;

public class Base64 {
	
	public static byte[] decode(String data) {
		//Necessário remover todos os backslashs para a conversão funcionar
		return java.util.Base64.getDecoder().decode(data.replace("\\", ""));
	}

	public static String encode(byte[] byteArray) {
		return java.util.Base64.getEncoder().encodeToString(byteArray);
	}
	
}