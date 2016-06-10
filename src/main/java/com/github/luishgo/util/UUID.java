package com.github.luishgo.util;

public class UUID {

	public static String generate() {
		java.util.UUID uuid = java.util.UUID.randomUUID();
		return uuid.toString().replace("-", "").toUpperCase(); 
	}
	
}
