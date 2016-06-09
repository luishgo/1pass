package com.github.luishgo;

public class UUID {

	public static String generate() {
		java.util.UUID uuid = java.util.UUID.randomUUID();
		return uuid.toString().replace("-", "").toUpperCase(); 
	}
	
}
