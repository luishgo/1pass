package com.github.luishgo.crypto;

import org.junit.Test;

public class SaltedDataTest {

	@Test public void shouldDecodeBase64WithIncorrectEnding() {
		String base64Encoded = "U2FsdGVkX1/3BJYSr/+hjbM+ADBBB0mNItNuIalSs74X3Vd9ryhO/jCG0TwWKjXrmwnLfXLGR2kxZk1LcG7+oKp3/+HNRNUiK1xxgEDk7uYni44k584HJfXGKj6yxpC1y6hcnW+y9XtX7FmP5wD4X35r9IOcIPDHgU/PzrDNAjezuG1ltbyr4PE2P90b/iaz+imP/CdgvC+D5kxWRb9iEW0a8NIwH2KAHsx8yGu5zWgxHcWHGqplov9M6eIHyAYPyMu8Qi4pxzuVeOsmSaKqzw==\u0000";
		SaltedData.newFromEncoded(base64Encoded);
	}

}
