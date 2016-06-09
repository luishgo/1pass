package com.github.luishgo;

import org.junit.Test;

import junit.framework.Assert;

public class UUIDTest {
	
	@Test public void shouldGenerateUUIDsWith32Chars() {
		Assert.assertEquals(32, UUID.generate().length());
	}

}
