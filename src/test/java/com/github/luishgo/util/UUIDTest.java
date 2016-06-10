package com.github.luishgo.util;

import org.junit.Test;

import com.github.luishgo.util.UUID;

import junit.framework.Assert;

public class UUIDTest {
	
	@Test public void shouldGenerateUUIDsWith32Chars() {
		Assert.assertEquals(32, UUID.generate().length());
	}

}
