package com.github.luishgo;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.Assert;
import org.junit.Test;

public class OnePassTest {
	
	@Test public void shouldDecrypt() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		String masterpass = "pa$$w0rd";
		String encodedKey = "U2FsdGVkX18O742tiin24L289EipX0yfOvS24X+XPnS2MRItGW1qQr4Lw5qd6dMYGa7zhbMUY1K/bbO0i7X0gwP/QgxCOHlyCnosq9yH0SIP7uQ8StAE1gxWaY2GM42oCIaKgXS3uvvSrtKZOyJizmgnMcA4KR5fNbfRHQoiZaWpT+2L+eckYeglN/+FN4YuAwgREzydBbzwGrJkDwWGuaHdXVBVRUMNjqJy7lP7gQ8iIVh6dPR1V733cgckPWLY6BaWs4CMrFu+/UOuPSvtnDXGjHCEXzwLjPKNKCvTF2h585Nl3zlMw/G/ZSlg0sjdy0MHOjIMMRjTKidzICNbNZgEKBe7BlW/MUBmaV4Vca+om2I8kcnC/7fBOevmZG810/zWlsPgt6nStroIMFeq1Vmqc4GnFa2GZcpKIpD7QJwAfcTfN0ALBlXgaXzO0/3bZduN2rMhoUygVPGncEcsnMfFKyknbuUXW/RHNxoOdS3k7n18yi6ZoQAeV+AVeKgHCinrGoKmmWHNTyvnZ/AXtkceuLcu99PaZidAErQdTsxxtCAUfPD++2Qs1LKwr/J9z1cnJM7TybBB+J4uNyWVLIV4WhyHGL4SZmCT2Apf0ZbqPWFKaSkelg96S5xQ0+epMxv4r6qsZoIBBJjijboWfl6UTgSzqcaDeQUbajhKTEZl65zqq00y3BG51i6AuLpjkhKNVitc/Xhu1dOT5YEja3wGsSLL2axSqSk2PG80PmprHduTkLArQkeEihED3UhtMVC40CvRcjr17FTxRjkDI2iZfDYWIxOIFDUZ1LPwiJXP3Egoi+HRFSZqQ5Uyv6WaET3a+drQFHHw+bliWYbRodx/qqb8t6ubnox/i9iaQ+eYqRXrKz58uXqBcJBhpa3+uU+Vj92qBBBxcCReZ+X5xYf9Kv8JOmjturFG1rG31qPrFuEKT+6xNSYa8qWP7rk3uKo/SZES03f4fwxDmP1/SxZtVtufWqkvvYM7ml6zwOj6fY2+65+3x2a3A/stAVtYjWLtqJbbzjzj2nSEcXr7+QN3TP0gRotbU+iLwgkrP97FPnj8ri3vmnQgqquvKu5C4dqNo6lwQuB/PaS9MF+vfHJlkDaTbk0SqfiWwjSnGJ4wQvGUCxSP2GUio4HoMmyuBy7gQ/UsU9ijuoVt/Geu3OwTpa8B7mmiWzcd5cwq/kjxJ9l460dhcyvLfoSWCDRVyvQd2kDAPRxqZ3FPKu4RNqOXr5EnqMqCeA3p6kp+copCgQUEEJxduisgYzNxdjgViWYbYzOgepKCq0jqOIrg7Rud3vD152VhbLXORyqmoYVZ3sNWTMpPCdD1mO2zkierl2JZRf78EpYUq6rzdGS9ZXApYSMH0iRIrC9rxHdHiMNPm5WVU6clVIDbcvyhMoGu";
		String encodedPassword = "U2FsdGVkX19rzutpu67A2hGyjdoLGSnWEtTGcfSKK7w4SUATx2y3bB0HdvXpTrODvJjAa73eJUDF+oRMYVyh6k9EIBCW8XI+1aKbtQGNVnJtRoW7xrpkl3TdgC++x0e4UPjB+LBA79LK8gHTr4Ad2Kd06dWTxwpqAgsLU3VI6ZUXvoctUk9ffxCHzZocQBBHnEInovrp+/kUHZxYWZkS6/2wZiY60PH9gYyatenh472mNgS9h0sH3FW38HFVKudhxj4uIiYr+gO3Y6XxTq9th7ykhV4FwpYXL9xbKptE2H8=";
		int iterations = 100000;
		
		String expected = "{\"URLs\":[{\"label\":\"\",\"url\":\"gmail.com\"}],\"fields\":[{\"value\":\"mygmailpassword\",\"name\":\"password\",\"type\":\"P\",\"designation\":\"password\"},{\"value\":\"\",\"name\":\"username\",\"type\":\"T\",\"designation\":\"username\"}]}";
		OnePass onePass = new OnePass(encodedKey, iterations);
		Assert.assertEquals(expected, onePass.decrypt(masterpass, encodedPassword));
	}
	
	@Test public void shouldDecryptPasswordWithBackslash() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		String masterpass = "demo";
		String encodedKey = "U2FsdGVkX1812zKPQ4SZijGOuvfOH2fdlVBU9vrLC+wkrI0I3+cMxC/eVGIPyPTgr5Bw4ijiJ36HnN5EQJscZ6c1eh65v/VFH4dIf+ABdSFCmbCXEbmGq2hxFOMkNA981N3Ssk0NxzXL14+Zagm2nTFQPymP+UWEuuod71tXVj5qPy5PpkCRElf1nwdVva0UIAHVJTDo7txNgabCgft64ZRRpBa8BCifu/yMpHU52CcVYR+vAolubo563CewsOAu1dofqBK/Tim3YtOKBRUp1P7ONgM0hhVrP1s7p5ZczXrUIJKZpdvdEZEHjHWPLgT28+a1cRM7CBJR+ZzaIDJ5jT4tTB/9PHUcLpT/GZ2Gmx/7MN8AyZd1hoo9Tin82MNdIuwiVRsz60aqG8Dtz/Frqg4DXpCbdKVl/8gluooV+qUSgyA6/pkVyh+ZMCOgTp0fHmHg07GiFh6LygcoyziKcjAeWEcOR5cYJjn0kpmCKNz+l03DuH3C7VfbEJJlS/4dUFtABRBwGKp3w5R5ku7IBUt1wKB3YAy15Pb4pgauIyvMZBlQ5p+ObZ2+zj8hA2+VENZTh2Bq6byDNW/P7DnwOAuzCT9pqIMYsay+X9jTVW7NVNskZuhyjWiQpna18h3yh/RIkqoEXzzDi0hclS12dITGJp6XihEtZ/8FM+HFuRhuWxSYRmEcrJo+4qpkPoOXFbjZc/Pi6/24xHVEapexzShyaMquiSdP56pBntGB05USiPAHtcDaohsj+LKmQ6tB464XjMRqrO86GmxDYNmei4gIkb4ZRgR87twADCzC95uRRXcJhxqgRdFLEC/+FKu6DFDSQHbH3zGU1WPl0xdLgxzaeBnDm5tnaK/dmw/Sodxp1HMp+MVJeNULgnUaFP2u3EHsOuCIQEVSghSQf17ueaA7vnllJ+3+mewmd63kTjWHMGM6mjFTd05qUcb6gcsRgI6YWMrz54CfXU+ZUJejZqkvpxxk+9AV0hnt9DuC/dF2Rf1aD11ntNIvWmYLkgPub+y9b0E5BOHiuDXAEuWQKK0QTdt4AjT11XxIdAzhxFeDfuUCiWqRdZtNfzJHpXaDJyKHwS1A/C0vYci/r2WEbc4qe9ky3KsaxYtNPSG8ZWMPnqQ/5iTF+WgTWCBTgybWxBszUMa3I8SFxZ8D8vuhmuL/FYE7WWumyLruQNgPy8HsmUwN/derxw/n4woGznexJQSyNHDKHHrzeGGkvS1eCgVYO9mGbC5ZJpyMzhpYxjNWeFX0hoj0Vmxub795cSK/TyCGvhAIYfkJqapT6DQcEfIn4Qiy2rHB9OtSqN1Am4BvchZ9F8z/YSC6T+xUSkgcacOmhkMhzJ9GvJO5FTLYd6qkMLsRQIW+NTPSFkwIjbwpEi35F87oni7FbjJH8QaJ";
		String encodedPassword = "U2FsdGVkX188xHPQvxV+Ru9cydhl9bMRNhpu1MeVVANSHY\\/DJrpPdzDUGauLsUz1RQSAHgV5W8LjqZkHtn1JJNejePdjkdf0oD7Q74TqlueH0QT9Ab0eadyaN4GzkU3iEW\\/12jieg5LzaQ1hwK93Jw==";
		int iterations = 28985;
		
		String expected = "{\"password\":\"teste\",\"sections\":[{\"title\":\"Related Items\",\"name\":\"linked items\"}]}";
		OnePass onePass = new OnePass(encodedKey, iterations);
		String result = onePass.decrypt(masterpass, encodedPassword);
		Assert.assertEquals(expected, result);
	}
	
	@Test public void shouldEncryptData() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		String masterpass = "demo";
		String encodedKey = "U2FsdGVkX1812zKPQ4SZijGOuvfOH2fdlVBU9vrLC+wkrI0I3+cMxC/eVGIPyPTgr5Bw4ijiJ36HnN5EQJscZ6c1eh65v/VFH4dIf+ABdSFCmbCXEbmGq2hxFOMkNA981N3Ssk0NxzXL14+Zagm2nTFQPymP+UWEuuod71tXVj5qPy5PpkCRElf1nwdVva0UIAHVJTDo7txNgabCgft64ZRRpBa8BCifu/yMpHU52CcVYR+vAolubo563CewsOAu1dofqBK/Tim3YtOKBRUp1P7ONgM0hhVrP1s7p5ZczXrUIJKZpdvdEZEHjHWPLgT28+a1cRM7CBJR+ZzaIDJ5jT4tTB/9PHUcLpT/GZ2Gmx/7MN8AyZd1hoo9Tin82MNdIuwiVRsz60aqG8Dtz/Frqg4DXpCbdKVl/8gluooV+qUSgyA6/pkVyh+ZMCOgTp0fHmHg07GiFh6LygcoyziKcjAeWEcOR5cYJjn0kpmCKNz+l03DuH3C7VfbEJJlS/4dUFtABRBwGKp3w5R5ku7IBUt1wKB3YAy15Pb4pgauIyvMZBlQ5p+ObZ2+zj8hA2+VENZTh2Bq6byDNW/P7DnwOAuzCT9pqIMYsay+X9jTVW7NVNskZuhyjWiQpna18h3yh/RIkqoEXzzDi0hclS12dITGJp6XihEtZ/8FM+HFuRhuWxSYRmEcrJo+4qpkPoOXFbjZc/Pi6/24xHVEapexzShyaMquiSdP56pBntGB05USiPAHtcDaohsj+LKmQ6tB464XjMRqrO86GmxDYNmei4gIkb4ZRgR87twADCzC95uRRXcJhxqgRdFLEC/+FKu6DFDSQHbH3zGU1WPl0xdLgxzaeBnDm5tnaK/dmw/Sodxp1HMp+MVJeNULgnUaFP2u3EHsOuCIQEVSghSQf17ueaA7vnllJ+3+mewmd63kTjWHMGM6mjFTd05qUcb6gcsRgI6YWMrz54CfXU+ZUJejZqkvpxxk+9AV0hnt9DuC/dF2Rf1aD11ntNIvWmYLkgPub+y9b0E5BOHiuDXAEuWQKK0QTdt4AjT11XxIdAzhxFeDfuUCiWqRdZtNfzJHpXaDJyKHwS1A/C0vYci/r2WEbc4qe9ky3KsaxYtNPSG8ZWMPnqQ/5iTF+WgTWCBTgybWxBszUMa3I8SFxZ8D8vuhmuL/FYE7WWumyLruQNgPy8HsmUwN/derxw/n4woGznexJQSyNHDKHHrzeGGkvS1eCgVYO9mGbC5ZJpyMzhpYxjNWeFX0hoj0Vmxub795cSK/TyCGvhAIYfkJqapT6DQcEfIn4Qiy2rHB9OtSqN1Am4BvchZ9F8z/YSC6T+xUSkgcacOmhkMhzJ9GvJO5FTLYd6qkMLsRQIW+NTPSFkwIjbwpEi35F87oni7FbjJH8QaJ";
		String data = "{\"password\":\"teste\",\"sections\":[{\"title\":\"Related Items\",\"name\":\"linked items\"}]}";
		int iterations = 28985;

		String encodedPassword = "U2FsdGVkX188xHPQvxV+Ru9cydhl9bMRNhpu1MeVVANSHY/DJrpPdzDUGauLsUz1RQSAHgV5W8LjqZkHtn1JJNejePdjkdf0oD7Q74TqlueH0QT9Ab0eadyaN4GzkU3iEW/12jieg5LzaQ1hwK93Jw==";
		OnePass onePass = new OnePass(encodedKey, iterations);
		String result = onePass.encrypt(masterpass, data);
		System.out.println(result);
		Assert.assertEquals(encodedPassword, result);
	}
	
}