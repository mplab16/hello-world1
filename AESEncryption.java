package com.ftr.esb.csid.utils;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.mail.internet.MimeUtility;


/*
 * This example implements a class for encrypting strings using AES. The class is created with 
 * an md5 algorithm generated key and can be used repeatedly to encrypt strings using that key 
 * or pass phrase. 
 */

/**
 * @author dpk390
 *
 */
public class AESEncryption implements AESEncryptDecrypt{
	Cipher ecipher;
	SecretKeySpec key = null;
	IvParameterSpec ipsec = null;
	SecureRandom random = null;
	byte[] ivBytes = new byte[16];
	byte[] cipher_text = new byte[32];
	
	/**
	 * Constructor used to create this object. Responsible for setting and initializing this
	 * object's encrypter Chipher instances given a key and algorithm.
	 * 
	 * @param key
	 *            Key used to initialize the encrypter instances.
	 */
	
	public AESEncryption(String passPhrase) throws Exception { 
		
		try {
			String key_hash = asHex(generateKey (passPhrase)).substring(0,16);
		
			// Code to generate SecretKey to be passed to instantiate a Cipher
			key = new SecretKeySpec(key_hash.getBytes(),"AES");
	  
			// Instantiating Cipher
			ecipher = Cipher.getInstance("AES/CBC/NoPadding");
		}
		catch (Exception e)	{
			// "Problem has been detected in AESEncryption()"
		}
	}
	
	public byte[] generateKey (String passPhrase) throws Exception	{
		byte[] key_hash_byte = new byte[16];
				
		try {
			// Code to generate key using md5 algorithm
			MessageDigest md5 = MessageDigest.getInstance("md5");
			md5.reset();
			key_hash_byte = md5.digest(passPhrase.getBytes());

		}
		catch (Exception e)	{
			// "Exception occurred during Key generation for generateKey()"
		}
		return key_hash_byte;
	}
	
	/**
	  * Turns array of bytes into string
	  *
	  * @param buf	Array of bytes to convert to hex string
	  * @return	Generated hex string
	  */
	public static String asHex (byte buf[]) {
		StringBuffer strbuf = new StringBuffer(buf.length * 2);
		int i;

		for (i = 0; i < buf.length; i++) {
			if (((int) buf[i] & 0xff) < 0x10)
				strbuf.append("0");

			strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
		}

		return strbuf.toString();
	}
	
	  /**
	   * Accepts string, encrypts it and returns array of bytes
	   *
	   * @param  String to be encrypted
	   * @return	returns encrypted value in array of bytes
	   */
	  public String encrypt(String str)
	  {
		    
		  try {
			  // Generating Initialization Vector
			  random = SecureRandom.getInstance("SHA1PRNG");
			  random.nextBytes(ivBytes);
			  ipsec = new IvParameterSpec(ivBytes);

			  // Initializing Cipher
			  ecipher.init(Cipher.ENCRYPT_MODE, key, ipsec, random);
	 	      
			  // Code for padding the string
			  StringBuffer strbuf = new StringBuffer();
			  int i;
		        
			  for (i = 0; i < (((str.length()/16)+1)*16); i++) {
				  if (i >= str.length())	
					  strbuf.append("\0");
				  else
					  strbuf.append(str.charAt(i));
			  }
			  String str1 = strbuf.toString();			
				
			  // Encode the string into bytes
			  byte[] utf= str1.getBytes();
				
			  // Encrypt the data by using the encrypted string
			  byte[] cipher_text = new byte[(((str.length()/16)+1)*16)]; 
			  cipher_text = ecipher.doFinal(utf);
			  
			  byte[] encrypted_text = concatenate(ivBytes, cipher_text);
			  
			  String base64_enc_text = base64_encode(encrypted_text);
			  base64_enc_text = base64_enc_text.replaceAll("\r", "").replaceAll("\n", "");
			  return base64_enc_text;
		  }
		  catch (Exception e)	{
			  // "Exception during AES Encryption of the string"
		  }
		return null;
	  }
	  
	  public byte[] concatenate (byte[] ivBytes, byte[] cipher_text) {
		  byte[] encrypted_text = new byte[ivBytes.length+cipher_text.length];

		  // Prepend ivBytes to encrypted data
		  System.arraycopy(ivBytes, 0, encrypted_text, 0, ivBytes.length);
		  System.arraycopy(cipher_text, 0, encrypted_text, ivBytes.length, cipher_text.length);

		  return encrypted_text;
	  }
	  
	  public String base64_encode(byte[] encrypted_text) throws Exception {
		  String base64_enc_text = null;
		  
		  try {
			  // Code to generate a base64 encoded String
			  ByteArrayOutputStream bos = new ByteArrayOutputStream();
			  OutputStream os = MimeUtility.encode(bos,"base64");
			  os.write(encrypted_text);
			  os.close(); 
			  base64_enc_text = bos.toString();
			  bos.close();
		  }
		  catch (Exception e)	{
			  // "Exception occurred during base64 encoding of the encrypted data."
		  }
		
		  return base64_enc_text;
	  }
	  public String decrypt(String str) {
		  str = "";
		  return str;
	  }
}