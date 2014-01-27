package net.nexhawks.nexauth;

import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.*;

import org.apache.commons.codec.binary.Base64;

public class NexAuthSession {

	public static final String CIPHER_ALGORITHM = "AES";
	public static final String CIPHER_MODE = CIPHER_ALGORITHM + "/CBC/PKCS5PADDING";
	
	String m_sessionId;
	Key m_aesKey;
	long m_lastUsage;
	long m_createdAt;
	String m_authUser;
	long m_seq;
    int m_keySize;
	
	public int m_generationLimit;
	public int m_generation;
	
	protected static final long now(){
		return System.currentTimeMillis();
	}
	
	public NexAuthSession() {
	}
	
	public void init(String sessionId, byte[] key, String authUser){
        m_keySize = key.length * 8;
		m_aesKey = new SecretKeySpec(key, CIPHER_ALGORITHM);
		m_sessionId = sessionId;
		m_lastUsage = now();
		m_createdAt = m_lastUsage;
		m_authUser = authUser;
		m_seq = 0;
		
		init();
	}
	
	public void init(){
		
	}

	public String getSessionId() {
		return m_sessionId;
	}

	public String getAuthUser() {
		return m_authUser;
	}

	public long getSeq() {
		return m_seq;
	}
	
	public long getLastUsage(){
		return m_lastUsage;
	}
	
	public double getIdleSeconds(){
		return (double)(now() - m_lastUsage) / 1000.;
	}
	
	public void reportActivity(){
		m_lastUsage = now();
	}
	
	public void setSeq(long seq) throws NexAuthProtocolException{
		if(seq < m_seq){
			throw new NexAuthProtocolException("Cannot set the seq. number to the same or older than the current one.");
		}
		m_seq = seq;
	}

	public String encrypt(byte[] bytes) throws NexAuthProtocolException{
		try{
			Cipher cipher = Cipher.getInstance(CIPHER_MODE);
			cipher.init(Cipher.ENCRYPT_MODE, m_aesKey);
			
			byte[] iv = cipher.getIV();
			byte[] outBytes = cipher.doFinal(bytes);
			
			byte[] ret = new byte[iv.length + outBytes.length];
			
			System.arraycopy(iv, 0, ret, 0, iv.length);
			System.arraycopy(outBytes, 0, ret, iv.length, outBytes.length);
            
            //throw new GeneralSecurityException();
			
			return Base64.encodeBase64String(ret);
		} catch (GeneralSecurityException e) {
			throw new NexAuthProtocolException(String.format(
                    "AES encryption failed (key length = %d, in bytes = %d).", m_keySize, bytes.length), e);
		} 
	}
	
	public byte[] decrypt(String str) throws NexAuthProtocolException{
        byte[] bytes = Base64.decodeBase64(str);
        if(bytes.length < 16)
            throw new NexAuthProtocolException("IV not found.");
        
		try{
			Cipher cipher = Cipher.getInstance(CIPHER_MODE);
			cipher.init(Cipher.DECRYPT_MODE, m_aesKey,
					new IvParameterSpec(bytes, 0, 16));
			
			byte[] outBytes = cipher.doFinal(bytes, 16, bytes.length - 16);
			return outBytes;
			
		} catch (GeneralSecurityException e) {
			throw new NexAuthProtocolException(String.format(
                    "AES decryption failed (key length = %d, in bytes = %d).", m_keySize, bytes.length), e);
		} 
	}
	
}
