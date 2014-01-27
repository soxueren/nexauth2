package net.nexhawks.nexauth;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;

import javax.crypto.*;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.*;

public final class NexAuthPubKeyAuth {
	public static final String CIPHER_ALGORITHM = "RSA";
	public static final String CIPHER_MODE = CIPHER_ALGORITHM + "/ECB/PKCS1PADDING";
	
	private PrivateKey m_privateKey;
	private PublicKey m_publicKey;
	
	private String m_publicKeyString;
	
	//private final static Logger LOGGER = Logger.getLogger(NexAuthPubKeyAuth.class .getName()); 
	
	public NexAuthPubKeyAuth(){
		super();
		
		try {
			
			KeyPairGenerator gen = KeyPairGenerator.getInstance(CIPHER_ALGORITHM);
			RSAKeyGenParameterSpec genSpec = new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(0x10001));
			gen.initialize(genSpec);
			
		
			KeyPair pair = gen.generateKeyPair();
			m_privateKey = pair.getPrivate();
			m_publicKey = pair.getPublic();
			
			
			// generate public key string
			byte[] pubKey = m_publicKey.getEncoded();
			pubKey = Arrays.copyOfRange(pubKey, 33, 33+256);
			m_publicKeyString = new String(Hex.encodeHex(pubKey, true));
			
			
		} catch (GeneralSecurityException e) {
			throw new RuntimeException("RSA key-pair generation failed.", e);
		} 
		
	}
	
	public String getPublicKeyString() {
		return m_publicKeyString;
	}
	
	public byte[] decrypt(String body) throws NexAuthProtocolException {
		try{
			byte[] codeBytes = Hex.decodeHex(body.toCharArray());
			
			Cipher cipher = Cipher.getInstance(CIPHER_MODE);
			cipher.init(Cipher.DECRYPT_MODE, m_privateKey);
			
			byte[] clearBytes = cipher.doFinal(codeBytes);
			//LOGGER.log(Level.INFO, String.format("Decrypt length: %d",clearBytes.length));
			//LOGGER.log(Level.INFO, "Decrypted: "+ new String(clearBytes));
			//LOGGER.log(Level.INFO, "DecryptedHex: "+ new String(Hex.encodeHex(clearBytes)));
			return clearBytes;
		}catch(GeneralSecurityException e){
			throw new NexAuthProtocolException("Decryption failure.", e);
		} catch (DecoderException e) {
			throw new NexAuthProtocolException("Bad format.", e);
		}
	}
	
}
