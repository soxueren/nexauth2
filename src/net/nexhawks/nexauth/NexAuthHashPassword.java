package net.nexhawks.nexauth;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.codec.digest.DigestUtils;

public final class NexAuthHashPassword {

	String[] m_salts;
	String m_hash;
	
	public NexAuthHashPassword(String[] validSalts, String hash) {
		m_salts = validSalts;
		m_hash = hash;
	}
	
	public boolean validate(String pass){
		for(String salt: m_salts){
			String txt = salt + ":" + pass;
			String correctHash = DigestUtils.sha256Hex(txt);
			if(m_hash.equals(correctHash))
				return true;
		}
		return false;
	}

}
