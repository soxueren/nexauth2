package net.nexhawks.nexauth;

import java.util.*;
import java.security.*;

public final class NexAuthSaltManager {

	long m_expirationTime = 15 * 1000;
	long m_minimumLifeToGive = 5 * 1000;
	final SecureRandom m_random = new SecureRandom();
	
	final TreeMap<Long, String> m_salts = new TreeMap<Long, String>();
	
	public NexAuthSaltManager() {
		
	}
	
	private long getCurrentTime(){
		return new Date().getTime();
	}
	
	private String generateNewSalt(){
		synchronized (m_random){
			long rnd = m_random.nextLong();
			String salt = Long.toHexString(rnd);
			salt = "0000000000000000".substring(0, 16-salt.length()) + salt;
			return salt;
		}
	}
	
	private void expireOldSalts(){
		synchronized (m_salts){
			long curTime = getCurrentTime();
			while(!m_salts.isEmpty()){
				// get the oldest salt
				Map.Entry<Long, String> entry = m_salts.firstEntry();
				long life = curTime - entry.getKey();
				if(life > m_expirationTime){
					// expired
					m_salts.remove(entry.getKey());
					continue;
				}else{
					break;
				}
			}
		}
	}
	
	public String publicSalt(){
		synchronized (m_salts){
			expireOldSalts();
			
			long curTime = getCurrentTime();
			if(!m_salts.isEmpty()){
				// get the most recent salt
				Map.Entry<Long, String> entry = m_salts.lastEntry();
				long life = curTime - entry.getKey();
				if(life < m_minimumLifeToGive){
					return entry.getValue();
				}
			}
		
			String newSalt = generateNewSalt();
			m_salts.put(new Long(curTime), newSalt);
			return newSalt;
		}
	}
	
	public String[] validSalts(){
		synchronized (m_salts){
			expireOldSalts();
			
			String[] validSalts = new String[m_salts.size()];
			int i = 0;
			for(String salt: m_salts.values()){
				validSalts[i++] = salt;
			}
			
			return validSalts;
		}
	}

}
