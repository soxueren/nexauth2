package net.nexhawks.nexauth;

import java.util.*;

/*
 * Implements NexAuth session manager. NexAuthSessionManager provides session look-up feature,
 * session expiration, and so on. Uses the generational algorithm for expiration detection.
 * */
public final class NexAuthSessionManager {
    
    public static class ManagerParam{
        int maxUserSession = 16;
        double expirationTime = 10.;

        public int getMaxUserSessions() {
            return maxUserSession;
        }

        public void setMaxUserSessions(int maxUserSession) {
            this.maxUserSession = maxUserSession;
        }

        public double getExpirationTime() {
            return expirationTime;
        }

        public void setExpirationTime(double expirationTime) {
            this.expirationTime = expirationTime;
        }
        
    };
	
	protected final class Generation{
		long m_checkInterval;
		long m_lastCheckTime;

		public int m_promotionLimit;
		public Map<String, NexAuthSession> m_sessions = new HashMap<String, NexAuthSession>();
		
		protected final long now(){
			return System.currentTimeMillis();
		}
		
		public Generation(double checkInterval,
				int promotionLimit){
			m_checkInterval = (long)(checkInterval * 1000.);
			m_promotionLimit = promotionLimit;
			m_lastCheckTime = now();
		}
		
		public boolean shouldCheck(){
			return (now() - m_lastCheckTime) < m_checkInterval;
		}
		
		public void logCheck(){
			m_lastCheckTime = now();
		}
	};
	
	Object m_sync = new Object();
	Map<String, NexAuthSession> m_sessions = new HashMap<String, NexAuthSession>();
	Map<String, Map<String, NexAuthSession>> m_users = new HashMap<String, Map<String, NexAuthSession>>();
	
	int m_genIntervalsMultiply[] = {
		1, 4, 64, 1024
	};
	
	Generation m_gens[];
	
	int m_maxUserSessions = 16;
	double m_expirationTime = 10.;

	protected static long now(){
		return System.currentTimeMillis();
	}
	
	public NexAuthSessionManager(ManagerParam param) {
        m_maxUserSessions = param.getMaxUserSessions();
        m_expirationTime = param.getExpirationTime();
        
		m_gens = new Generation[m_genIntervalsMultiply.length];
		for(int i = 0; i < m_gens.length; i++){
			double interval = m_expirationTime * (double)m_genIntervalsMultiply[i];
			int limit = 0;
			if(i < m_gens.length - 1){
				limit = m_genIntervalsMultiply[i+1] / m_genIntervalsMultiply[i];
			}
			m_gens[i] = new Generation(interval, limit);
		}
	}
	
	public void addSession(NexAuthSession session){
		synchronized (m_sync){
			String user = session.getAuthUser();
			String sessionId = session.getSessionId();
			if(m_sessions.containsKey(sessionId)){
				// just replacing existing session.
				
				// first, remove the existing session from its generation.
				NexAuthSession oldSession = m_sessions.get(sessionId);
				m_gens[oldSession.m_generation].m_sessions.remove(sessionId);
				
				// replace existing session
				m_sessions.put(sessionId, session);
				
				Map<String, NexAuthSession> userSessions = m_users.get(user);
				userSessions.put(sessionId, session);
				
				// add to the first generation pool
				session.m_generation = 0;
				session.m_generationLimit = m_gens[0].m_promotionLimit;
				m_gens[0].m_sessions.put(sessionId, session);
				
			}else{
			
				// really adding a new session.
				m_sessions.put(sessionId, session);
				
				Map<String, NexAuthSession> userSessions = m_users.get(user);
				if(userSessions == null){
					userSessions = new HashMap<String, NexAuthSession>();
					m_users.put(user, userSessions);
				}
				
				userSessions.put(sessionId, session);
				
				// add to the first generation pool
				session.m_generation = 0;
				session.m_generationLimit = m_gens[0].m_promotionLimit;
				m_gens[0].m_sessions.put(sessionId, session);
				
				// if the user has too many sessions,
				// close the oldest one.
				while(userSessions.size() > m_maxUserSessions){
					NexAuthSession oldestSession = null;
					double oldestAge = -1;
					for(NexAuthSession sess: userSessions.values()){
						double age = sess.getIdleSeconds();
						if(age > oldestAge){
							oldestSession = sess;
							oldestAge = age;
						}
					}
					
					removeSession(oldestSession, true);
				}
			
			}
			
			checkExpiration();
		}
		
	}

	public void removeSession(NexAuthSession session, boolean removeFromGeneration){
		String user = session.getAuthUser();
		String sessionId = session.getSessionId();
		synchronized(m_sync){
			if(!m_sessions.containsKey(sessionId))
				return;
			
			m_sessions.remove(sessionId);
			
			Map<String, NexAuthSession> userSessions = m_users.get(user);
			if(userSessions == null)
				return;
			
			userSessions.remove(sessionId);
			
			if(userSessions.isEmpty()){
				m_users.remove(user);
			}
			
			if(removeFromGeneration)
				m_gens[session.m_generation].m_sessions.remove(sessionId);
		}
	}
	
	public NexAuthSession getSession(String sessId){
		synchronized(m_sync){
			return m_sessions.get(sessId);
		}
	}
	
	public void checkExpiration(){
		synchronized(m_sync){
			long expiredLastUsageTime = now() - (long)(m_expirationTime * 1000.);
			for(int i = 0; i < m_gens.length; i++){
				Generation gen = m_gens[i];
				if(!gen.shouldCheck())
					continue;
				gen.logCheck();
				
				// cannot remove element while enumerating, so elements to remove are
				// temporary added to trash.
				int trashSize = Math.max((gen.m_sessions.size() + 1) / 2, 16);
				ArrayList<NexAuthSession> trash = new ArrayList<NexAuthSession>(trashSize);
				
				for(NexAuthSession session: gen.m_sessions.values()){
					if(session.getLastUsage() > expiredLastUsageTime){
						// not expired
						if(session.m_generationLimit > 0){
							assert i < m_gens.length-1;
							session.m_generationLimit -= 1;
							if(session.m_generationLimit == 0){
								// move this session to the next generation
								trash.add(session);
								m_gens[i+1].m_sessions.put(session.getSessionId(), session);
								session.m_generation = i + 1;
								session.m_generationLimit = m_gens[i + 1].m_promotionLimit;
							}
						}
					}else{
						// expired
						trash.add(session);
						removeSession(session, false);
					}
				}
				
				for(NexAuthSession session: trash){
					gen.m_sessions.remove(session.getSessionId());
				}
				
				
			}
		}
	}
	
}
