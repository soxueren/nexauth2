package net.nexhawks.nexauth;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.*;

public final class NexAuthParams {

	private static final ObjectMapper m_mapper = new ObjectMapper();
	
	byte[] m_bytes;
	
	public NexAuthParams() {
		m_bytes = "null".getBytes();
	}
	
	public NexAuthParams(Object obj) {
		setObject(obj);
	}
	
	public void setJSON(byte[] bytes){
		m_bytes = bytes;
	}
	
	public byte[] getJSON(){
		return m_bytes;
	}
	
	public void setObject(Object obj){
		try {
			m_bytes = m_mapper.writeValueAsBytes(obj);
		} catch (JsonProcessingException e) {
			throw new RuntimeException("Failed to serialize object.", e);
		}
	}
	
	public <T extends Object> Object getObject(Class<T> cls) throws NexAuthProtocolException{
		if(m_bytes.length == 0)
			return null;
		try {
			return m_mapper.readValue(m_bytes, cls);
		} catch (JsonParseException e) {
			throw new NexAuthProtocolException("Invalid data format.", e);
		} catch (JsonMappingException e) {
			throw new RuntimeException("Failed to map JSON data.", e);
		} catch (IOException e) {
			throw new RuntimeException("Unexpected I/O error.", e);
		}
	}

}
