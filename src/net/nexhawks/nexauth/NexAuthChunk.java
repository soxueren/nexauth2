package net.nexhawks.nexauth;

import java.io.*;
import java.nio.charset.*;
import java.util.*;

public final class NexAuthChunk {

	private static final Charset UTF8_CHARSET = Charset.forName("UTF-8");
	
	protected byte[] m_bytes = null;
	protected String m_string = null;
	
	public NexAuthChunk(byte[] bytes){
		m_bytes = bytes;
	}
	
	public NexAuthChunk(String str){
		m_string = str;
	}
	
	public byte[] getBytes(){
		if(m_bytes == null){
			m_bytes = m_string.getBytes(UTF8_CHARSET);
		}
		return m_bytes;
	}
	
	public String getString(){
		if(m_string == null){
			m_string = new String(m_bytes, UTF8_CHARSET);
		}
		return m_string;
	}
	
	@Override
	public String toString() {
		return getString();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(getBytes());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		NexAuthChunk other = (NexAuthChunk) obj;
		if (!Arrays.equals(getBytes(), other.getBytes()))
			return false;
		return true;
	}

	public static NexAuthChunk[] explode(byte[] bytes) throws NexAuthInvalidChunkException{
		ArrayList<NexAuthChunk> chunks = new ArrayList<NexAuthChunk>();
		int i = 0;
		int length = bytes.length;
		
		try{
			while(i < length){
				int siz = 0, shift = 0;
				while(i < length){
					byte b = bytes[i++];
					if((b & 0x80) != 0){
						siz |= (((int)b & 0x7f) << shift);
						shift += 7;
					}else{
						siz |= (int)b << shift;
						break;
					}
				}
				
				NexAuthChunk chunk = new NexAuthChunk(Arrays.copyOfRange(bytes, i, i + siz));
				//Logger.getLogger("NexAuthChunk").log(Level.INFO, 
				//		String.format("%d: %s", chunks.size(), chunk.getString()));
				chunks.add(chunk);
				i += siz;
			}
		}catch(IndexOutOfBoundsException e){
			throw new NexAuthInvalidChunkException("Unexpected end of data.", e);
		}
		
		NexAuthChunk[] arr = new NexAuthChunk[chunks.size()];
		System.arraycopy(chunks.toArray(), 0, arr, 0, chunks.size());
		return arr;
	}
	
	public static byte[] implode(Object[] chunks, byte[] header){
		ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
		try {
			outBytes.write(header);
		} catch (IOException e1) {
            // shouldn't come here
			throw new RuntimeException(e1);
		}
		
		try{
			for(Object chunk: chunks){
				byte[] bytes = null;
				if(chunk == null){
					bytes = new byte[0];
				}else if(chunk instanceof byte[]){
					bytes = (byte[])chunk;
				}else if(chunk instanceof NexAuthChunk){
					bytes = ((NexAuthChunk)chunk).getBytes();
				}else{
					String str = chunk.toString();
					bytes = str.getBytes(UTF8_CHARSET);
				}
				int size = bytes.length;
				do{
					if(size >= 0x80){
						outBytes.write((size & 0x7f) | 0x80);
					}else{
						outBytes.write(size);
					}
					size >>= 7;
				}while(size > 0);
				outBytes.write(bytes);
			}
		}catch(IOException e){
            // shouldn't come here
			throw new RuntimeException(e);
		}
		
		return outBytes.toByteArray();
	}

	public static byte[] implode(Object[] chunks, String header){
		return implode(chunks, header.getBytes());
	}
	
	
	public static byte[] implode(Object[] chunks){
		return implode(chunks, new byte[0]);
	}
	
}
