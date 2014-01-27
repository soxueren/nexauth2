package net.nexhawks.nexauth;

public class NexAuthInvalidChunkException extends NexAuthProtocolException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 873386894476292148L;

	public NexAuthInvalidChunkException() {
		super("NexAuth chunk corrupted.");
	}

	public NexAuthInvalidChunkException(String arg0) {
		super(arg0);
	}

	public NexAuthInvalidChunkException(Throwable arg0) {
		super("NexAuth chunk corrupted.", arg0);
	}

	public NexAuthInvalidChunkException(String arg0, Throwable arg1) {
		super(arg0, arg1);
	}

}
