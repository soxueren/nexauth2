/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package net.nexhawks.nexauth;

/**
 *
 * @author tcpp
 */
public class NexAuthProtocolException extends NexAuthException {

    public NexAuthProtocolException() {
        super("Protocol error.");
    }

    public NexAuthProtocolException(String message) {
        super(message);
    }

    public NexAuthProtocolException(String message, Throwable cause) {
        super(message, cause);
    }

    public NexAuthProtocolException(Throwable cause) {
        super("Protocol error.", cause);
    }
    
}
