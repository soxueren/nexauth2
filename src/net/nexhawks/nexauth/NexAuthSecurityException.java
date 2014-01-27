/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package net.nexhawks.nexauth;

/**
 *
 * @author tcpp
 */
public class NexAuthSecurityException extends NexAuthException {

    public NexAuthSecurityException() {
        super("Access denied.");
    }

    public NexAuthSecurityException(String message) {
        super(message);
    }

    public NexAuthSecurityException(String message, Throwable cause) {
        super(message, cause);
    }

    public NexAuthSecurityException(Throwable cause) {
        super("Access denied.", cause);
    }
    
}
