/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package net.nexhawks.nexauth;

/**
 *
 * @author tcpp
 */
public class NexAuthException extends Exception {

    public NexAuthException(Throwable cause) {
        super(cause);
    }

    public NexAuthException() {
    }

    public NexAuthException(String message) {
        super(message);
    }

    public NexAuthException(String message, Throwable cause) {
        super(message, cause);
    }
    
}
