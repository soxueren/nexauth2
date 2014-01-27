/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package net.nexhawks.nexauth;

/**
 *
 * @author tcpp
 */
public class NexAuthInvalidCommandException extends NexAuthException {

    /**
     * Creates a new instance of
     * <code>NexAuthInvalidCommandException</code> without detail message.
     */
    public NexAuthInvalidCommandException() {
        super("Invalid command.");
    }

    /**
     * Constructs an instance of
     * <code>NexAuthInvalidCommandException</code> with the specified detail
     * message.
     *
     * @param msg the detail message.
     */
    public NexAuthInvalidCommandException(String msg) {
        super(msg);
    }
}
