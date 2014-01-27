package net.nexhawks.nexauth;

import java.security.SecureRandom;
import java.util.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.sun.org.apache.xml.internal.security.utils.Base64;
import java.io.InputStream;

import java.lang.reflect.Method;
import java.util.logging.Level;
import java.util.logging.Logger;


import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.databind.*;
import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import java.lang.reflect.InvocationTargetException;

/**
 * Servlet implementation class NexAuthServlet
 */
public class NexAuthServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    public static class AuthResult {

        /**
         * Authenticated user.
         */
        public String user;
        /**
         * Message derived to the authorization client.
         */
        public String message;
    };

    public static class Command {

        /**
         * Name of the Command. When command "xxxCmd" is invoked,
         * cmd_xxxCmd(Command) will be invoked.
         */
        public String cmd;
        public NexAuthParams params;
        public NexAuthSession session;
    };

    public static class ErrorResponse {

        public static class ErrorObject {

            private String message;

            public String getMessage() {
                return message;
            }

            public void setMessage(String message) {
                this.message = message;
            }
        };
        private ErrorObject _error;

        public ErrorObject get_error() {
            return _error;
        }

        public void set_error(ErrorObject _error) {
            this._error = _error;
        }
    };
    private static final String ACT_REQUEST_PUBLICKEY = "QPBK";
    private static final String ACT_REQUEST_AUTHORIZATION = "QATH";
    private static final String ACT_REQUEST_COMMAND = "QCOM";
    private static final String ACT_RESPONSE_PUBLICKEY = "RPBK";
    private static final String ACT_RESPONSE_ERROR = "RERR";
    private static final String ACT_RESPONSE_CONNECTED = "RCON";
    private static final String ACT_RESPONSE_COMMAND_DONE = "RRES";
    private NexAuthPubKeyAuth m_pubkeyAuth = null;
    private NexAuthSaltManager m_saltManager = null;
    private NexAuthSessionManager m_sessions = null;
    private final Map<String, Method> m_cmds = new HashMap<String, Method>();
    private final SecureRandom m_random = new SecureRandom();
    private String m_proxyPage = null;
    protected int m_maxBodyLength = 1024 * 1024;

    /**
     * @see HttpServlet#HttpServlet()
     */
    public NexAuthServlet() {
        super();

    }

    @Override
    public void init() throws ServletException {
        super.init();


        log("Starting NexAuth endpoint...");

        m_pubkeyAuth = new NexAuthPubKeyAuth();
        m_saltManager = new NexAuthSaltManager();
        m_sessions = new NexAuthSessionManager(getSessionManagerParam());

        log("NexAuth endpoint ready.");

    }

    /**
     * Override to change the session manager parameter.
     *
     * @return Session manager parameter used to instantiate a session manager.
     */
    protected NexAuthSessionManager.ManagerParam getSessionManagerParam() {
        return new NexAuthSessionManager.ManagerParam();
    }

    /**
     * Override to modify allowed origins of the remote NexAuth call. The origin
     * specified can call
     *
     * @return List of origins
     */
    protected String[] getAllowedOrigins() {
        final String[] origins = {};
        return origins;
    }

    /**
     * Override to modify authorization
     *
     * @param user
     * @param hashPass
     * @return
     * @throws Exception
     */
    protected String authorizeUser(String user, NexAuthHashPassword hashPass) throws NexAuthSecurityException {
    	// TODO: fix the misuage of words: this should be "authenticate" instead of "authorize"
        if (user.equals("TestUser")) {
            if (hashPass.validate("TestHash")) {
                return "Welcome";
            } else {
                throw new NexAuthSecurityException("Invalid password.");
            }
        } else {
            throw new NexAuthSecurityException("Invalid user name.");
        }
    }

    /**
     * Override to modify the session instantiation.
     *
     * @return NexAuthSession instance.
     */
    protected NexAuthSession createSession(String user) {
        return new NexAuthSession();
    }

    public NexAuthParams cmd_GetNexAuthVersion(Command cmd) throws NexAuthException {
        @SuppressWarnings("unused")
        class VersionObject {

            private int major;
            private int minor;
            private int revision;
            private String name;

            public int getMajor() {
                return major;
            }

            public int getMinor() {
                return minor;
            }

            public int getRevision() {
                return revision;
            }

            public String getName() {
                return name;
            }

            public String getVersion() {
                return String.format("%d.%d.%d", major, minor, revision);
            }

            public String getFullname() {
                return String.format("%s %d.%d.%d", name, major, minor, revision);
            }

            public VersionObject() {
                major = 0;
                minor = 0;
                revision = 1;
                name = "NexAuth2";
            }
        }
        Object ver = new VersionObject();
        return new NexAuthParams(ver);
    }

    private double getTimestamp() {
        return (double) (new Date().getTime()) / 1000.;
    }

    private String generateProxyPage() {
        if (m_proxyPage != null) {
            return m_proxyPage;
        }
        try {


            InputStream res = getServletContext().getResourceAsStream(
                    "/WEB-INF/classes/net/nexhawks/nexauth/NexAuthProxy.html");
            if (res == null) {
                throw new java.lang.RuntimeException("Failed to load proxy page resource because it wasn't found");
            }

            byte[] buf = new byte[16384];
            int len = res.read(buf);
            String html = new java.lang.String(buf, "UTF-8");

            String[] origins = this.getAllowedOrigins();
            String originStr;
            originStr = new ObjectMapper().writeValueAsString(origins);

            html = html.replace("__origins__", originStr);


            m_proxyPage = html;
            return m_proxyPage;
        } catch (IOException ex) {
            throw new java.lang.RuntimeException("Failed to load proxy page resource", ex);
        }
    }

    /**
     * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
     * response)
     */
    @Override
    protected final void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Generates remove NexAuth call page.
        response.setContentType("text/html");

        PrintWriter writer = response.getWriter();

        writer.println(generateProxyPage());

        writer.close();
    }

    protected final void respond(HttpServletResponse resp, String act, String body) throws IOException {
        assert act.length() == 4;

        PrintWriter writer = resp.getWriter();
        writer.print(act);
        writer.print(body);
        writer.close();
    }

    protected final String readBody(BufferedReader data,
            int maxLength) throws IOException {
        char[] buf = new char[1024];
        StringBuilder outStr = new StringBuilder();
        while (outStr.length() < maxLength) {
            int readSize = maxLength - outStr.length();
            if (readSize > buf.length) {
                readSize = buf.length;
            }

            readSize = data.read(buf);
            if (readSize == -1) {
                readSize = 0;
            }
            outStr.append(buf, 0, readSize);

            if (readSize == 0) {
                break;
            }
        }

        return outStr.toString();
    }

    protected final AuthResult authorize(String identity) throws NexAuthProtocolException, NexAuthSecurityException {

        String[] bits = identity.split(":");
        if (bits.length != 2) {
            throw new NexAuthProtocolException("Authorization string malformed");
        }

        String user = bits[0];
        String hash = bits[1];
        NexAuthHashPassword hashObj = new NexAuthHashPassword(m_saltManager.validSalts(), hash);

        AuthResult res = new AuthResult();
        res.message = authorizeUser(user, hashObj);
        res.user = user;

        return res;
    }

    protected final byte[] stripHeader(byte[] bytes, String correctHeader) throws NexAuthProtocolException {
        byte[] hdr = correctHeader.getBytes();
        if (bytes.length < hdr.length) {
            throw new NexAuthProtocolException("Header not found.");
        }

        int len = hdr.length;
        for (int i = 0; i < len; i++) {
            if (hdr[i] != bytes[i]) {
                throw new NexAuthProtocolException("Header mismatch.");
            }
        }

        byte[] body = new byte[bytes.length - hdr.length];
        System.arraycopy(bytes, hdr.length, body, 0, body.length);

        return body;
    }

    protected final String generateSessionId() {
        synchronized (m_random) {
            long rnd = m_random.nextLong();
            String salt = Long.toHexString(rnd);
            salt = "0000000000000000".substring(0, 16 - salt.length()) + salt;
            return salt;
        }
    }

    protected final Method getCommandMethod(String name) throws NoSuchMethodException {
        Method meth = m_cmds.get(name);
        if (meth != null) {
            return meth;
        }

        try {
            meth = this.getClass().getMethod("cmd_" + name, Command.class);
        } catch (SecurityException e) {
            throw new RuntimeException("Command method access denied.", e);
        }

        m_cmds.put(name, meth);
        return meth;
    }

    private String formatErrorString(Throwable e, int level) {
        StringBuilder msg = new StringBuilder();
        msg.append(e.getMessage());

        StackTraceElement[] backtrace = e.getStackTrace();

        int startIndex = 0;

        for (int times = 0; times < 6; times++) {

            msg.append("\nin ");

            int i = startIndex;
            while (i < backtrace.length) {
                StackTraceElement stack = backtrace[i];
                String classname = stack.getClassName();

                // skip core library
                if (classname.startsWith("java.")) {
                    i++;
                    continue;
                }
                if (classname.startsWith("javax.")) {
                    i++;
                    continue;
                }
                if (classname.startsWith("com.sun.")) {
                    i++;
                    continue;
                }

                break;
            }

            if (i == backtrace.length) {
                i = startIndex;
            }

            if (backtrace.length == 0) {
                msg.append("???");
                break;
            } else {
                msg.append(backtrace[i++].toString());
                if (i < backtrace.length) {
                    msg.append("\nin ");
                    msg.append(backtrace[i].toString());
                }
            }

            startIndex = i + 1;
            if (startIndex >= backtrace.length) {
                break;
            }
        }

        if (startIndex < backtrace.length) {
            msg.append("\n...");
        }

        Throwable cause = e.getCause();
        if (level > 0 && cause != null) {
            msg.append("\n\nCaused by:\n");
            msg.append(formatErrorString(cause, level - 1));
        }

        return msg.toString();
    }

    private String formatErrorString(Throwable e) {
        return formatErrorString(e, 4);
    }

    protected final void handleCommand(String act, BufferedReader data,
            HttpServletResponse response) throws ServletException, IOException, NexAuthException {
        if (act.equals(ACT_REQUEST_PUBLICKEY)) {
            StringBuilder ret = new StringBuilder();
            ret.append((long) this.getTimestamp());
            ret.append(':');
            ret.append(m_pubkeyAuth.getPublicKeyString());
            ret.append(':');
            ret.append(m_saltManager.publicSalt());
            respond(response, ACT_RESPONSE_PUBLICKEY, ret.toString());
        } else if (act.equals(ACT_REQUEST_AUTHORIZATION)) {
            String body = readBody(data, 4096);

            {
                // de-parenthesize body
                String[] bits = body.split("\\|");
                if (bits.length < 2) {
                    throw new NexAuthProtocolException("Authorization string not parenthized by |x|");
                }


                body = bits[1];
            }

            byte[] bytes = null;
            try {
                bytes = m_pubkeyAuth.decrypt(body);
            } catch (Exception e) {
                throw new NexAuthProtocolException("Bad decrypt", e);
            }
            try {
                bytes = Base64.decode(bytes);
            } catch (Base64DecodingException ex) {
                throw new NexAuthProtocolException(ex);
            }

            bytes = stripHeader(bytes, "!auth");

            NexAuthChunk[] chunks = NexAuthChunk.explode(bytes);
            if (chunks.length < 3) {
                throw new NexAuthProtocolException(String.format("Data malformed (too few chunks: %d < 3)", chunks.length));
            }

            String identity = chunks[0].getString();
            byte[] aesKey = chunks[2].getBytes();
            double timestamp = Double.parseDouble(chunks[1].getString());
            if (Double.isInfinite(timestamp) || Double.isNaN(timestamp)) {
                throw new NexAuthProtocolException("Invalid timestamp");
            }

            double diff = timestamp - getTimestamp();
            if (Math.abs(diff) > 60.) {
                throw new NexAuthProtocolException("Invalid timestamp");
            }

            AuthResult result = authorize(identity);
            String sessionId = generateSessionId();

            NexAuthSession sess;
            sess = createSession(result.user);
            sess.init(sessionId, aesKey, result.user);

            m_sessions.addSession(sess);

            Object[] retChunks = {
                sess.getSessionId(),
                result.message
            };

            byte[] concrete = NexAuthChunk.implode(retChunks, "!authorized-");

            respond(response, ACT_RESPONSE_CONNECTED,
                    sess.encrypt(concrete));

        } else if (act.equals(ACT_REQUEST_COMMAND)) {
            String body = readBody(data, m_maxBodyLength);
            int sepIndex = body.indexOf(':');
            if (sepIndex < 0) {
                throw new NexAuthProtocolException("Invalid command syntax.");
            }

            String sessionId = body.substring(0, sepIndex);
            body = body.substring(sepIndex + 1);

            NexAuthSession sess = m_sessions.getSession(sessionId);
            if (sess == null) {
                throw new NexAuthProtocolException("Invalid or expired session.");
            }

            byte[] clearBody = null;
            clearBody = sess.decrypt(body);


            clearBody = stripHeader(clearBody, "!cmd");
            NexAuthChunk[] chunks = NexAuthChunk.explode(clearBody);
            if (chunks.length < 4) {
                throw new NexAuthProtocolException("Too few chunks found.");
            }

            if (!chunks[0].getString().equals(sessionId)) {
                throw new NexAuthProtocolException("Encrypted session ID differs from the clear one.");
            }

            String seqStr = chunks[1].getString();
            long seq = Long.parseLong(seqStr);

            String cmd = chunks[2].toString();
            byte[] paramsStr = chunks[3].getBytes();
            NexAuthParams params = new NexAuthParams();
            params.setJSON(paramsStr);

            synchronized (sess) {
                sess.setSeq(seq);
                sess.reportActivity();
            }

            Command cmdObj = new Command();
            cmdObj.cmd = cmd;
            cmdObj.params = params;
            cmdObj.session = sess;

            Method meth;
            try {
                meth = getCommandMethod(cmd);
            } catch (NoSuchMethodException ex) {
                throw new NexAuthInvalidCommandException("Command not found: " + cmd);
            }
            NexAuthParams retParams = null;
            try {
                Object ret = meth.invoke(this, cmdObj);
                retParams = (NexAuthParams) ret;
            } catch (IllegalAccessException e) {
            } catch (InvocationTargetException ex) {
                try {
                    throw ex.getTargetException();
                } catch (NexAuthException e) {
                    // encrypt error
                    retParams = new NexAuthParams();

                    ErrorResponse resp = new ErrorResponse();
                    ErrorResponse.ErrorObject errObj = new ErrorResponse.ErrorObject();
                    errObj.setMessage(formatErrorString(e));
                    resp._error = errObj;

                    retParams.setObject(resp);
                } catch (RuntimeException e) {
                    throw e;
                } catch (Throwable e) {
                    // (command must not throw any checked exceptions but
                    //  NexAuthException)
                    throw new RuntimeException("Unexpected exception.", e);
                }
            }

            byte[] resParamBody = null;
            if (retParams != null) {
                resParamBody = retParams.getJSON();
            }

            Object[] resChunks = {
                sessionId,
                Long.toString(seq),
                resParamBody
            };

            byte[] resClearBytes = NexAuthChunk.implode(resChunks, "!res-");
            respond(response, ACT_RESPONSE_COMMAND_DONE,
                    sess.encrypt(resClearBytes));

        } else {

            throw new NexAuthInvalidCommandException(String.format("Unrecognized action '%s'.", act));
        }
    }

    protected final void respondWithError(HttpServletResponse response, String message) throws IOException {
        respond(response, ACT_RESPONSE_ERROR, message);
    }

    /**
     * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
     * response)
     */
    @Override
    protected final void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        BufferedReader reader = request.getReader();
        response.setContentType("text/plain");
        try {
            char[] actionName = new char[4];
            if (reader.read(actionName) < actionName.length) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST);
                return;
            }
            try {
                handleCommand(new String(actionName),
                        reader, response);
            } catch (NexAuthException th) {
                respondWithError(response, formatErrorString(th));
            } catch (Throwable th) {
                respondWithError(response, "Internal error.");
                this.log("Unexpected exception in Action '" + new String(actionName) + "'", th);
            }
        } finally {
            reader.close();
        }
    }
    /**
     * @see HttpServlet#doOptions(HttpServletRequest, HttpServletResponse)
     */
    /*
     @Override
     protected final void doOptions(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
     }*/
}
