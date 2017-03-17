package net.lucamasini.security;

import weblogic.security.principal.WLSGroupImpl;
import weblogic.security.principal.WLSUserImpl;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

public class PacktLoginModuleImpl implements LoginModule {
    private static final Logger LOGGER = Logger.getLogger(PacktLoginModuleImpl.class.getSimpleName());

    private Subject subject;
    private CallbackHandler callbackHandler;
    private String url;

    @Override
    public void
    initialize(
            Subject subject,
            CallbackHandler callbackHandler,
            Map sharedState,
            Map options
    ) {
        LOGGER.info("PacktLoginModuleImpl.initialize");

        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.url = options.get("url").toString();
    }

    private boolean loginSucceeded;
    private List<Principal> principalsForSubject = new ArrayList<Principal>();


    @Override
    public boolean login() throws LoginException {
        LOGGER.info("PacktLoginModuleImpl.login");

        Callback[] callbacks = new Callback[]{
                new NameCallback("username: "),
                new PasswordCallback("password: ", false)
        };

        try {
            callbackHandler.handle(callbacks);
        } catch (Exception e) {
            LOGGER.throwing("PacktLoginModuleImpl", "login", e);
            throw new LoginException(e.getMessage());
        }

        final String userName = ((NameCallback) callbacks[0]).getName();

        PasswordCallback passwordCallback = (PasswordCallback) callbacks[1];
        char[] passwordChars = passwordCallback.getPassword();
        passwordCallback.clearPassword();
        final String password = new String(passwordChars);

        if (userName != null && password != null && userName.length() > 0 && password.length() > 0) {
            checkUsernameAndPassword(userName, password);
        } else {
            throw new LoginException("username and/or password cannot be null");
        }

        loginSucceeded = true;

        principalsForSubject.add(new WLSUserImpl(userName));
        principalsForSubject.add(new WLSGroupImpl("Packt"));

        return loginSucceeded;
    }

    private boolean principalsInSubject;

    @Override
    public boolean commit() {
        LOGGER.info("PacktLoginModuleImpl.commit");
        if (loginSucceeded) {
            subject.getPrincipals().addAll(principalsForSubject);
            principalsInSubject = true;
            return true;
        } else {
            return false;
        }
    }

    @Override
    public boolean abort() {
        LOGGER.info("PacktLoginModuleImpl.abort");
        if (principalsInSubject) {
            subject.getPrincipals().removeAll(principalsForSubject);
            principalsInSubject = false;
        }
        return true;
    }

    @Override
    public boolean logout() throws LoginException {
        LOGGER.info("PacktLoginModuleImpl.logout");
        if( principalsInSubject ) {
            if( !subject.isReadOnly() ) {
                subject.getPrincipals().removeAll(principalsForSubject);
            } else {
                for(Principal principal: principalsForSubject ) {
                    if( principal instanceof Destroyable ) {
                        try {
                            ((Destroyable)principal).destroy();
                        } catch (DestroyFailedException e) {
                            LOGGER.throwing("PacktLoginModuleImpl", "logout", e);
                            throw new LoginException("cannot destroy principal "+principal.getName());
                        }
                    } else {
                        throw new LoginException("cannot destroy principal "+principal.getName());
                    }
                }
            }
        }
        return true;
    }

    private void checkUsernameAndPassword(String userName, String password) throws LoginException {
        try {
            String loginURL = url + "?username=" + userName + "&password=" + password;
            HttpURLConnection urlConnection = (HttpURLConnection) new URI(loginURL).toURL().openConnection();
            int responseCode = urlConnection.getResponseCode();
            if (responseCode != 200) {
                throw new LoginException("username e/o password non corrette: HttpResponseCode=" + responseCode + " for loginURL=" + loginURL.substring(0, loginURL.indexOf("&password=")) + "&password=<omissis>");
            }

            BufferedReader reader = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));

            String line;
            StringBuilder sb = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            reader.close();
        } catch (Exception e) {
            LOGGER.throwing("PacktLoginModuleImpl", "checkUsernameAndPassword", e);
            throw new LoginException(e.getMessage());
        }
    }
}
