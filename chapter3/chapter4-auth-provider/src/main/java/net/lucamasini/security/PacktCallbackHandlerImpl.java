package net.lucamasini.security;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

class PacktCallbackHandlerImpl implements CallbackHandler {
 private String userName;

    PacktCallbackHandlerImpl(String user)
   {
      userName = user;
   }
   public void handle(Callback[] callbacks) throws UnsupportedCallbackException
   {
      for (int i = 0; i < callbacks.length; i++) {
            Callback callback = callbacks[i];
            if (!(callback instanceof NameCallback)) {
               throw new UnsupportedCallbackException(callback, "Unrecognized Callback");
            }
            NameCallback nameCallback = (NameCallback)callback;
            nameCallback.setName(userName);
      }
   }
}
