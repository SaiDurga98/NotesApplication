package com.techie.notes.service;


import com.warrenstrange.googleauth.GoogleAuthenticatorKey;


public interface TotpService {
    GoogleAuthenticatorKey generateSecret();

    String getQRCodeURL(GoogleAuthenticatorKey secret, String username);

    boolean verifyCode(String secret, int code);
}
