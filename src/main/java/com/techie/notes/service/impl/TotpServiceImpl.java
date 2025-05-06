package com.techie.notes.service.impl;

import com.techie.notes.service.TotpService;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import org.springframework.stereotype.Service;

@Service
public class TotpServiceImpl implements TotpService {

    private final GoogleAuthenticator googleAuthenticator;

    public TotpServiceImpl(GoogleAuthenticator googleAuthenticator) {
        this.googleAuthenticator = googleAuthenticator;
    }

    public TotpServiceImpl() {
        this.googleAuthenticator = new GoogleAuthenticator();
    }

    // Generate the secret
    @Override
    public GoogleAuthenticatorKey generateSecret() {
        return googleAuthenticator.createCredentials();
    }

    // Get the url for the bar code with secret and username which will be sent to front end and they can embed the barcode image and show it to user
    @Override
    public String getQRCodeURL(GoogleAuthenticatorKey secret, String username) {
        return GoogleAuthenticatorQRGenerator.getOtpAuthURL("Secure Notes Application", username, secret);
    }

    // verify the code entered by the user
    @Override
    public boolean verifyCode(String secret, int code) {
        return googleAuthenticator.authorize(secret, code);
    }


}
