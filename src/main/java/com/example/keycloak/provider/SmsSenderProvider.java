package com.example.keycloak.provider;

import org.keycloak.provider.Provider;

public interface SmsSenderProvider extends Provider {
    /**
     * Sends an arbitrary text message to a phone number.
     *
     * @param phone   E.164 format (“+98912…”) – validation is left to caller
     * @param message Plain UTF-8 body (max 160 chars recommended)
     * @return true  if sms.ir accepted the message (HTTP 200 + “IsSuccessful=true”)
     */
    boolean send(String phone, String message);
}
