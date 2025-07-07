package com.example.keycloak.auth;

import org.jboss.logging.Logger;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.Config;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Collections;
import java.util.List;

public class SmsOtpAuthenticatorFactory implements AuthenticatorFactory {

    private static final Logger LOG = Logger.getLogger(SmsOtpAuthenticatorFactory.class);

    public static final String ID = "sms-otp-authenticator";

    public SmsOtpAuthenticatorFactory() {
        LOG.info("SmsOtpAuthenticatorFactory: constructor called");
    }

    @Override
    public String getId() {
        LOG.info("getId() called");
        return ID;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        LOG.info("create() called");
        return new SmsOtpAuthenticator();
    }

    @Override
    public void init(Config.Scope cfg) {
        LOG.info("init() called");
    }

    @Override
    public void postInit(KeycloakSessionFactory f) {
        LOG.info("postInit() called");
    }

    @Override
    public void close() {
        LOG.info("close() called");
    }

    /* -------- UI / configuration metadata -------- */

    @Override
    public String getDisplayType() {
        LOG.info("getDisplayType() called");
        return "SMS OTP (phone)";
    }

    @Override
    public String getHelpText() {
        LOG.info("getHelpText() called");
        return "Authenticates users by phone + SMS code";
    }

    @Override
    public boolean isConfigurable() {
        LOG.info("isConfigurable() called");
        return false;
    }

    @Override
    public String getReferenceCategory() {
        LOG.info("getReferenceCategory() called");
        return "otp";
    }

    @Override
    public boolean isUserSetupAllowed() {
        LOG.info("isUserSetupAllowed() called");
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        LOG.info("getConfigProperties() called");
        return Collections.emptyList(); // No configuration needed
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        LOG.info("getRequirementChoices() called");
        return new AuthenticationExecutionModel.Requirement[]{ AuthenticationExecutionModel.Requirement.REQUIRED };
    }
}
