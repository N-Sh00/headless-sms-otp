package com.example.keycloak.provider;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderFactory;

public class SmsIrSenderProviderFactory implements ProviderFactory<SmsSenderProvider> {

    private static final Logger LOG = Logger.getLogger(SmsIrSenderProviderFactory.class);
    private Config.Scope cfg;

    public SmsIrSenderProviderFactory() {
        LOG.info("SmsIrSenderProviderFactory: constructor called");
    }

    @Override
    public SmsSenderProvider create(KeycloakSession session) {
        LOG.info("create() called");
        return new SmsIrSenderProvider(session, cfg);
    }

    @Override
    public void init(Config.Scope config) {
        LOG.info("init() called with config: " + config);
        this.cfg = config;   // keep for later use by create()
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        LOG.info("postInit() called");
        // not used
    }

    @Override
    public void close() {
        LOG.info("close() called");
        // nothing
    }

    @Override
    public String getId() {
        LOG.info("getId() called");
        return "sms-ir";
    }
}
