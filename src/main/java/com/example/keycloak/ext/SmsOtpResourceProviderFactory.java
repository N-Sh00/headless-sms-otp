package com.example.keycloak.ext;

import com.google.auto.service.AutoService;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.Config;
import org.keycloak.services.resource.RealmResourceProviderFactory;
import org.jboss.logging.Logger;

@AutoService(RealmResourceProviderFactory.class)
public class SmsOtpResourceProviderFactory
        implements RealmResourceProviderFactory {

    private static final Logger LOG = Logger.getLogger(SmsOtpResourceProviderFactory.class);

    public static final String ID = "sms";

    public SmsOtpResourceProviderFactory() {
        LOG.info("SmsOtpResourceProviderFactory: constructor called");
    }

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        LOG.info("create() called");
        return new SmsOtpResourceProvider(session);
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

    @Override
    public String getId() {
        LOG.info("getId() called");
        return ID;
    }
}
