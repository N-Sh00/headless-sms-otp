package com.example.keycloak.provider;

import com.google.auto.service.AutoService;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Provider;

@AutoService(org.keycloak.provider.ProviderFactory.class)
public class SmsIrSenderProviderFactory implements ProviderFactory<SmsSenderProvider> {
    private static final Logger LOG = Logger.getLogger(SmsIrSenderProviderFactory.class);

    public SmsIrSenderProviderFactory() {
        LOG.info("SmsIrSenderProviderFactory: constructor called");
    }

    @Override
    public SmsSenderProvider create(KeycloakSession session) {
        LOG.info("SmsIrSenderProviderFactory.create(session) called");
        return new SmsIrSenderProvider();   // your no-arg provider
    }

//    @Override
//    public SmsSenderProvider create() {
//        LOG.info("SmsIrSenderProviderFactory.create()");
//        return new SmsIrSenderProvider();
//    }

    @Override
    public void init(org.keycloak.Config.Scope config) {
        LOG.info("SmsIrSenderProviderFactory.init()");
        // no-op: config now comes from env
    }

    @Override
    public void postInit(org.keycloak.models.KeycloakSessionFactory factory) {
        LOG.info("SmsIrSenderProviderFactory.postInit()");
    }

    @Override
    public void close() {
        LOG.info("SmsIrSenderProviderFactory.close()");
    }

    @Override
    public String getId() {
        LOG.info("SmsIrSenderProviderFactory.getId()");
        return "sms-ir";
    }
}
