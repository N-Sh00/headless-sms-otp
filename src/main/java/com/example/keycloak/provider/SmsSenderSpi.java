package com.example.keycloak.provider;

import com.google.auto.service.AutoService;
import org.jboss.logging.Logger;
import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

import java.util.Collections;
import java.util.List;

@AutoService(org.keycloak.provider.Spi.class)
public class SmsSenderSpi implements Spi {
    private static final Logger LOG = Logger.getLogger(SmsSenderSpi.class);


    @Override public String getName() {
        // This must match the interface name (convention, not mandatory)
        return "sms-sender";
    }

    public SmsSenderSpi() {
        LOG.info("SmsSenderSpi: loaded");
    }

    @Override public Class<? extends Provider> getProviderClass() {
        return SmsSenderProvider.class;
    }

    @Override public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return org.keycloak.provider.ProviderFactory.class;
    }

    public List<Class<?>> getRequiredProviderClasses() {
        return Collections.emptyList();
    }

    @Override public boolean isInternal() {
        return false;          // expose as public SPI
    }
}
