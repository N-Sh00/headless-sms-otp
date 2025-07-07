package com.example.keycloak.provider;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.MediaType;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

public class SmsIrSenderProvider implements SmsSenderProvider {

    private static final Logger LOG = Logger.getLogger(SmsIrSenderProvider.class);

    private static final URI SMSIR_URI = URI.create("https://api.sms.ir/v1/send/bulk");
    private static final ObjectMapper JSON = new ObjectMapper();

    private final HttpClient http;
    private final String apiKey;
    private final String lineNumber;   // sms.ir “from” line

    public SmsIrSenderProvider(KeycloakSession session, Config.Scope cfg) {
        LOG.info("SmsIrSenderProvider: constructor called");
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
        this.apiKey = cfg.get("apiKey");
        this.lineNumber = cfg.get("lineNumber");

        if (apiKey == null || lineNumber == null) {
            LOG.error("SmsIrSenderProvider: apiKey or lineNumber missing in config");
            throw new IllegalStateException("SmsIrSenderProvider: apiKey or lineNumber missing in config");
        }
        LOG.infof("SmsIrSenderProvider initialized with apiKey=%s, lineNumber=%s", apiKey, lineNumber);
    }

    @Override
    public boolean send(String phone, String message) {
        LOG.infof("send() called: phone=%s, message=%s", phone, message);
        try {
            var payload = Map.of(
                    "apikey", apiKey,
                    "linenumber", lineNumber,
                    "mobile", phone,
                    "message", message
            );
            byte[] json = JSON.writeValueAsBytes(payload);

            var req = HttpRequest.newBuilder(SMSIR_URI)
                    .timeout(Duration.ofSeconds(5))
                    .header("Content-Type", MediaType.APPLICATION_JSON)
                    .POST(HttpRequest.BodyPublishers.ofByteArray(json))
                    .build();

            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());

            boolean ok = resp.statusCode() == 200 &&
                    resp.body().contains("\"IsSuccessful\":true");

            if (ok) {
                LOG.infof("SMS sent successfully to %s", phone);
            } else {
                LOG.warnf("sms.ir rejected message to %s – response %s", phone, resp.body());
            }
            return ok;

        } catch (Exception ex) {
            LOG.errorf(ex, "Could not send SMS to %s", phone);
            return false;
        }
    }

    @Override
    public void close() {
        LOG.info("close() called");
        // nothing to free – HttpClient is lightweight
    }
}
