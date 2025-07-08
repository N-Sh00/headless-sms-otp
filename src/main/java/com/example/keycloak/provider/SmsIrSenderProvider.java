package com.example.keycloak.provider;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.MediaType;
import org.jboss.logging.Logger;
import org.keycloak.provider.Provider;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;

public class SmsIrSenderProvider implements SmsSenderProvider {
    private static final Logger LOG = Logger.getLogger(SmsIrSenderProvider.class);
    private static final URI SMSIR_URI = URI.create("https://api.sms.ir/v1/send/verify");
    private static final ObjectMapper JSON = new ObjectMapper();

    private final HttpClient http;
    private final String apiKey;
    private final String templateId;
    // line number not needed for /v1/send/verify

    public SmsIrSenderProvider() {
        LOG.info("SmsIrSenderProvider: constructor called");
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();

        // Read from environment, not Config.Scope
        this.apiKey     = System.getenv("SMSIR_API_KEY");
        this.templateId = System.getenv("SMSIR_TEMPLATE_ID");

        if (apiKey == null || templateId == null) {
            LOG.error("SmsIrSenderProvider: missing env vars SMSIR_API_KEY or SMSIR_TEMPLATE_ID");
            throw new IllegalStateException("Missing SMSIR_API_KEY or SMSIR_TEMPLATE_ID");
        }
        LOG.info("SmsIrSenderProvider initialized");
    }

    @Override
    public boolean send(String phone, String message) {
        LOG.infof("send() called: phone=%s, message=%s", phone, message);
        try {
            Map<String,Object> payload = Map.of(
                "mobile",     phone,
                "templateId", Integer.parseInt(templateId),
                "parameters", List.of(
                    Map.of("name", "Code", "value", message)
                )
            );
            byte[] body = JSON.writeValueAsBytes(payload);

            HttpRequest req = HttpRequest.newBuilder(SMSIR_URI)
                    .timeout(Duration.ofSeconds(5))
                    .header("Content-Type", MediaType.APPLICATION_JSON)
                    .header("Accept",       "text/plain")
                    .header("x-api-key",    apiKey)          // moved to header
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                    .build();

            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            boolean ok = resp.statusCode() == 200 && resp.body().contains("\"status\":1");

            if (ok) {
                LOG.infof("SMS sent successfully to %s", phone);
            } else {
                LOG.warnf("sms.ir rejected message to %s – response: %s", phone, resp.body());
            }
            return ok;
        } catch (Exception ex) {
            LOG.errorf(ex, "Could not send SMS to %s", phone);
            return false;
        }
    }

    @Override
    public void close() {
        LOG.info("SmsIrSenderProvider.close()");
    }
}
