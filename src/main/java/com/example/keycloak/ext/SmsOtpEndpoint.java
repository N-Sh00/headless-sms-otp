package com.example.keycloak.ext;

import com.example.keycloak.auth.SmsOtpAuthenticator;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.jboss.logging.Logger;
import java.util.Map;

/**
 * Thin façade that delegates to our SmsOtpAuthenticator so that the mobile app
 * can call clean JSON endpoints:
 *
 *  POST /sms/init    { phone_number, client_id, code_challenge, state }
 *  POST /sms/confirm { phone_number, otp }
 *
 * The first call sends the OTP; the second one completes the Browser flow and
 * returns the real OAuth2 authorization code in JSON – all with NO WebView.
 */
@Path("")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class SmsOtpEndpoint {

    private final KeycloakSession session;
    private static final Logger LOG = Logger.getLogger(SmsOtpEndpoint.class);


    public SmsOtpEndpoint(KeycloakSession session) {
        LOG.info("SmsOtpEndpoint: constructor called");
        this.session = session;
    }

    /* ------------------------------------------------------------ */

    @POST
    @Path("/init")
    public Response init(Map<String, String> json) {
        LOG.infof("/init called with json: %s", json);
        if (json == null) {
            LOG.error("/init: Missing JSON body");
            throw new ErrorResponseException("invalid_request", "Missing JSON body", Response.Status.BAD_REQUEST);
        }

        String phone         = json.get("phone_number");
        String clientId      = json.get("client_id");
        String codeChallenge = json.get("code_challenge");
        String state         = json.get("state");

        if (phone == null || clientId == null || codeChallenge == null) {
            LOG.errorf("/init: missing params, phone=%s, clientId=%s, codeChallenge=%s", phone, clientId, codeChallenge);
            throw new ErrorResponseException("missing_params",
                    "phone_number / client_id / code_challenge required",
                    Response.Status.BAD_REQUEST);
        }

        // Create a fresh authentication session (1 tab == 1 transaction)
        LOG.infof("/init: creating authentication session for clientId=%s", clientId);
        AuthenticationSessionModel authSession =
                SmsOtpSessionHelper.createAuthSession(session, clientId, codeChallenge, state);

        // Delegate “send OTP” to the authenticator – same method, no duplication
        LOG.infof("/init: sending code for phone=%s", phone);
        SmsOtpAuthenticator.sendCodeForSession(session, authSession, phone);

        LOG.infof("/init: returning txn=%s", authSession.getTabId());
        return Response.ok(Map.of("txn", authSession.getTabId())).build();
    }

    @POST
    @Path("/confirm")
    public Response confirm(Map<String, String> json) {
        LOG.infof("/confirm called with json: %s", json);

        if (json == null) {
            LOG.error("/confirm: Missing JSON body");
            throw new ErrorResponseException("invalid_request", "Missing JSON body", Response.Status.BAD_REQUEST);
        }

        String phone = json.get("phone_number");
        String otp   = json.get("otp");
        String txn   = json.get("txn");

        if (phone == null || otp == null || txn == null) {
            LOG.errorf("/confirm: missing params, phone=%s, otp=%s, txn=%s", phone, otp, txn);
            throw new ErrorResponseException("missing_params",
                    "phone_number / otp / txn required",
                    Response.Status.BAD_REQUEST);
        }

        LOG.infof("/confirm: looking up authentication session for txn=%s", txn);
        AuthenticationSessionModel authSession =
                SmsOtpSessionHelper.lookupAuthSession(session, txn);

        LOG.infof("/confirm: verifying OTP for phone=%s", phone);
        // Re-use the same verifier code we already trust
        SmsOtpAuthenticator.verifyOtpForSession(session, authSession, phone, otp);

        String code  = SmsOtpSessionHelper.issueCode(session, authSession);
        String state = authSession.getClientNote("state");

        LOG.infof("/confirm: returning code=%s, state=%s", code, state);
        return Response.ok(Map.of("code", code, "state", state)).build();
    }

    @GET
    @Path("/ping")
    public Response ping() {
        LOG.info("/ping called");
        return Response.ok(Map.of("msg", "pong")).build();
    }
}
