package com.example.keycloak.auth;

import com.example.keycloak.provider.SmsSenderProvider;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.*;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.jboss.logging.Logger;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Objects;

public class SmsOtpAuthenticator implements Authenticator {



    private static final Logger LOG = Logger.getLogger(SmsOtpAuthenticator.class);

    // form field / JSON parameter names
    private static final String PARAM_PHONE = "phone_number";
    private static final String PARAM_OTP   = "otp";

    // AuthenticationSession notes
    private static final String NOTE_SENT_OTP  = "SMS_OTP_CODE";
    private static final String NOTE_TIMESTAMP = "SMS_OTP_GEN_TS";

    private static final int OTP_TTL_SECONDS = 120;                    // user-configurable later
    private static final int OTP_LENGTH      = 6;

    public SmsOtpAuthenticator() {
        LOG.info("SmsOtpAuthenticator: constructor called");
    }

    /* ----------  Browser (and Direct-Grant) flow entry point  ---------- */

    @Override
    public void authenticate(AuthenticationFlowContext ctx) {
        LOG.info("authenticate() called");
        String phone = ctx.getHttpRequest().getDecodedFormParameters().getFirst(PARAM_PHONE);

        // Step 1: first visit – no OTP yet
        if (phone != null && ctx.getHttpRequest().getDecodedFormParameters().getFirst(PARAM_OTP) == null) {
            LOG.infof("authenticate() - sending code to phone: %s", phone);
            sendCodeAndChallenge(ctx, phone.trim());
            LOG.info("authenticate() - waiting for OTP, exiting method");
            return;  // wait for second POST containing otp
        }

        // Step 2: verify
        LOG.info("authenticate() - verifying OTP");
        verifyOtpAndFinish(ctx);
        LOG.info("authenticate() finished");
    }

    @Override
    public void action(AuthenticationFlowContext ctx) {
        LOG.info("action() called");
        // Browser flow re-enters here after user submits form/JSON
        authenticate(ctx);
        LOG.info("action() finished");
    }

    /* ----------  Shared helpers  ---------- */

    private static void sendCodeAndChallenge(AuthenticationFlowContext ctx, String phone) {
        LOG.infof("sendCodeAndChallenge() called with phone=%s", phone);
        String otp = generateOtp();
        AuthenticationSessionModel session = ctx.getAuthenticationSession();
        session.setAuthNote(NOTE_SENT_OTP, otp);
        session.setAuthNote(NOTE_TIMESTAMP, Long.toString(Instant.now().getEpochSecond()));
        session.setAuthNote(PARAM_PHONE, phone);

        SmsSenderProvider sms = ctx.getSession().getProvider(SmsSenderProvider.class, "sms-ir");
        if (sms == null) {
            LOG.error("sendCodeAndChallenge() - SmsSenderProvider is null!");
            throw new ErrorResponseException("sms_provider_not_found",
                    "No SMS provider registered for id \"sms-ir\"", Response.Status.INTERNAL_SERVER_ERROR);
        }
        LOG.info("sendCodeAndChallenge() - sending SMS");
        boolean ok = sms.send(phone, otp);

        if (!ok) {
            LOG.error("sendCodeAndChallenge() - SMS send failed!");
            throw new ErrorResponseException("sms_failed",
                    "SMS provider error",
                    Response.Status.BAD_GATEWAY);
        }
        LOG.info("sendCodeAndChallenge() - SMS sent successfully, responding to frontend");
        // Tell frontend that code was sent (HTTP 204 is fine – frontend already knows the phone)
        ctx.challenge(Response.noContent().build());
        LOG.info("sendCodeAndChallenge() finished");
    }

    private static void verifyOtpAndFinish(AuthenticationFlowContext ctx) {
        LOG.info("verifyOtpAndFinish() called");
        var form = ctx.getHttpRequest().getDecodedFormParameters();
        String phone = Objects.requireNonNullElse(form.getFirst(PARAM_PHONE), ctx.getAuthenticationSession().getAuthNote(PARAM_PHONE));
        String otp   = form.getFirst(PARAM_OTP);

        AuthenticationSessionModel session = ctx.getAuthenticationSession();
        String expected = session.getAuthNote(NOTE_SENT_OTP);
        String tsStr    = session.getAuthNote(NOTE_TIMESTAMP);

        // missing info?
        if (expected == null || tsStr == null || otp == null) {
            LOG.error("verifyOtpAndFinish() - missing params");
            throw new ErrorResponseException("missing_params",
                    "Phone or OTP missing",
                    Response.Status.BAD_REQUEST);
        }

        // expired?
        long age = Instant.now().getEpochSecond() - Long.parseLong(tsStr);
        if (age > OTP_TTL_SECONDS) {
            LOG.error("verifyOtpAndFinish() - OTP expired");
            throw new ErrorResponseException("expired_code",
                    "OTP expired",
                    Response.Status.UNAUTHORIZED);
        }

        // mismatch?
        if (!expected.equals(otp.trim())) {
            LOG.error("verifyOtpAndFinish() - OTP wrong");
            throw new ErrorResponseException("invalid_code",
                    "OTP wrong",
                    Response.Status.UNAUTHORIZED);
        }

        /* ----------  OTP matched – prevent replay, ensure user exists  ---------- */
        session.removeAuthNote(NOTE_SENT_OTP);      // avoid reuse in parallel requests
        session.removeAuthNote(NOTE_TIMESTAMP);

        KeycloakSession ksession = ctx.getSession();
        RealmModel realm = ctx.getRealm();
        UserModel user = ksession.users().getUserByUsername(realm, phone);
        if (user == null) {
            LOG.info("verifyOtpAndFinish() - user not found, creating new user");
            user = ksession.users().addUser(realm, phone);
            user.setEnabled(true);
            user.setEmailVerified(false);
            user.setSingleAttribute("phone_number", phone);
        } else {
            LOG.info("verifyOtpAndFinish() - found existing user");
        }

        ctx.setUser(user);
        ctx.success();
        LOG.info("verifyOtpAndFinish() finished successfully");
    }

    private static String generateOtp() {
        LOG.info("generateOtp() called");
        int num = new SecureRandom().nextInt((int) Math.pow(10, OTP_LENGTH));
        String otp = String.format("%0" + OTP_LENGTH + "d", num);
        LOG.infof("generateOtp() generated: %s", otp);
        return otp;
    }

    /* ----------  Super-lean helpers used by the JAX-RS layer  ---------- */

            public static void sendCodeForSession(KeycloakSession ks,
                                          AuthenticationSessionModel sess,
                                          String phone) {
        LOG.infof("sendCodeForSession() called: phone=%s", phone);

        String otp = generateOtp();
        sess.setAuthNote(NOTE_SENT_OTP, otp);
        sess.setAuthNote(NOTE_TIMESTAMP, Long.toString(Instant.now().getEpochSecond()));
        sess.setAuthNote(PARAM_PHONE, phone);

        SmsSenderProvider sms = ks.getProvider(SmsSenderProvider.class, "sms-ir");
        if (sms == null) {
            LOG.error("sendCodeForSession() - SmsSenderProvider is null!");
            throw new ErrorResponseException("sms_provider_not_found",
                    "No SMS provider registered for id \"sms-ir\"", Response.Status.INTERNAL_SERVER_ERROR);
        }
        LOG.info("sendCodeForSession() - sending SMS");
                boolean ok = sms.send(phone, otp);
        if (!ok) {
            LOG.error("sendCodeForSession() - SMS send failed!");
            throw new ErrorResponseException("sms_failed",
                    "SMS provider error",
                    Response.Status.BAD_GATEWAY);
        }
        LOG.info("sendCodeForSession() finished");
    }

    public static void verifyOtpForSession(KeycloakSession ks,
                                          AuthenticationSessionModel sess,
                                          String phone, String otp) {
        LOG.infof("verifyOtpForSession() called: phone=%s, otp=%s", phone, otp);
        String expected = sess.getAuthNote(NOTE_SENT_OTP);
        String tsStr    = sess.getAuthNote(NOTE_TIMESTAMP);

        if (expected == null || tsStr == null || otp == null) {
            LOG.error("verifyOtpForSession() - missing params");
            throw new ErrorResponseException("missing_params",
                    "Phone or OTP missing",
                    Response.Status.BAD_REQUEST);
        }

        long age = Instant.now().getEpochSecond() - Long.parseLong(tsStr);
        if (age > OTP_TTL_SECONDS) {
            LOG.error("verifyOtpForSession() - OTP expired");
            throw new ErrorResponseException("expired_code",
                    "OTP expired",
                    Response.Status.UNAUTHORIZED);
        }
        if (!expected.equals(otp.trim())) {
            LOG.error("verifyOtpForSession() - OTP wrong");
            throw new ErrorResponseException("invalid_code",
                    "OTP wrong",
                    Response.Status.UNAUTHORIZED);
        }

        /* OTP matched – prevent replay & make sure user exists */
        sess.removeAuthNote(NOTE_SENT_OTP);
        sess.removeAuthNote(NOTE_TIMESTAMP);

        RealmModel realm = ks.getContext().getRealm();
        UserModel user   = ks.users().getUserByUsername(realm, phone);
        if (user == null) {
            LOG.info("verifyOtpForSession() - user not found, creating new user");
            user = ks.users().addUser(realm, phone);
            user.setEnabled(true);
            user.setSingleAttribute("phone_number", phone);
        } else {
            LOG.info("verifyOtpForSession() - found existing user");
        }
        sess.setAuthenticatedUser(user);
        LOG.info("verifyOtpForSession() finished successfully");
    }


    /* ----------  Unused lifecycle hooks  ---------- */
    @Override public boolean requiresUser()                    { LOG.info("requiresUser() called"); return false; }
    @Override public boolean configuredFor(KeycloakSession s, RealmModel r, UserModel u) { LOG.info("configuredFor() called"); return true; }
    @Override public void setRequiredActions(KeycloakSession s, RealmModel r, UserModel u) { LOG.info("setRequiredActions() called"); }
    @Override public void close() { LOG.info("close() called"); }
}
