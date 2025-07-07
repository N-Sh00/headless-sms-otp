package com.example.keycloak.ext;

import jakarta.ws.rs.core.Response;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.jboss.logging.Logger;

/**
 * Utility glue so the /ext/sms endpoints can work without directly
 * touching Keycloak internals in many places.
 */
final class SmsOtpSessionHelper {

    private static final Logger LOG = Logger.getLogger(SmsOtpSessionHelper.class);

    private SmsOtpSessionHelper() {
        LOG.info("SmsOtpSessionHelper: constructor called");
    }

    /**
     * Creates a fresh AuthenticationSession and stores PKCE + state.
     * Returns that session so the caller can keep its tabId.
     */
    static AuthenticationSessionModel createAuthSession(KeycloakSession session,
                                                        String clientId,
                                                        String codeChallenge,
                                                        String state) {
        LOG.infof("createAuthSession() called: clientId=%s, codeChallenge=%s, state=%s", clientId, codeChallenge, state);

        RealmModel realm = session.getContext().getRealm();
        ClientModel client = realm.getClientByClientId(clientId);
        if (client == null) {
            LOG.errorf("createAuthSession(): unknown client \"%s\"", clientId);
            throw new ErrorResponseException("unknown_client",
                    "Client \"" + clientId + "\" not found", Response.Status.BAD_REQUEST);
        }

        AuthenticationSessionManager mgr = new AuthenticationSessionManager(session);
        RootAuthenticationSessionModel root = mgr.createAuthenticationSession(realm, true);
        AuthenticationSessionModel authSession = root.createAuthenticationSession(client);

        authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        authSession.setClientNote(OIDCLoginProtocol.CODE_CHALLENGE_PARAM, codeChallenge);
        authSession.setClientNote(OIDCLoginProtocol.CODE_CHALLENGE_METHOD_PARAM, "S256");
        authSession.setClientNote("state", state);

        LOG.infof("createAuthSession(): created session with tabId=%s", authSession.getTabId());
        return authSession;
    }

    /** Finds an existing authentication session by tabId (txn). */
    static AuthenticationSessionModel lookupAuthSession(KeycloakSession session, String tabId) {
        LOG.infof("lookupAuthSession() called: tabId=%s", tabId);
        RealmModel realm = session.getContext().getRealm();
        RootAuthenticationSessionModel root =
                session.authenticationSessions().getRootAuthenticationSession(realm, tabId);

        if (root == null) {
            LOG.warnf("lookupAuthSession(): no root session found for tabId=%s", tabId);
            return null;
        }

        for (AuthenticationSessionModel authSession : root.getAuthenticationSessions().values()) {
            if (authSession.getTabId().equals(tabId)) {
                LOG.infof("lookupAuthSession(): found authSession with tabId=%s", tabId);
                return authSession;
            }
        }

        LOG.warnf("lookupAuthSession(): no authSession found with tabId=%s", tabId);
        return null;
    }

    /** Issues the final OAuth2 authorisation-code string (Keycloak 26 style). */
    static String issueCode(KeycloakSession session, AuthenticationSessionModel authSession) {
        LOG.infof("issueCode() called: tabId=%s", authSession.getTabId());
        ClientSessionCode<AuthenticationSessionModel> csc =
                new ClientSessionCode<>(session, session.getContext().getRealm(), authSession);
        String code = csc.getOrGenerateCode();
        LOG.infof("issueCode(): issued code=%s", code);
        return code;
    }
}
