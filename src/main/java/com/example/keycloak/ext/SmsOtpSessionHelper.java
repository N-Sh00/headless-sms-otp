package com.example.keycloak.ext;

import jakarta.ws.rs.core.Response;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.utils.OAuth2Code;
import org.keycloak.protocol.oidc.utils.OAuth2CodeParser;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.jboss.logging.Logger;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Utility glue so the /ext/sms endpoints can work without directly
 * touching Keycloak internals in many places.
 */
final class SmsOtpSessionHelper {

    private static final Logger LOG = Logger.getLogger(SmsOtpSessionHelper.class);

    /** tab-id → root-session-id lookup kept in memory until Keycloak restarts */
    private static final Map<String, String> TAB_TO_ROOT = new ConcurrentHashMap<>();

    private SmsOtpSessionHelper() {
        LOG.info("SmsOtpSessionHelper: constructor called");
    }

    /**
     * Creates a fresh AuthenticationSession and stores PKCE + state.
     * Returns that session so the caller can keep its tabId.
     */
    public static AuthenticationSessionModel createAuthSession(KeycloakSession session,
                                                               String clientId,
                                                               String codeChallenge,
                                                               String state) {
        LOG.infof("createAuthSession() called: clientId=%s, codeChallenge=%s, state=%s",
                  clientId, codeChallenge, state);

        RealmModel realm  = session.getContext().getRealm();
        ClientModel client = realm.getClientByClientId(clientId);
        if (client == null) {
            LOG.errorf("createAuthSession(): unknown client \"%s\"", clientId);
            throw new ErrorResponseException("unknown_client",
                    "Client \"" + clientId + "\" not found", Response.Status.BAD_REQUEST);
        }

        AuthenticationSessionManager mgr = new AuthenticationSessionManager(session);
        RootAuthenticationSessionModel root = mgr.createAuthenticationSession(realm, true);
        AuthenticationSessionModel authSession = root.createAuthenticationSession(client);

        /* ---- store PKCE & state ----------------------------------------------------- */
        authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        authSession.setClientNote(OIDCLoginProtocol.CODE_CHALLENGE_PARAM,        codeChallenge);
        authSession.setClientNote(OIDCLoginProtocol.CODE_CHALLENGE_METHOD_PARAM, "S256");
        authSession.setClientNote("state",                                       state);

        /* ---- remember which root-session belongs to this tab-id -------------------- */
        TAB_TO_ROOT.put(authSession.getTabId(), root.getId());

        LOG.infof("createAuthSession(): created session root=%s tab=%s",
                  root.getId(), authSession.getTabId());
        return authSession;
    }

    /** Finds an existing authentication session by **tabId** (txn). */
    static AuthenticationSessionModel lookupAuthSession(KeycloakSession session, String tabId) {
        LOG.infof("lookupAuthSession() called: tabId=%s", tabId);

        String rootId = TAB_TO_ROOT.get(tabId);
        if (rootId == null) {
            LOG.warnf("lookupAuthSession(): no root id mapped for tabId=%s", tabId);
            return null;
        }

        RealmModel realm = session.getContext().getRealm();
        RootAuthenticationSessionModel root =
                session.authenticationSessions().getRootAuthenticationSession(realm, rootId);

        if (root == null) {
            LOG.warnf("lookupAuthSession(): root session %s not found (tabId=%s)", rootId, tabId);
            return null;
        }

        AuthenticationSessionModel authSession = root.getAuthenticationSessions().get(tabId);
        if (authSession == null) {
            /* fallback – iterate if map key layout ever changes */
            for (AuthenticationSessionModel s : root.getAuthenticationSessions().values()) {
                if (s.getTabId().equals(tabId)) { authSession = s; break; }
            }
        }

        if (authSession != null) {
            LOG.infof("lookupAuthSession(): found authSession root=%s tab=%s", rootId, tabId);
        } else {
            LOG.warnf("lookupAuthSession(): authSession not found for tabId=%s", tabId);
        }
        return authSession;
    }

    /** Issues the final OAuth2 authorisation-code string (Keycloak 26+ style). */
    static String issueCode(KeycloakSession session, AuthenticationSessionModel authSession) {
        RealmModel realm = session.getContext().getRealm();
        ClientModel client = authSession.getClient();
        UserSessionProvider usp = session.sessions();

        // 1️⃣ Create a fresh User-Session with the correct signature
        UserSessionModel userSession = usp.createUserSession(
                null, // id will be generated
                realm,
                authSession.getAuthenticatedUser(),
                authSession.getAuthenticatedUser().getUsername(), // loginUsername
                session.getContext().getConnection().getRemoteAddr(), // ipAddress
                "sms", // authMethod from your OTP flow
                false, // rememberMe
                null, // brokerSessionId
                null, // brokerUserId
                UserSessionModel.SessionPersistenceState.PERSISTENT // persistenceState
        );
        userSession.setNote("auth_method", authSession.getClientNote("auth_method"));

        // 2️⃣ Create and persist a Client-Session
        String redirectUri = authSession.getRedirectUri();
        if (redirectUri == null) {
            LOG.warn("Redirect URI is null, using client's default");
            redirectUri = client.getRootUrl() + client.getBaseUrl(); // Fallback
        }
        AuthenticatedClientSessionModel clientSession = usp.createClientSession(
                realm,
                client,
                userSession
        );
        clientSession.setRedirectUri(redirectUri); // Set redirectUri after creation
        authSession.getClientNotes().forEach(clientSession::setNote);

        // 3️⃣ Persist and return a 3-part code using OAuth2CodeParser
        ClientSessionCode<AuthenticationSessionModel> csc = new ClientSessionCode<>(session, realm, authSession);
        String random = csc.getOrGenerateCode();
        String issuer = session.getContext().getUri().getBaseUri().toString() + "/realms/" + realm.getName();
        String audience = client.getId();
        String subject = userSession.getUser().getId();
        String scope = authSession.getClientNote("scope") != null ? authSession.getClientNote("scope") : "openid";
        String issuedFor = client.getId(); // Likely the client ID
        String nonce = authSession.getClientNote("nonce") != null ? authSession.getClientNote("nonce") : null; // Optional
        String sessionState = userSession.getId();               // <-- correct value
        OAuth2Code oAuth2Code = new OAuth2Code(
                random,
                realm.getAccessCodeLifespan(),
                issuer,
                audience,
                subject,
                sessionState,
                scope,
                issuedFor,
                nonce);

        String code = OAuth2CodeParser.persistCode(session, clientSession, oAuth2Code);
        LOG.infof("issueCode(): issued code=%s", code);
        return code;
    }
}
