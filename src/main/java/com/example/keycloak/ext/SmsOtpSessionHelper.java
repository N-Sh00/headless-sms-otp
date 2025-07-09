package com.example.keycloak.ext;

import jakarta.ws.rs.core.Response;
import org.keycloak.common.util.Time;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
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
                                                               String state,
                                                               String redirectUri) {
        LOG.info("createAuthSession: Starting session creation process");
        LOG.infof("createAuthSession: Input parameters - clientId=%s, codeChallenge=%s, state=%s, redirectUri=%s",
                  clientId, codeChallenge, state, redirectUri);

        RealmModel realm = session.getContext().getRealm();
        LOG.infof("createAuthSession: Retrieved realm with name=%s", realm.getName());

        ClientModel client = realm.getClientByClientId(clientId);
        if (client == null) {
            LOG.errorf("createAuthSession: Unknown client \"%s\" not found", clientId);
            throw new ErrorResponseException("unknown_client",
                    "Client \"" + clientId + "\" not found", Response.Status.BAD_REQUEST);
        }
        LOG.infof("createAuthSession: Found client with ID=%s", client.getId());

        // Validate redirect URI against client's registered URIs
        if (redirectUri != null && !client.getRedirectUris().contains(redirectUri)) {
            LOG.warnf("createAuthSession: redirectUri %s not registered for client %s", redirectUri, clientId);
            throw new ErrorResponseException("invalid_redirect_uri",
                    "Redirect URI not registered", Response.Status.BAD_REQUEST);
        }
        LOG.info("createAuthSession: Redirect URI validation passed");

        AuthenticationSessionManager mgr = new AuthenticationSessionManager(session);
        LOG.info("createAuthSession: Initialized AuthenticationSessionManager");

        RootAuthenticationSessionModel root = mgr.createAuthenticationSession(realm, true);
        LOG.infof("createAuthSession: Created root authentication session with ID=%s", root.getId());

        AuthenticationSessionModel authSession = root.createAuthenticationSession(client);
        LOG.infof("createAuthSession: Created authentication session with tabId=%s", authSession.getTabId());

        /* ---- store PKCE, state, and redirect URI ----------------------------------- */
        authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        LOG.info("createAuthSession: Set protocol to OIDCLoginProtocol");

        authSession.setClientNote(OIDCLoginProtocol.CODE_CHALLENGE_PARAM, codeChallenge);
        authSession.setClientNote(OIDCLoginProtocol.CODE_CHALLENGE_METHOD_PARAM, "S256");
        authSession.setClientNote("state", state);
        if (redirectUri != null) {
            authSession.setRedirectUri(redirectUri);
            LOG.infof("createAuthSession: Set redirectUri to %s", redirectUri);
        }
        LOG.info("createAuthSession: Stored PKCE, state, and redirect URI notes");

        /* ---- remember which root-session belongs to this tab-id -------------------- */
        TAB_TO_ROOT.put(authSession.getTabId(), root.getId());
        LOG.infof("createAuthSession: Mapped tabId=%s to rootId=%s", authSession.getTabId(), root.getId());

        LOG.infof("createAuthSession: Completed session creation, returning authSession with tab=%s", authSession.getTabId());
        return authSession;
    }

    /** Finds an existing authentication session by tabId (txn). */
    static AuthenticationSessionModel lookupAuthSession(KeycloakSession session, String tabId) {
        LOG.info("lookupAuthSession: Starting lookup process");
        LOG.infof("lookupAuthSession: Input tabId=%s", tabId);

        String rootId = TAB_TO_ROOT.get(tabId);
        if (rootId == null) {
            LOG.warnf("lookupAuthSession: No root ID mapped for tabId=%s", tabId);
            return null;
        }
        LOG.infof("lookupAuthSession: Retrieved rootId=%s for tabId=%s", rootId, tabId);

        RealmModel realm = session.getContext().getRealm();
        LOG.infof("lookupAuthSession: Retrieved realm with name=%s", realm.getName());

        RootAuthenticationSessionModel root = session.authenticationSessions().getRootAuthenticationSession(realm, rootId);
        if (root == null) {
            LOG.warnf("lookupAuthSession: Root session %s not found for tabId=%s", rootId, tabId);
            return null;
        }
        LOG.infof("lookupAuthSession: Found root session with ID=%s", rootId);

        AuthenticationSessionModel authSession = root.getAuthenticationSessions().get(tabId);
        if (authSession == null) {
            LOG.info("lookupAuthSession: Direct lookup failed, performing fallback iteration");
            for (AuthenticationSessionModel s : root.getAuthenticationSessions().values()) {
                if (s.getTabId().equals(tabId)) {
                    authSession = s;
                    LOG.infof("lookupAuthSession: Found authSession via fallback with tabId=%s", tabId);
                    break;
                }
            }
        } else {
            LOG.infof("lookupAuthSession: Found authSession directly with tabId=%s", tabId);
        }

        if (authSession != null) {
            LOG.infof("lookupAuthSession: Successfully found authSession, root=%s, tab=%s", rootId, tabId);
        } else {
            LOG.warnf("lookupAuthSession: AuthSession not found for tabId=%s", tabId);
        }
        return authSession;
    }

    /** Issues the final OAuth2 authorisation-code string (Keycloak 26+ style). */
    static String issueCode(KeycloakSession session, AuthenticationSessionModel authSession) {
        LOG.info("issueCode: Starting code issuance process");
        RealmModel realm = session.getContext().getRealm();
        LOG.infof("issueCode: Retrieved realm with name=%s", realm.getName());

        ClientModel client = authSession.getClient();
        LOG.infof("issueCode: Retrieved client with ID=%s", client.getId());

        UserSessionProvider usp = session.sessions();
        LOG.info("issueCode: Initialized UserSessionProvider");

        // 1️⃣ Use existing authenticated user from authSession
        UserModel user = authSession.getAuthenticatedUser();
        if (user == null) {
            LOG.error("issueCode: Authenticated user is null in authSession");
            throw new ErrorResponseException("unauthenticated", "User not authenticated", Response.Status.UNAUTHORIZED);
        }
        LOG.infof("issueCode: Retrieved authenticated user with ID=%s", user.getId());

        // 2️⃣ Retrieve or create UserSessionModel linked to authSession
        UserSessionModel userSession = usp.getUserSession(realm, authSession.getParentSession().getId());
        if (userSession == null) {
            LOG.info("issueCode: No existing user session found, creating new one");
            userSession = usp.createUserSession(
                authSession.getParentSession().getId(),
                realm,
                user,
                user.getUsername(),
                session.getContext().getConnection().getRemoteAddr(),
                "sms",
                false,
                null,
                null,
                UserSessionModel.SessionPersistenceState.PERSISTENT
            );
            userSession.setNote("auth_method", authSession.getClientNote("auth_method"));
            LOG.infof("issueCode: Created new user session with ID=%s", userSession.getId());
        } else {
            LOG.infof("issueCode: Retrieved existing user session with ID=%s", userSession.getId());
        }

        // Verify user is correctly associated (no setUser needed)
        if (userSession.getUser() == null) {
            LOG.error("issueCode: User is null in userSession despite authentication - check authentication flow");
            throw new ErrorResponseException("internal_error", "User session corrupted", Response.Status.INTERNAL_SERVER_ERROR);
        }
        LOG.debugf("issueCode: Verified user session, userId=%s", userSession.getUser().getId());

        // 3️⃣ Create and persist a Client-Session
        String redirectUri = authSession.getRedirectUri();
        if (redirectUri == null) {
            LOG.warn("issueCode: redirectUri is null, using client's root URL");
            redirectUri = client.getRootUrl();
            if (redirectUri == null) {
                redirectUri = session.getContext().getUri().getBaseUri().toString();
            }
            LOG.infof("issueCode: Set fallback redirectUri to %s", redirectUri);
        } else {
            LOG.infof("issueCode: Using redirectUri from authSession: %s", redirectUri);
        }
        AuthenticatedClientSessionModel clientSession = usp.createClientSession(realm, client, userSession);
        LOG.infof("issueCode: Created client session with ID=%s", clientSession.getId());

        clientSession.setRedirectUri(redirectUri);
        authSession.getClientNotes().forEach(clientSession::setNote);
        LOG.info("issueCode: Set redirectUri and client notes on clientSession");

        // 4️⃣ Persist and return a 3-part code using OAuth2CodeParser
        ClientSessionCode<AuthenticationSessionModel> csc = new ClientSessionCode<>(session, realm, authSession);
        LOG.info("issueCode: Initialized ClientSessionCode");

        String random = KeycloakModelUtils.generateCodeSecret();
        LOG.infof("issueCode: Generated random code secret: %s", random);

        String issuer = session.getContext().getUri().getBaseUri().toString() + "/realms/" + realm.getName();
        LOG.infof("issueCode: Set issuer to %s", issuer);

        String audience = client.getId();
        String subject = user.getId();
        String scope = authSession.getClientNote("scope") != null ? authSession.getClientNote("scope") : "openid";
        String issuedFor = client.getId();
        String nonce = authSession.getClientNote("nonce") != null ? authSession.getClientNote("nonce") : null;
        String codeChallenge = authSession.getClientNote(OIDCLoginProtocol.CODE_CHALLENGE_PARAM);
        String codeChallengeMethod = authSession.getClientNote(OIDCLoginProtocol.CODE_CHALLENGE_METHOD_PARAM);

        LOG.infof("issueCode: Code parameters - scope=%s, redirectUri=%s, codeChallenge=%s, codeChallengeMethod=%s, userSessionId=%s",
                  scope, redirectUri, codeChallenge, codeChallengeMethod, userSession.getId());

        OAuth2Code oAuth2Code = new OAuth2Code(
            random,
            Time.currentTime() + userSession.getRealm().getAccessCodeLifespan(),
            nonce,
            scope,
            redirectUri, // Use redirectUri directly as redirectUriParam
            codeChallenge,
            codeChallengeMethod,
            null, // dpopJkt (not used)
            userSession.getId() // Correct userSessionId
        );
        LOG.infof("issueCode: Created OAuth2Code with lifespan=%d seconds", realm.getAccessCodeLifespan());

        String code = OAuth2CodeParser.persistCode(session, clientSession, oAuth2Code);
        LOG.infof("issueCode: Persisted code=%s", code);

        LOG.infof("issueCode: Issued code=%s, userSession=%s, clientSession=%s, userId=%s",
                  code, userSession.getId(), clientSession.getId(), user.getId());
        return code;
    }
}