import {
    AuthorizationNotifier,
    AuthorizationRequest,
    AuthorizationServiceConfiguration,
    BaseTokenRequestHandler,
    BasicQueryStringUtils,
    DefaultCrypto,
    FetchRequestor,
    GRANT_TYPE_AUTHORIZATION_CODE, GRANT_TYPE_REFRESH_TOKEN,
    LocalStorageBackend,
    RedirectRequestHandler,
    TokenRequest, TokenResponse,
} from "@openid/appauth"
import { decodeToken } from "jwt-js"

/**
 * Signed but otherwise mostly arbitrary content of OpenId tokens.
 *
 * Some keys are defined according to OpenId specification for access and refresh tokens but interpreting that is
 * mostly left to application logic.
 */
type TokenPayload = Record<string, string | undefined>

/**
 * Configuration options for this Library.
 *
 * A sensible default is exported as {@link DEFAULT_OPENID_CONFIG}
 */
interface OpenidConfig {
    issuer: string
    clientId: string
}

const KEY_ISSUER_CONFIG = "oidcConfiguration"
const KEY_ACCESS_TOKEN = "oidcAccessToken"
const KEY_REFRESH_TOKEN = "oidcRefreshToken"
const KEY_ID_TOKEN = "oidcIdToken"

/**
 * Default OpenId Config which uses Mafiasi as OpenId issuer and authorizes itself as dev-client
 */
export const DEFAULT_OPENID_CONFIG: OpenidConfig = {
    issuer: "https://identity.mafiasi.de/auth/realms/mafiasi",
    clientId: "dev-client"
}

/**
 * Get verbatim access token if one is available.
 * <br/>
 * Automatically renews tokens when the access token is expired and a refresh token is available so that an access
 * token can be retrieved with as minimal overhead as possible.
 * <br/>
 * In most scenarios you as library user should attach this to requests to protected resources via the *Authorization*
 * header like `Authorization: Bearer <token>`.
 */
export async function getAccessToken(): Promise<string | null> {
    const token = sessionStorage.getItem(KEY_ACCESS_TOKEN)
    if (token != null) {
        if (isTokenExpired(token)) {
            await renewTokens()
            return getAccessToken()
        } else {
            return token
        }
    }

    return null
}

/**
 * Get decoded id token if one is available.
 * <br/>
 * Automatically renews tokens when the access token is expired and a refresh token is available so that an access
 * token can be retrieved with as minimal overhead as possible.
 * <br/>
 * The contents of these tokens are dependent on the requested OpenId scopes.
 */
export async function getIdToken(): Promise<TokenPayload | null> {
    const token = sessionStorage.getItem(KEY_ID_TOKEN)
    if (token != null) {
        if (isTokenExpired(token)) {
            await renewTokens()
            return getIdToken()
        } else {
            const { payload } = decodeToken(token)
            return payload
        }
    }

    return null
}

/**
 * Whether or not the current application can be considered to be authenticated.
 * <br/>
 * This is determined merely by the presence of a valid access token and therefore **does not** take into account
 * session revocation.
 */
export async function isAuthenticated(): Promise<boolean> {
    return await getAccessToken() != null
}

/**
 * Initiate the authorization process by redirecting the user to the authentication server.
 * The user will eventually be redirected to this application in the form of the supplied *callbackUri*
 *
 * @param callbackUri A URI (probably a URL) under which this application is reachable and will receive the authorization callback
 *  At this location {@link doAuthorizationCallback} should be called so that the result can be properly handled.
 * @param openidConfig An optional configuration which overrides {@link DEFAULT_OPENID_CONFIG} if supplied.
 */
export async function doAuthorization(callbackUri: string, openidConfig?: OpenidConfig): Promise<void> {
    if (openidConfig == null) {
        openidConfig = DEFAULT_OPENID_CONFIG
    }
    const config = await getServiceConfiguration(openidConfig.issuer)

    const request = new AuthorizationRequest({
        client_id: openidConfig.clientId,
        response_type: AuthorizationRequest.RESPONSE_TYPE_CODE,
        redirect_uri: callbackUri,
        scope: "openid"
    }, new DefaultCrypto(), true)

    const authorizationHandler = new RedirectRequestHandler()
    authorizationHandler.performAuthorizationRequest(config, request)
}

/**
 * Continue the authorization process by handling the result of the authentication server.
 *
 * @param openidConfig An optional configuration which overrides {@link DEFAULT_OPENID_CONFIG} if supplied.
 *  <br/>
 *  This **must** be the same as the one passed to {@link doAuthorization} or otherwise, the authorization will fail.
 */
export async function doAuthorizationCallback(openidConfig?: OpenidConfig): Promise<void> {
    if (openidConfig == null) {
        openidConfig = DEFAULT_OPENID_CONFIG
    }

    return new Promise(((resolve, reject) => {
        const notifier = new AuthorizationNotifier()
        notifier.setAuthorizationListener(((request, response, error) => {
            if (error != null) {
                reject(error)
            } else if (response != null) {
                // openIdConfig is definitely not null since we ensure that at function start
                resolve(exchangeCodeForTokens(response.code, request, openidConfig!))
            }
        }))

        const authorizationHandler = new RedirectRequestHandler(new LocalStorageBackend(), new BasicQueryStringUtils(), {
            ...window.location,
            hash: window.location.search
        })
        authorizationHandler.setAuthorizationNotifier(notifier)
        authorizationHandler.completeAuthorizationRequestIfPossible().then()
    }))
}

export default {
    getAccessToken,
    getIdToken,
    isAuthenticated,
    doAuthorization,
    doAuthorizationCallback,
    DEFAULT_OPENID_CONFIG,
}

/**
 * Exchange a code which was received during {@link doAuthorizationCallback} for refresh and access tokens
 *
 * @param code The received code
 * @param authorizationRequest The original request which was used to start the Authorization-Code-Flow
 * @param openidConfig The OpenId configuration which was used to start the Authorization-Code-Flow
 */
async function exchangeCodeForTokens(code: string, authorizationRequest: AuthorizationRequest, openidConfig: OpenidConfig) {
    const tokenHandler = new BaseTokenRequestHandler(new FetchRequestor())

    // if PKCE extension is used, we need to send the code_verifier along in the TokenRequest
    const extras = {} as Record<string, string>
    if (authorizationRequest.internal != null && authorizationRequest.internal["code_verifier"] != null) {
        extras["code_verifier"] = authorizationRequest.internal["code_verifier"]
    }

    const request = new TokenRequest({
        client_id: openidConfig.clientId,
        redirect_uri: authorizationRequest.redirectUri,
        grant_type: GRANT_TYPE_AUTHORIZATION_CODE,
        code,
        extras,
    })
    const response = await tokenHandler.performTokenRequest(await getServiceConfiguration(openidConfig.issuer), request)
    storeTokenResponse(response)
}

/**
 * Renew all stored tokens by requesting new ones from the OpenId Issuer
 */
async function renewTokens() {
    const refreshToken = sessionStorage.getItem(KEY_REFRESH_TOKEN)

    if (refreshToken != null) {
        const { payload } = decodeToken(refreshToken)

        const handler = new BaseTokenRequestHandler(new FetchRequestor())
        const request = new TokenRequest({
            grant_type: GRANT_TYPE_REFRESH_TOKEN,
            client_id: payload.azp!,            // azp is the authorized party according to OpenId spec
            refresh_token: refreshToken,
            redirect_uri: ""
        })
        const response = await handler.performTokenRequest(await getServiceConfiguration(payload.iss!), request)        // iss is the OpenId issuer according to OpenId spec
        storeTokenResponse(response)
    }
}

/**
 * Whether or not the given token is expired
 *
 * @param token Encoded token (can be any type of OpenId token)
 */
function isTokenExpired(token: string) {
    const { payload } = decodeToken(token)
    return Number(payload.exp!) <= Date.now() / 1000        // exp is the expiry date according to OpenId spec
}

/**
 * Get @openid/appauth configuration object by querying the supplied OpenId Issuer
 *
 * @param issuer URL of the OpenId Issuer which should be used
 */
async function getServiceConfiguration(issuer: string) {
    const cachedIssuerConfig = sessionStorage.getItem(KEY_ISSUER_CONFIG)
    if (cachedIssuerConfig == null) {
        const config = await AuthorizationServiceConfiguration.fetchFromIssuer(issuer, new FetchRequestor())
        sessionStorage.setItem(KEY_ISSUER_CONFIG, JSON.stringify(config.toJson()))
        return config
    } else {
        return new AuthorizationServiceConfiguration(JSON.parse(cachedIssuerConfig))
    }
}

/**
 * Store all tokens present in the TokenResponse in sessionStorage so that they can be retrieved by other functions
 * who need them ({@link getIdToken}, {@link getAccessToken})
 *
 * @param response The response which was received from the OpenId Issuer during token exchange
 */
function storeTokenResponse(response: TokenResponse) {
    sessionStorage.setItem(KEY_ACCESS_TOKEN, response.accessToken)
    if (response.idToken == null) {
        throw new Error("OpenId TokenResponse does not contain an idToken")
    } else {
        sessionStorage.setItem(KEY_ID_TOKEN, response.idToken)
    }
    if (response.refreshToken == null) {
        throw new Error("OpenId TokenResponse does not contain a refreshToken")
    } else {
        sessionStorage.setItem(KEY_REFRESH_TOKEN, response.refreshToken)
    }
}
