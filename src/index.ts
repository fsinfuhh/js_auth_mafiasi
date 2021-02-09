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
//@ts-ignore because jwt-js does not have type definition files
import { decodeToken } from "jwt-js"

type TokenPayload = Record<string, string | undefined>

interface OpenidConfig {
    issuer: string
    clientId: string
}

const KEY_ISSUER_CONFIG = "oidcConfiguration"
const KEY_ACCESS_TOKEN = "oidcAccessToken"
const KEY_REFRESH_TOKEN = "oidcRefreshToken"
const KEY_ID_TOKEN = "oidcIdToken"

export const DEFAULT_OPENID_CONFIG: OpenidConfig = {
    issuer: "https://identity.mafiasi.de/auth/realms/mafiasi",
    clientId: "dev-client"
}

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

export async function isAuthenticated(): Promise<boolean> {
    return await getAccessToken() != null
}

export async function doAuthorization(callbackUri: string, openidConfig?: OpenidConfig) {
    const config = await getServiceConfiguration()
    if (openidConfig == null) {
        openidConfig = DEFAULT_OPENID_CONFIG
    }

    const request = new AuthorizationRequest({
        client_id: openidConfig.clientId,
        response_type: AuthorizationRequest.RESPONSE_TYPE_CODE,
        redirect_uri: callbackUri,
        scope: "openid"
    }, new DefaultCrypto(), true)

    const authorizationHandler = new RedirectRequestHandler()
    authorizationHandler.performAuthorizationRequest(config, request)
}

export async function doAuthorizationCallback(openidConfig: OpenidConfig) {
    return new Promise(((resolve, reject) => {
        const notifier = new AuthorizationNotifier()
        notifier.setAuthorizationListener(((request, response, error) => {
            if (error != null) {
                reject(error)
            } else if (response != null) {
                resolve(exchangeCodeForTokens(response.code, request, openidConfig))
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

async function exchangeCodeForTokens(code: string, authorizationRequest: AuthorizationRequest, openidConfig?: OpenidConfig) {
    const tokenHandler = new BaseTokenRequestHandler(new FetchRequestor())
    if (openidConfig == null) {
        openidConfig = DEFAULT_OPENID_CONFIG
    }

    // if PKCE extension is used, we need to send the code_verifier along in the TokenRequest
    let extras = {} as Record<string, string>
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
    const response = await tokenHandler.performTokenRequest(await getServiceConfiguration(), request)
    storeTokenResponse(response)
}

async function renewTokens(openidConfig?: OpenidConfig) {
    const refreshToken = sessionStorage.getItem(KEY_REFRESH_TOKEN)
    if (openidConfig == null) {
        openidConfig = DEFAULT_OPENID_CONFIG
    }

    if (refreshToken != null) {
        const handler = new BaseTokenRequestHandler(new FetchRequestor())
        const request = new TokenRequest({
            grant_type: GRANT_TYPE_REFRESH_TOKEN,
            client_id: openidConfig.clientId,
            refresh_token: refreshToken,
            redirect_uri: ""
        })
        const response = await handler.performTokenRequest(await getServiceConfiguration(), request)
        storeTokenResponse(response)
    }
}

function isTokenExpired(token: string) {
    const { payload } = decodeToken(token)
    return payload.exp <= Date.now() / 1000
}

async function getServiceConfiguration(openidConfig?: OpenidConfig) {
    if (openidConfig == null) {
        openidConfig = DEFAULT_OPENID_CONFIG
    }

    const cachedIssuerConfig = sessionStorage.getItem(KEY_ISSUER_CONFIG)
    if (cachedIssuerConfig == null) {
        const config = await AuthorizationServiceConfiguration.fetchFromIssuer(openidConfig.issuer, new FetchRequestor())
        sessionStorage.setItem(KEY_ISSUER_CONFIG, JSON.stringify(config.toJson()))
        return config
    } else {
        return new AuthorizationServiceConfiguration(JSON.parse(cachedIssuerConfig))
    }
}

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
