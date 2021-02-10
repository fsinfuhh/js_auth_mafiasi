declare module "jwt-js" {
    // See https://www.npmjs.com/package/jwt-js

    export interface DecodedToken {
        header: {
            alg: string,
            typ: string
        } | Record<string, string | undefined>,
        payload: Record<string, string | undefined>,
        signature: string
    }

    export function decodeToken(token: string): DecodedToken
}