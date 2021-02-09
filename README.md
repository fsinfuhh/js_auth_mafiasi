# Javascript Auth with Mafiasi

Javascript authentication library for working with Mafiasi.

## What it does

This library is intended for applications which are intended to be used in the context of [Mafiasi](https://mafiasi.de).
It particularly aims to take care of any authentication related functionality so that all Mafiasi services use the
same technology and conform to the same security requirements.

## How it works

This is probably the most useful feature and explained in great detail [on the OAUTH website](https://www.oauth.com/)
which also provides a [playground](https://www.oauth.com/playground/oidc.html) for interactively trying it out.

In summary the following steps are performed:
1. User clicks *Login with Mafiasi* in the current application
2. The application redirects to
   `https://<your-oidc-issuer>/auth?state=<something>&scope=<requested-scopes>&redirect_uri=<some-url-to-this-application>&client_id=<ths-application-id>`
3. The oidc issuer validates that the passed `redirect_uri` is allowed for the passed `client_id`, logs the user in
   (we don't really care how) and redirects back to `<redirect_uri>?state=<same-state>&session_state=<some-code>`
4. This application then validates that the passed `state` is the same and therefore associates step 1 with this response
   (prevents replay attacks), parses the `session_state` according to some openid spec, validates it (because it is signed),
   extracts some information from it (i.e. username) and logs the user in.

   At this point, the user gets authenticated via the standard django authentication framework and accessible as normal.

## How to use it

TODO
