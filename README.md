![Build Status](https://github.com/bpedroza/js-pkce/actions/workflows/run-tests.yml/badge.svg)

# js-pkce
A package that makes using the OAuth2 PKCE flow easier

## Installation
`npm i js-pkce`

## Create a new instance
Create a new instance of js-pkce with all of the details needed.

```javascript
import PKCE from 'js-pkce';
const pkce = new PKCE({
  client_id: 'myclientid',
  redirect_uri: 'http://localhost:8080/auth',
  authorization_endpoint: 'https://authserver.com/oauth/authorize',
  token_endpoint: 'https://authserver.com/oauth/token',
  revoke_endpoint: 'https://authserver.com/oauth/revoke', // optional
  requested_scopes: '*',
  storage: sessionStorage // optional
});
```

## Start the authorization process
Typically you just need to go to the authorization url to start the process.
This example is something that might work in a SPA.

```javascript
window.location.replace(pkce.authorizeUrl());
```

You may add additional query parameters to the authorize url by using an optional second parameter:

```javascript
const additionalParams = {test_param: 'testing'};
window.location.replace(pkce.authorizeUrl(additionalParams));
```

## Trade the code for a token
After logging in with the authorization server, you will be redirected to the value in
the `redirect_uri` parameter you set when creating the instance.
Again, this is an example that might work for a SPA.

When you get back here, you need to exchange the code for a token.

```javascript
const url = window.location.href;
pkce.exchangeForAccessToken(url).then((resp) => {
  const token = resp.access_token;
  // Do stuff with the access token.
});
```

As with the authorizeUrl method, an optional second parameter may be passed to
the `exchangeForAccessToken` method to send additional parameters to the request:

```javascript
const url = window.location.href;
const additionalParams = {test_param: 'testing'};

pkce.exchangeForAccessToken(url, additionalParams).then((resp) => {
  const token = resp.access_token;
  // Do stuff with the access token.
});
```

## Refreshing the token
Get a new access token using a refresh token

```javascript
pkce.refreshAccessToken(refreshToken).then((resp) => {
  const accessToken = resp.access_token;
  const refreshToken = resp.refresh_token;
  // Do stuff with the access & refresh token.
});
```

## Revoking a token
Revoke a token. Note that the specification for this functionality in the context of PKCE
is not very well defined. This may not work for all authorization servers.

You may optionally pass a `token_type_hint` as the second parameter.

```javascript
pkce.revokeToken(tokenToExpire, 'access_token')
```

## Cors credentials
When using httpOnly cookies, there is some additional configuration required. The method 
`enableCorsCredentials` can be called to allow sending credentials.

```javascript
pkce.enableCorsCredentials(true);
```

## A note on Storage
By default, this package will use `sessionStorage` to persist the `pkce_state`. On (mostly) mobile
devices there's a higher chance users are returning in a different browser tab. E.g. they kick off
in a WebView & get redirected to a new tab. The `sessionStorage` will be empty there.

In this case it you can opt in to use `localStorage` instead of `sessionStorage`:

```javascript
import PKCE from 'js-pkce';
const pkce = new PKCE({
  // ...
  storage: localStorage, // any Storage object, sessionStorage (default) or localStorage 
});
```
