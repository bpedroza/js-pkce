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
  requested_scopes: '*',
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
