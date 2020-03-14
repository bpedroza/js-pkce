import helpers from './helpers';

export default class PKCE {
  #config = {
    client_id: process.env.VUE_APP_OAUTH_CLIENT_ID,
    redirect_uri: process.env.VUE_APP_OAUTH_REDIRECT,
    authorization_endpoint: `${process.env.VUE_APP_API_URL}/oauth/authorize`,
    token_endpoint: `${process.env.VUE_APP_API_URL}/oauth/token`,
    requested_scopes: '*',
  };

  #state;

  #codeVerifier;

  get state() {
    if (typeof (this.#state) === 'undefined') {
      this.#state = helpers.randomStringFromStorage('pkce_state');
    }

    return this.#state;
  }

  get codeVerifier() {
    if (typeof (this.#codeVerifier) === 'undefined') {
      this.#codeVerifier = helpers.randomStringFromStorage('pkce_code_verifier');
    }

    return this.#codeVerifier;
  }

  async authorizeUrl() {
    const codeChallenge = await this.pkceChallengeFromVerifier();

    const queryString = helpers.generateQueryString({
      response_type: 'code',
      client_id: this.#config.client_id,
      state: this.state,
      scope: this.#config.requested_scopes,
      redirect_uri: this.#config.redirect_uri,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });

    return `${this.#config.authorization_endpoint}${queryString}`;
  }

  checkState(returnedState) {
    if (returnedState !== this.state) {
      throw new Error('Invalid state');
    }
  }

  exchangeForAccessToken() {
    const queryParams = helpers.queryParams();
    return new Promise((resolve) => {
      if (queryParams.error) {
        throw new Error(queryParams.error);
      }
      this.checkState(queryParams.state);
      return resolve(queryParams);
    }).then((q) => {
      const url = this.#config.token_endpoint;
      const data = {
        grant_type: 'authorization_code',
        code: q.code,
        client_id: this.#config.client_id,
        redirect_uri: this.#config.redirect_uri,
        code_verifier: this.codeVerifier,
      };

      return fetch(url, {
        method: 'POST',
        body: JSON.stringify(data),
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json;charset=UTF-8',
        },
      }).then(response => response.json());
    });
  }

  async pkceChallengeFromVerifier() {
    const hashed = await helpers.sha256(this.codeVerifier);
    return helpers.base64urlencode(hashed);
  }
}
