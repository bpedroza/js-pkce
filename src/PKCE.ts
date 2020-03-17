
interface AuthQuery {
  error: string | null,
  query: string | null,
  state: string | null,
  code: string | null,
}

export default class PKCE {

  private config;
  private state;
  private codeVerifier;

  constructor(config) {
    this.config = {
      client_id: '',
      redirect_uri: '',
      authorization_endpoint: '',
      token_endpoint: '',
      requested_scopes: '*',
    };
  }

  private getState(): string {
    if (typeof (this.state) === 'undefined') {
      this.state = this.randomStringFromStorage('pkce_state');
    }

    return this.state;
  }

  private getCodeVerifier(): string {
    if (typeof (this.codeVerifier) === 'undefined') {
      this.codeVerifier = this.randomStringFromStorage('pkce_code_verifier');
    }

    return this.codeVerifier;
  }

  public async authorizeUrl() {
    const codeChallenge = await this.pkceChallengeFromVerifier();

    const queryString = this.generateQueryString({
      response_type: 'code',
      client_id: this.config.client_id,
      state: this.getState(),
      scope: this.config.requested_scopes,
      redirect_uri: this.config.redirect_uri,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });

    return `${this.config.authorization_endpoint}${queryString}`;
  }

  public exchangeForAccessToken() {
    const queryParams = this.queryParams();

    return new Promise<AuthQuery>((resolve) => {
      if (queryParams.error) {
        throw new Error(queryParams.error);
      }
      this.checkState(queryParams.state);
      return resolve(queryParams);
    }).then((q) => {
      const url = this.config.token_endpoint;
      const data = {
        grant_type: 'authorization_code',
        code: q.code,
        client_id: this.config.client_id,
        redirect_uri: this.config.redirect_uri,
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

  private base64urlencode(str): string {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(str)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }


  private checkState(returnedState) {
    if (returnedState !== this.getState()) {
      throw new Error('Invalid state');
    }
  }

  private generateRandomString(): string {
    const array = new Uint32Array(28);
    window.crypto.getRandomValues(array);

    return Array.from(array, dec => (`0${dec.toString(16)}`).substr(-2)).join('');
  }

  private generateQueryString(options): string {
    let query = '?';

    Object.entries(options).forEach(([key, value]) => {
      query += `${key}=${encodeURIComponent(value.toString())}&`;
    });

    return query.substring(0, (query.length - 1));
  }

  private async pkceChallengeFromVerifier(): Promise<string> {
    const hashed = await this.sha256(this.getCodeVerifier());
    return this.base64urlencode(hashed);
  }

  private queryParams(): AuthQuery {
    const params = new URL(window.location.href).searchParams;

    return {
      error: params.get("error"),
      query: params.get("query"),
      state: params.get("state"),
      code: params.get("code"),
    };
  }

  private randomStringFromStorage(key): string {
    const fromStorage = sessionStorage.getItem(key);
    if (fromStorage === null) {
      sessionStorage.setItem(key, this.generateRandomString());
    }

    return sessionStorage.getItem(key);
  }

  private sha256(plain): PromiseLike<ArrayBuffer> {
    const encoder = new TextEncoder();
    const data = encoder.encode(plain);

    return window.crypto.subtle.digest('SHA-256', data);
  }
}
