import sha256 from 'crypto-js/sha256';
import Base64 from 'crypto-js/enc-base64';
import WordArray from 'crypto-js/lib-typedarrays';

interface AuthQuery {
  response_type: string;
  client_id: string;
  state: string;
  scope: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: string;
}

interface AuthResponse {
  error: string | null;
  query: string | null;
  state: string | null;
  code: string | null;
}

interface Config {
  client_id: string;
  redirect_uri: string;
  authorization_endpoint: string;
  token_endpoint: string;
  requested_scopes: string;
}

export default class PKCE {
  private config: Config;
  private state: string = '';
  private codeVerifier: string = '';

  constructor(config: Config) {
    this.config = config;
  }

  /**
   * Generate the authorize url
   * @return Promise<string>
   */
  public async authorizeUrl(): Promise<string> {
    const codeChallenge = await this.pkceChallengeFromVerifier();

    const queryString = this.generateAuthQueryString({
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

    return new Promise<AuthResponse>((resolve) => {
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
      }).then((response) => response.json());
    });
  }

  /**
   * Check the existing state against a given state
   * @param {string} returnedState
   */
  private checkState(returnedState: string | null): void {
    if (returnedState !== this.getState()) {
      throw new Error('Invalid state');
    }
  }

  /**
   * Generate the query string for auth code exchange
   * @param  {AuthQuery} options
   * @return {string}
   */
  private generateAuthQueryString(options: AuthQuery): string {
    let query = '?';

    Object.entries(options).forEach(([key, value]) => {
      query += `${key}=${encodeURIComponent(value.toString())}&`;
    });

    return query.substring(0, query.length - 1);
  }

  /**
   * Get the current codeVerifier or generate a new one
   * @return {string}
   */
  private getCodeVerifier(): string {
    if (this.codeVerifier === '') {
      this.codeVerifier = this.randomStringFromStorage('pkce_code_verifier');
    }

    return this.codeVerifier;
  }

  /**
   * Get the current state or generate a new one
   * @return {string}
   */
  private getState(): string {
    if (this.state === '') {
      this.state = this.randomStringFromStorage('pkce_state');
    }

    return this.state;
  }

  /**
   * Generate a code challenge
   * @return {Promise<string>}
   */
  private async pkceChallengeFromVerifier(): Promise<string> {
    const hashed = await sha256(this.getCodeVerifier());
    return Base64.stringify(hashed);
  }

  private queryParams(): AuthResponse {
    const params = new URL(window.location.href).searchParams;

    return {
      error: params.get('error'),
      query: params.get('query'),
      state: params.get('state'),
      code: params.get('code'),
    };
  }

  /**
   * Get a random string from storage or store a new one and return it's value
   * @param  {string} key
   * @return string
   */
  private randomStringFromStorage(key: string): string {
    const fromStorage = sessionStorage.getItem(key);
    if (fromStorage === null) {
      sessionStorage.setItem(key, WordArray.random(64));
    }

    return sessionStorage.getItem(key) || '';
  }
}
