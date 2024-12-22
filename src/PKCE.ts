import sha256 from 'crypto-js/sha256';
import Base64 from 'crypto-js/enc-base64';
import WordArray from 'crypto-js/lib-typedarrays';
import IAuthResponse from './IAuthResponse';
import IConfig from './IConfig';
import IObject from './IObject';
import ITokenResponse from './ITokenResponse';
import ICorsOptions from './ICorsOptions';

export default class PKCE {
  private readonly STATE_KEY: string = 'pkce_state';
  private readonly CODE_VERIFIER_KEY: string = 'pkce_code_verifier';

  private config: IConfig;
  private corsRequestOptions: ICorsOptions = {};

  /**
   * Initialize the instance with configuration
   * @param {IConfig} config
   */
  constructor(config: IConfig) {
    this.config = config;
  }

  /**
   * Allow the user to enable cross domain cors requests
   * @param  enable turn the cross domain request options on.
   * @return ICorsOptions
   */
  public enableCorsCredentials(enable: boolean): ICorsOptions {
    this.corsRequestOptions = enable
      ? {
          credentials: 'include',
          mode: 'cors',
        }
      : {};
    return this.corsRequestOptions;
  }

  /**
   * Generate the authorize url
   * @param  {object} additionalParams include additional parameters in the query
   * @return Promise<string>
   */
  public authorizeUrl(additionalParams: IObject = {}): string {
    this.setCodeVerifier();
    this.setState(additionalParams.state || null);
    const codeChallenge = this.pkceChallengeFromVerifier();

    const queryString = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.client_id,
      state: this.getState(),
      scope: this.config.requested_scopes,
      redirect_uri: this.config.redirect_uri,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      ...additionalParams
    }).toString();

    return `${this.config.authorization_endpoint}?${queryString}`;
  }

  /**
   * Given the return url, get a token from the oauth server
   * @param  url current urlwith params from server
   * @param  {object} additionalParams include additional parameters in the request body
   * @return {Promise<ITokenResponse>}
   */
  public async exchangeForAccessToken(url: string, additionalParams: IObject = {}): Promise<ITokenResponse> {
    const { code } = await this.parseAuthResponseUrl(url);
    const response = await fetch(this.config.token_endpoint, {
      method: 'POST',
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        client_id: this.config.client_id,
        redirect_uri: this.config.redirect_uri,
        code_verifier: this.getCodeVerifier(),
        ...additionalParams
      }),
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
      },
      ...this.corsRequestOptions,
    });

    return await response.json();
  }

  /**
   * Given a refresh token, return a new token from the oauth server
   * @param  refreshTokens current refresh token from server
   * @return {Promise<ITokenResponse>}
   */
  public async refreshAccessToken(refreshToken: string): Promise<ITokenResponse> {
    const response = await fetch(this.config.token_endpoint, {
      method: 'POST',
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: this.config.client_id,
        refresh_token: refreshToken,
      }),
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
      },
    });

    return await response.json();
  }

  /**
   * Revoke an existing token. 
   * Optionally send a token_type_hint as second parameter
   * @param {string} tokenToExpire the token to be expired
   * @param {string} hint when not empty, token_type_hint will be sent with request
   * @returns 
   */
  public async revokeToken(tokenToExpire: string, hint: string = ''): Promise<boolean> {
    this.checkEndpoint('revoke_endpoint');

    const params = new URLSearchParams({
      token: tokenToExpire,
      client_id: this.config.client_id,
    });

    if (hint.length) {
      params.append('token_type_hint', hint);
    }

    const response = await fetch(this.config.revoke_endpoint, {
      method: 'POST',
      body: params,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
      },
    });

    return response.ok;
  }

  /**
   * Get the current codeVerifier
   * @return {string}
   */
  public getCodeVerifier(): string {
    const codeVerifier = this.getStore().getItem(this.CODE_VERIFIER_KEY);

    if(null === codeVerifier) {
      throw new Error('Code Verifier not set.');
    }

    return codeVerifier;
  }

  /**
   * Get the current state
   * @return {string}
   */
  public getState(): string {
    const state = this.getStore().getItem(this.STATE_KEY);

    if(null === state) {
      throw new Error('State not set.');
    }

    return state;
  }

  /**
   * Check if an endpoint from configuration is set and using https protocol
   * Allow http on localhost
   * @param {string} propertyName the key of the item in configuration to check
   */
  private checkEndpoint(propertyName: string) {
    if (!this.config.hasOwnProperty(propertyName)) {
      throw new Error(`${propertyName} not configured.`);
    }

    const url = new URL(this.config[propertyName]);
    const isLocalHost = ['localhost', '127.0.0.1'].indexOf(url.hostname) !== -1;
    if (url.protocol !== 'https:' && !isLocalHost) {
      throw new Error(`Protocol ${url.protocol} not allowed with this action.`);
    }
  }

  /**
   * Generate a random string
   * @return {string}
   */
  private generateRandomString(): string {
    return WordArray.random(64);
  }

  /**
   * Get the query params as json from a auth response url
   * @param  {string} url a url expected to have AuthResponse params
   * @return {Promise<IAuthResponse>}
   */
  private parseAuthResponseUrl(url: string): Promise<IAuthResponse> {
    const params = new URL(url).searchParams;

    return this.validateAuthResponse({
      error: params.get('error'),
      query: params.get('query'),
      state: params.get('state'),
      code: params.get('code'),
    });
  }

  /**
   * Generate a code challenge
   * @return {Promise<string>}
   */
  private pkceChallengeFromVerifier(): string {
    const hashed = sha256(this.getCodeVerifier());
    return Base64.stringify(hashed).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  /**
   * Set the code verifier in storage to a random string
   * @return {void}
   */
  private setCodeVerifier(): void {
    this.getStore().setItem(this.CODE_VERIFIER_KEY, this.generateRandomString());
  }

  /**
   * Set the state in storage to a random string. 
   * Optionally set an explicit state
   * @param {string | null} explicit when set, we will use this value for the state value
   * @return {void}
   */
  private setState(explicit: string | null = null): void {
    const value = explicit !== null ? explicit : this.generateRandomString();
    this.getStore().setItem(this.STATE_KEY, value);
  }

  /**
   * Validates params from auth response
   * @param  {AuthResponse} queryParams
   * @return {Promise<IAuthResponse>}
   */
  private validateAuthResponse(queryParams: IAuthResponse): Promise<IAuthResponse> {
    return new Promise<IAuthResponse>((resolve, reject) => {
      if (queryParams.error) {
        return reject({ error: queryParams.error });
      }

      if (queryParams.state !== this.getState()) {
        return reject({ error: 'Invalid State' });
      }

      return resolve(queryParams);
    });
  }

  /**
   * Get the instance of Storage interface to use.
   * Defaults to sessionStorage.
   * @return {Storage}
   */
  private getStore(): Storage {
    return this.config?.storage || sessionStorage;
  }
}
