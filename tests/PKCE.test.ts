import PKCE from '../src/PKCE';
import fetch from 'jest-fetch-mock';

const config = {
  client_id: '42',
  redirect_uri: 'http://localhost:8080/',
  authorization_endpoint: 'https://example.com/auth',
  token_endpoint: 'https://example.com/token',
  requested_scopes: '*',
};

describe('Test PKCE authorization url', () => {
  it('Should build an authorization url', () => {
    const instance = new PKCE(config);
    const url = instance.authorizeUrl();

    expect(url).toContain(config.authorization_endpoint);
    expect(url).toContain('?response_type=code');
    expect(url).toContain('&client_id=' + config.client_id);
    expect(url).toContain('&state=');
    expect(url).toContain('&scope=*');
    expect(url).toContain('&redirect_uri=' + encodeURIComponent(config.redirect_uri));
    expect(url).toContain('&code_challenge=');
    expect(url).not.toContain('%3D');
    expect(url).toContain('&code_challenge_method=S256');
  });

  it('Should include additional parameters', () => {
    const instance = new PKCE(config);
    const url = instance.authorizeUrl({test_param: 'test'});

    expect(url).toContain(config.authorization_endpoint);
    expect(url).toContain('?response_type=code');
    expect(url).toContain('&client_id=' + config.client_id);
    expect(url).toContain('&test_param=test');
  });

  it('Should update state from additional params', async () => {
    const instance = new PKCE(config);
    const url = instance.authorizeUrl({state: 'Anewteststate'});

    expect(url).toContain('&state=Anewteststate');
    expect(sessionStorage.getItem('pkce_state')).toEqual('Anewteststate');
  });
});

describe('Test PKCE exchange code for token', () => {
  it('Should throw an error when error is present', async () => {
    expect.assertions(1);
    const url = 'https://example.com?error=Test+Failure';
    const instance = new PKCE(config);

    try {
      const token = await instance.exchangeForAccessToken(url);
    } catch (e) {
      expect(e).toEqual({
        error: 'Test Failure',
      });
    }
  });

  it('Should throw an error when state mismatch', async () => {
    expect.assertions(1);
    const url = 'https://example.com?state=invalid';
    const instance = new PKCE(config);

    try {
      const token = await instance.exchangeForAccessToken(url);
    } catch (e) {
      expect(e).toEqual({
        error: 'Invalid State',
      });
    }
  });

  it('Should make a request to token endpoint', async () => {
    await mockRequest();

    expect(fetch.mock.calls.length).toEqual(1);
    expect(fetch.mock.calls[0][0]).toEqual(config.token_endpoint);
  });

  it('Should set code verifier', async () => {
    await mockRequest();

    expect(sessionStorage.getItem('pkce_code_verifier')).not.toEqual(null);
  });

  it('Should request with headers', async () => {
    await mockRequest();
    const headers = fetch.mock.calls[0][1].headers;

    expect(headers['Accept']).toEqual('application/json');
    expect(headers['Content-Type']).toEqual('application/x-www-form-urlencoded;charset=UTF-8');
  });

  it('Should request with body', async () => {
    await mockRequest();
    const body = new URLSearchParams(fetch.mock.calls[0][1].body.toString());

    expect(body.get('grant_type')).toEqual('authorization_code');
    expect(body.get('code')).toEqual('123');
    expect(body.get('client_id')).toEqual(config.client_id);
    expect(body.get('redirect_uri')).toEqual(config.redirect_uri);
    expect(body.get('code_verifier')).not.toEqual(null);
  });

  it('Should request with additional parameters', async () => {
    await mockRequest({test_param: 'testing'});
    const body = new URLSearchParams(fetch.mock.calls[0][1].body.toString());

    expect(body.get('grant_type')).toEqual('authorization_code');
    expect(body.get('test_param')).toEqual('testing');
  });

  async function mockRequest(additionalParams: object = {}) {
    sessionStorage.setItem('pkce_state', 'teststate');
    const url = 'https://example.com?state=teststate&code=123';
    const instance = new PKCE(config);

    const mockSuccessResponse = {
      access_token: 'token',
      expires_in: 123,
      refresh_expires_in: 234,
      refresh_token: 'refresh',
      scope: '*',
      token_type: 'type',
    };

    fetch.resetMocks();
    fetch.mockResponseOnce(JSON.stringify(mockSuccessResponse))

    sessionStorage.removeItem('pkce_code_verifier');

    await instance.exchangeForAccessToken(url, additionalParams);
  }
});

describe('Test PCKE refresh token', () => {
  const refreshToken = 'REFRESH_TOKEN';

  it('Should make a request to token endpoint', async () => {
    await mockRequest();

    expect(fetch.mock.calls.length).toEqual(1);
    expect(fetch.mock.calls[0][0]).toEqual(config.token_endpoint);
  });

  it('Should request with headers', async () => {
    await mockRequest();
    const headers = fetch.mock.calls[0][1].headers;

    expect(headers['Accept']).toEqual('application/json');
    expect(headers['Content-Type']).toEqual('application/x-www-form-urlencoded;charset=UTF-8');
  });

  it('Should request with body', async () => {
    await mockRequest();
    const body = new URLSearchParams(fetch.mock.calls[0][1].body.toString());

    expect(body.get('grant_type')).toEqual('refresh_token');
    expect(body.get('client_id')).toEqual(config.client_id);
    expect(body.get('refresh_token')).toEqual(refreshToken);
  });


  async function mockRequest() {
    const instance = new PKCE(config);

    const mockSuccessResponse = {
      access_token: 'token',
      expires_in: 123,
      refresh_expires_in: 234,
      refresh_token: 'refresh',
      scope: '*',
      token_type: 'type',
    };

    fetch.resetMocks();
    fetch.mockResponseOnce(JSON.stringify(mockSuccessResponse))

    await instance.refreshAccessToken(refreshToken);
  }
});


describe('Test storage types', () => {
  it('Should default to sessionStorage, localStorage emtpy', async () => {
    sessionStorage.removeItem('pkce_code_verifier');
    localStorage.removeItem('pkce_code_verifier');

    const instance = new PKCE({ ...config });
    instance.authorizeUrl();

    expect(sessionStorage.getItem('pkce_code_verifier')).not.toEqual(null);
    expect(localStorage.getItem('pkce_code_verifier')).toEqual(null);
  });

  it('Should allow for using localStorage, sessionStorage emtpy', async () => {
    sessionStorage.removeItem('pkce_code_verifier');
    localStorage.removeItem('pkce_code_verifier');

    const instance = new PKCE({ ...config, storage: localStorage });
    instance.authorizeUrl();

    expect(sessionStorage.getItem('pkce_code_verifier')).toEqual(null);
    expect(localStorage.getItem('pkce_code_verifier')).not.toEqual(null);
  });
});

describe('Test additional cors options', () => {
  it('Should have set the cors options correctly', async () => {
    const instance = new PKCE(config);
    const opts = instance.enableCorsCredentials(true)
    expect(opts.credentials).toEqual('include')
    expect(opts.mode).toEqual('cors')

    // unset cors options
    const newOpts = instance.enableCorsCredentials(false)
    expect(newOpts.credentials).toBe(undefined)
    expect(newOpts.mode).toBe(undefined)
  });
});