import PKCE from '../src/PKCE';
import fetch from 'jest-fetch-mock';
import ITokenResponse from '../src/ITokenResponse';

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

  it('Should request with headers', async () => {
    await mockRequest();
    const headers = fetch.mock.calls[0][1]?.headers ?? [];

    expect(headers['Accept']).toEqual('application/json');
    expect(headers['Content-Type']).toEqual('application/x-www-form-urlencoded;charset=UTF-8');
  });

  it('Should request with body', async () => {
    await mockRequest();
    const body = new URLSearchParams(fetch.mock.calls[0][1]?.body?.toString());

    expect(body.get('grant_type')).toEqual('authorization_code');
    expect(body.get('code')).toEqual('123');
    expect(body.get('client_id')).toEqual(config.client_id);
    expect(body.get('redirect_uri')).toEqual(config.redirect_uri);
    expect(body.get('code_verifier')).not.toEqual(null);
  });

  it('Should request with additional parameters', async () => {
    await mockRequest({test_param: 'testing'});
    const body = new URLSearchParams(fetch.mock.calls[0][1]?.body?.toString());

    expect(body.get('grant_type')).toEqual('authorization_code');
    expect(body.get('test_param')).toEqual('testing');
  });

  it('Should have set the cors credentials options correctly', async () => {
    // enable cors credentials
    await mockRequest({}, true)
    expect(fetch.mock.calls[0][1]?.mode).toEqual('cors');
    expect(fetch.mock.calls[0][1]?.credentials).toEqual('include');
  });

  it('Should not have cors credentials options set', async () => {
    // disable cors credentials
    await mockRequest({}, false)
    expect(fetch.mock.calls[0][1]?.mode).toBeUndefined();
    expect(fetch.mock.calls[0][1]?.credentials).toBeUndefined();
  });

  it('Should not have cors credentials options set when not specified', async () => {
    await mockRequest({}, null)
    expect(fetch.mock.calls[0][1]?.mode).toBeUndefined();
    expect(fetch.mock.calls[0][1]?.credentials).toBeUndefined();
  });

  it('Should return token', async () => {
    const result = await mockRequest({});
    expect(result.access_token).toEqual('token');
  });

  /* @TODO breaking change - implement in v2.0 it('Should clear storage after token exchange', async () => {
    await mockRequest({}, false);
    expect(sessionStorage.getItem('pkce_code_verifier')).toEqual(null);
    expect(sessionStorage.getItem('pkce_state')).toEqual(null);
  }); */ 

  async function mockRequest(additionalParams: object = {}, enableCorsCredentials: boolean|null = null): Promise<ITokenResponse> {
    sessionStorage.setItem('pkce_state', 'teststate');
    const url = 'https://example.com?state=teststate&code=123';
    const instance = new PKCE(config);

    if(enableCorsCredentials !== null) {
      instance.enableCorsCredentials(enableCorsCredentials);
    } 

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

    return await instance.exchangeForAccessToken(url, additionalParams);
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
    const headers = fetch.mock.calls[0][1]?.headers ?? [];

    expect(headers['Accept']).toEqual('application/json');
    expect(headers['Content-Type']).toEqual('application/x-www-form-urlencoded;charset=UTF-8');
  });

  it('Should request with body', async () => {
    await mockRequest();
    const body = new URLSearchParams(fetch.mock.calls[0][1]?.body?.toString());

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

describe('Test PCKE revoke token', () => {
  const tokenToExpire = 'A_TOKEN_TO_EXPIRE';

  it('Should make a request to revoke token endpoint', async () => {
    const url = 'https://example.com/revoke';
    const ok = await mockRequest({revoke_endpoint: url});

    expect(ok).toEqual(true);
    expect(fetch.mock.calls.length).toEqual(1);
    expect(fetch.mock.calls[0][0]).toEqual(url);
  });


  it('Should return false on error response', async () => {
    const instance = new PKCE({
      ...config,
      revoke_endpoint: 'https://example.com/revoke'
    });

    fetch.resetMocks();
    fetch.mockReject(new Error('fake error message'))
    const ok = await instance.revokeToken('atoken');

    expect(ok).toEqual(false);
  });

  it('Should request with headers', async () => {
    const url = 'https://example.com/revoke';
    await mockRequest({revoke_endpoint: url});
    const headers = fetch.mock.calls[0][1]?.headers ?? [];

    expect(headers['Content-Type']).toEqual('application/x-www-form-urlencoded;charset=UTF-8');
  });

  it('Should request with body', async () => {
    const url = 'https://example.com/revoke';
    await mockRequest({revoke_endpoint: url});
    const body = new URLSearchParams(fetch.mock.calls[0][1]?.body?.toString());

    expect(body.get('token')).toEqual(tokenToExpire);
    expect(body.get('client_id')).toEqual(config.client_id);
    expect(body.get('token_type_hint')).toBeNull();
  });

  it('Should request with body including type hint', async () => {
    const url = 'https://example.com/revoke';
    const hint = 'refresh_token'
    await mockRequest({revoke_endpoint: url}, hint);
    const body = new URLSearchParams(fetch.mock.calls[0][1]?.body?.toString());

    expect(body.get('token')).toEqual(tokenToExpire);
    expect(body.get('client_id')).toEqual(config.client_id);
    expect(body.get('token_type_hint')).toEqual(hint);
  });

  it('Should throw an error when not https and not localhost', async () => {
    expect.assertions(1);
    const url = 'http://example.com/revoke';

    try {
      await mockRequest({revoke_endpoint: url});
    } catch (e) {
      expect(e.message).toEqual('Protocol http: not allowed with this action.');
    }
  });

  it('Should not throw an error when not https and is localhost', async () => {
    const url = 'http://localhost:8000/revoke';
    await mockRequest({revoke_endpoint: url});

    expect(fetch.mock.calls.length).toEqual(1);
    expect(fetch.mock.calls[0][0]).toEqual(url);
  });

  async function mockRequest(configAddition: {revoke_endpoint: string}, hint: string = '') {
    const instance = new PKCE({
      ...config,
      ...configAddition
    });

    fetch.resetMocks();
    fetch.mockResponseOnce(JSON.stringify({}))

    if(hint.length == 0) {
      return await instance.revokeToken(tokenToExpire);
    }
    
    await instance.revokeToken(tokenToExpire, hint);
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
