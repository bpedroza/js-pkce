import PKCE from '../src/PKCE';
import fetch from 'jest-fetch-mock';

const config = {
  client_id: '42',
  redirect_uri: 'http://localhost:8080/',
  authorization_endpoint: 'https://example.com/auth',
  token_endpoint: 'https://example.com/token',
  requested_scopes: "*"
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
    sessionStorage.setItem('pkce_state', 'teststate');
    const url = 'https://example.com?state=teststate';
    const instance = new PKCE(config);

    const mockSuccessResponse = {
      access_token: 'token',
      expires_in: 123,
      refresh_expires_in: 234,
      refresh_token: 'refresh',
      scope: '*',
      token_type: 'type',
    };
    fetch.mockResponseOnce(JSON.stringify(mockSuccessResponse))

    const token = await instance.exchangeForAccessToken(url);

    expect(fetch.mock.calls.length).toEqual(1)
    expect(fetch.mock.calls[0][0]).toEqual(config.token_endpoint)
  });
});
