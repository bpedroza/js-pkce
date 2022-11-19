import PKCE from '../src/PKCE';

const config = {
  client_id: '42',
  redirect_uri: 'http://localhost:8080/',
  authorization_endpoint: 'https://example.com/auth',
  token_endpoint: 'https://example.com/token',
  requested_scopes: '*',
  implicit: true,
};

describe('Test Implicit authorization url', () => {
  it('Should build an authorization url', () => {
    const instance = new PKCE(config);
    const url = instance.authorizeUrl();

    expect(url).toContain(config.authorization_endpoint);
    expect(url).toContain('?response_type=token');
    expect(url).toContain('&client_id=' + config.client_id);
    expect(url).toContain('&state=');
    expect(url).toContain('&scope=*');
    expect(url).toContain('&redirect_uri=' + encodeURIComponent(config.redirect_uri));
    expect(url).not.toContain('&code_challenge=');
    expect(url).not.toContain('%3D');
    expect(url).not.toContain('&code_challenge_method=S256');
  });

  it('Should include additional parameters', () => {
    const instance = new PKCE(config);
    const url = instance.authorizeUrl({ test_param: 'test' });

    expect(url).toContain(config.authorization_endpoint);
    expect(url).toContain('?response_type=token');
    expect(url).toContain('&client_id=' + config.client_id);
    expect(url).toContain('&test_param=test');
  });

  it('Should update state from additional params', async () => {
    const instance = new PKCE(config);
    const url = instance.authorizeUrl({ state: 'Anewteststate' });

    expect(url).toContain('&state=Anewteststate');
  });
});

describe('Test Implicit JWT for token', () => {
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

  it('Should obtain Implicit token', async () => {
    const instance = new PKCE(config);
    const accessToken =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const url = 'https://example.com?access_token=' + accessToken + '&scope=*';

    const token = await instance.exchangeForAccessToken(url);
    expect(token.access_token).toEqual(accessToken);
    expect(token.scope).toEqual('*');
  });
});
