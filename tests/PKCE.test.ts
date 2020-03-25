import PKCE from '../src/PKCE';

const config = {
  client_id: '42',
  redirect_uri: 'http://localhost:8080/',
  authorization_endpoint: 'https://example.com/auth',
  token_endpoint: 'https://example.com/token',
  requested_scopes: "*"
};

describe('Test PKCE functionality', () => {
  it('Should build an authorization url', async () => {
    const instance = new PKCE(config);
    const url = await instance.authorizeUrl();

    expect(url).toContain(config.authorization_endpoint);
    expect(url).toContain('?response_type=code');
    expect(url).toContain('&client_id=' + config.client_id);
    expect(url).toContain('&state=');
    expect(url).toContain('&scope=*');
    expect(url).toContain('&redirect_uri=' + encodeURIComponent(config.redirect_uri));
    expect(url).toContain('&code_challenge=');
    expect(url).toContain('&code_challenge_method=S256');
  });
});
