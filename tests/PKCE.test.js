const PKCE = require('../lib/PKCE');

describe('Construction Test', () => {
  it('should not throw any exceptions', () => {
    const config = {
      client_id: '',
      redirect_uri: '',
      authorization_endpoint: '',
      token_endpoint:'',
    };
    const instance = new PKCE(config);
    expect(instance.isReady()).toBe(true);
  });

  it('should throw an exception when client_id missing', () => {
    const t = () => {
      const config = {
        redirect_uri: '',
        authorization_endpoint: '',
        token_endpoint:'',
      };
      new PKCE(config);
    };
    expect(t).toThrow(Error);
  });
});
