export default interface IConfig {
  client_id: string;
  redirect_uri: string;
  authorization_endpoint: string;
  token_endpoint: string;
  requested_scopes: string;
  storage?: Storage;
}
