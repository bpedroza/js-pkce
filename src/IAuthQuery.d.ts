export default interface IAuthQuery {
  response_type: string;
  client_id: string;
  state: string;
  scope: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: string;
}
