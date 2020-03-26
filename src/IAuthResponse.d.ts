export default interface IAuthResponse {
  error: string | null;
  query: string | null;
  state: string | null;
  code: string | null;
}
