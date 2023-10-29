export default interface ICorsOptions {
  credentials?: 'omit' | 'same-origin' | 'include';
  // RFC for mode options: https://fetch.spec.whatwg.org/#concept-request-mode
  mode?: 'cors' | 'no-cors' | 'same-origin' | 'navigate';
}
