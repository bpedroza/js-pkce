
const base64urlencode = str => btoa(String.fromCharCode.apply(null, new Uint8Array(str)))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const generateRandomString = () => {
  const array = new Uint32Array(28);
  window.crypto.getRandomValues(array);

  return Array.from(array, dec => (`0${dec.toString(16)}`).substr(-2)).join('');
};

const generateQueryString = (options) => {
  let query = '?';

  Object.entries(options).forEach(([key, value]) => {
    query += `${key}=${encodeURIComponent(value)}&`;
  });

  return query.substring(0, (query.length - 1));
};

const queryParams = () => {
  let match;

  const urlParams = {};
  const pl = /\+/g; // Regex for replacing addition symbol with a space
  const search = /([^&=]+)=?([^&]*)/g;
  const decode = s => decodeURIComponent(s.replace(pl, ' '));
  const query = window.location.search.substring(1);

  while ((match = search.exec(query)) !== null) {
    urlParams[decode(match[1])] = decode(match[2]);
  }

  return urlParams;
};

const randomStringFromStorage = (key) => {
  const fromStorage = sessionStorage.getItem(key);
  if (fromStorage === null) {
    sessionStorage.setItem(key, generateRandomString());
  }

  return sessionStorage.getItem(key);
};

const sha256 = (plain) => {
  const encoder = new TextEncoder();
  const data = encoder.encode(plain);

  return window.crypto.subtle.digest('SHA-256', data);
};

export default {
  base64urlencode,
  generateRandomString,
  generateQueryString,
  queryParams,
  randomStringFromStorage,
  sha256,
};
