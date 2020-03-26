"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var sha256_1 = __importDefault(require("crypto-js/sha256"));
var enc_base64_1 = __importDefault(require("crypto-js/enc-base64"));
var lib_typedarrays_1 = __importDefault(require("crypto-js/lib-typedarrays"));
var PKCE = /** @class */ (function () {
    /**
     * Initialize the instance with configuration
     * @param {IConfig} config
     */
    function PKCE(config) {
        this.state = '';
        this.codeVerifier = '';
        this.config = config;
    }
    /**
     * Generate the authorize url
     * @return Promise<string>
     */
    PKCE.prototype.authorizeUrl = function () {
        var codeChallenge = this.pkceChallengeFromVerifier();
        var queryString = this.generateAuthQueryString({
            response_type: 'code',
            client_id: this.config.client_id,
            state: this.getState(),
            scope: this.config.requested_scopes,
            redirect_uri: this.config.redirect_uri,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256',
        });
        return "" + this.config.authorization_endpoint + queryString;
    };
    /**
     * Given the return url, get a token from the oauth server
     * @param  url current urlwith params from server
     * @return {Promise<ITokenResponse>}
     */
    PKCE.prototype.exchangeForAccessToken = function (url) {
        var _this = this;
        return this.parseAuthResponseUrl(url).then(function (q) {
            var data = {
                grant_type: 'authorization_code',
                code: q.code,
                client_id: _this.config.client_id,
                redirect_uri: _this.config.redirect_uri,
                code_verifier: _this.codeVerifier,
            };
            return fetch(_this.config.token_endpoint, {
                method: 'POST',
                body: JSON.stringify(data),
                headers: {
                    Accept: 'application/json',
                    'Content-Type': 'application/json;charset=UTF-8',
                },
            }).then(function (response) { return response.json(); });
        });
    };
    /**
     * Generate the query string for auth code exchange
     * @param  {IAuthQuery} options
     * @return {string}
     */
    PKCE.prototype.generateAuthQueryString = function (options) {
        var query = '?';
        Object.entries(options).forEach(function (_a) {
            var key = _a[0], value = _a[1];
            query += key + "=" + encodeURIComponent(value.toString()) + "&";
        });
        return query.substring(0, query.length - 1);
    };
    /**
     * Get the current codeVerifier or generate a new one
     * @return {string}
     */
    PKCE.prototype.getCodeVerifier = function () {
        if (this.codeVerifier === '') {
            this.codeVerifier = this.randomStringFromStorage('pkce_code_verifier');
        }
        return this.codeVerifier;
    };
    /**
     * Get the current state or generate a new one
     * @return {string}
     */
    PKCE.prototype.getState = function () {
        if (this.state === '') {
            this.state = this.randomStringFromStorage('pkce_state');
        }
        return this.state;
    };
    /**
     * Get the query params as json from a auth response url
     * @param  {string} url a url expected to have AuthResponse params
     * @return {Promise<IAuthResponse>}
     */
    PKCE.prototype.parseAuthResponseUrl = function (url) {
        var params = new URL(url).searchParams;
        return this.validateAuthResponse({
            error: params.get('error'),
            query: params.get('query'),
            state: params.get('state'),
            code: params.get('code'),
        });
    };
    /**
     * Generate a code challenge
     * @return {Promise<string>}
     */
    PKCE.prototype.pkceChallengeFromVerifier = function () {
        var hashed = sha256_1.default(this.getCodeVerifier());
        return enc_base64_1.default.stringify(hashed);
    };
    /**
     * Get a random string from storage or store a new one and return it's value
     * @param  {string} key
     * @return {string}
     */
    PKCE.prototype.randomStringFromStorage = function (key) {
        var fromStorage = sessionStorage.getItem(key);
        if (fromStorage === null) {
            sessionStorage.setItem(key, lib_typedarrays_1.default.random(64));
        }
        return sessionStorage.getItem(key) || '';
    };
    /**
     * Validates params from auth response
     * @param  {AuthResponse} queryParams
     * @return {Promise<IAuthResponse>}
     */
    PKCE.prototype.validateAuthResponse = function (queryParams) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            if (queryParams.error) {
                return reject({ error: queryParams.error });
            }
            if (queryParams.state !== _this.getState()) {
                return reject({ error: 'Invalid State' });
            }
            return resolve(queryParams);
        });
    };
    return PKCE;
}());
exports.default = PKCE;
