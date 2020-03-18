"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
var PKCE = /** @class */ (function () {
    function PKCE(config) {
        this.state = '';
        this.codeVerifier = '';
        this.config = {
            client_id: '',
            redirect_uri: '',
            authorization_endpoint: '',
            token_endpoint: '',
            requested_scopes: '*',
        };
    }
    /**
     * Generate the authorize url
     * @return Promise<string>
     */
    PKCE.prototype.authorizeUrl = function () {
        return __awaiter(this, void 0, void 0, function () {
            var codeChallenge, queryString;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.pkceChallengeFromVerifier()];
                    case 1:
                        codeChallenge = _a.sent();
                        queryString = this.generateAuthQueryString({
                            response_type: 'code',
                            client_id: this.config.client_id,
                            state: this.getState(),
                            scope: this.config.requested_scopes,
                            redirect_uri: this.config.redirect_uri,
                            code_challenge: codeChallenge,
                            code_challenge_method: 'S256',
                        });
                        return [2 /*return*/, "" + this.config.authorization_endpoint + queryString];
                }
            });
        });
    };
    PKCE.prototype.exchangeForAccessToken = function () {
        var _this = this;
        var queryParams = this.queryParams();
        return new Promise(function (resolve) {
            if (queryParams.error) {
                throw new Error(queryParams.error);
            }
            _this.checkState(queryParams.state);
            return resolve(queryParams);
        }).then(function (q) {
            var url = _this.config.token_endpoint;
            var data = {
                grant_type: 'authorization_code',
                code: q.code,
                client_id: _this.config.client_id,
                redirect_uri: _this.config.redirect_uri,
                code_verifier: _this.codeVerifier,
            };
            return fetch(url, {
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
     * Base64 encode a given string.
     * @param  {ArrayBuffer} str
     * @return {string}
     */
    PKCE.prototype.base64urlencode = function (str) {
        return btoa(String.fromCharCode.apply(null, new Uint8Array(str)))
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    };
    /**
     * Check the existing state against a given state
     * @param {string} returnedState
     */
    PKCE.prototype.checkState = function (returnedState) {
        if (returnedState !== this.getState()) {
            throw new Error('Invalid state');
        }
    };
    /**
     * Generate a random string
     * @return {string}
     */
    PKCE.prototype.generateRandomString = function () {
        var array = new Uint32Array(28);
        window.crypto.getRandomValues(array);
        return Array.from(array, function (dec) { return ("0" + dec.toString(16)).substr(-2); }).join('');
    };
    /**
     * Generate the query string for auth code exchange
     * @param  {AuthQuery} options
     * @return {string}
     */
    PKCE.prototype.generateAuthQueryString = function (options) {
        var query = '?';
        Object.entries(options).forEach(function (_a) {
            var key = _a[0], value = _a[1];
            query += key + "=" + encodeURIComponent(value.toString()) + "&";
        });
        return query.substring(0, (query.length - 1));
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
     * Generate a code challenge
     * @return {Promise<string>}
     */
    PKCE.prototype.pkceChallengeFromVerifier = function () {
        return __awaiter(this, void 0, void 0, function () {
            var hashed;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.sha256(this.getCodeVerifier())];
                    case 1:
                        hashed = _a.sent();
                        return [2 /*return*/, this.base64urlencode(hashed)];
                }
            });
        });
    };
    PKCE.prototype.queryParams = function () {
        var params = new URL(window.location.href).searchParams;
        return {
            error: params.get("error"),
            query: params.get("query"),
            state: params.get("state"),
            code: params.get("code"),
        };
    };
    /**
     * Get a random string from storage or store a new one and return it's value
     * @param  {string} key
     * @return string
     */
    PKCE.prototype.randomStringFromStorage = function (key) {
        var fromStorage = sessionStorage.getItem(key);
        if (fromStorage === null) {
            sessionStorage.setItem(key, this.generateRandomString());
        }
        return sessionStorage.getItem(key) || '';
    };
    /**
     * Create SHA256 hash of given string
     * @param  {string} plain
     * @return PromiseLike<ArrayBuffer>
     */
    PKCE.prototype.sha256 = function (plain) {
        var encoder = new TextEncoder();
        var data = encoder.encode(plain);
        return window.crypto.subtle.digest('SHA-256', data);
    };
    return PKCE;
}());
exports.default = PKCE;
