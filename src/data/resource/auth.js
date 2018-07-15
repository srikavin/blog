//@flow
import type {UserSchema} from './user';
import {UserStore} from './user';
import axios from './_common';
import {Identifier} from './identifier'
import decode from 'jwt-decode';


interface AuthService {
    login(email: string, password: string): Promise<string>;

    register(email: string, password: string, username: string): Promise<string>;

    isLoggedIn(): boolean;

    logout(): void;

    getUser(): UserSchema | any;

    getToken(): string | void;

    checkLogin(token: string): string;

    onChange(f: (user: UserSchema) => void): void;
}

type TokenSchema = {
    id: Identifier;
}


class AuthFetcher implements AuthService {
    user: ?UserSchema;
    userPromise = Promise.resolve({});

    _setToken;
    callOnChange;
    _onChangeFunc = (user) => {
    };

    constructor() {
        this._setToken = this._setToken.bind(this);
        this.callOnChange = this.callOnChange.bind(this);
    }

    login(email, password) {
        return axios.post('/auth/login', {email, password})
            .then((e) => e.data.token)
            .then(this._setToken);
    }

    register(email, password, username) {
        return axios.post('/auth/register', {email, username, password})
            .then((e) => e.data.token)
            .then(this._setToken);
    }

    isLoggedIn() {
        return token !== undefined && token !== null;
    }

    callOnChange(user) {
        this._onChangeFunc(user || {});
        return user;
    }

    onChange(f) {
        this._onChangeFunc = f;
    }

    checkLogin(token) {
        axios.defaults.headers['x-access-token'] = token;
        return axios.get('/auth/me')
            .then((e) => e.data.token)
            .then(this._setToken);
    }

    logout() {
        localStorage.removeItem('jwt_token');
        token = undefined;
        this.callOnChange({});
    }

    getUser() {
        if (this.user) {
            return Promise.resolve(this.user);
        }
        if (this.isLoggedIn()) {
            return this.userPromise;
        }
    }

    getToken() {
        return token;
    }

    _setToken(_token) {
        token = _token;
        localStorage.setItem('jwt_token', _token);
        if (_token === null || _token === undefined) {
            this.logout();
            return;
        }

        let data: TokenSchema = decode(token);

        this.userPromise = UserStore.getById(data.id)
            .then(e => {
                this.user = e;
                return this.user;
            })
            .then(this.callOnChange);

        return _token;
    }
}

let AuthInstance = new AuthFetcher();


let token: (string | any) = localStorage.getItem('jwt_token');
if (token !== null) {
    AuthInstance.checkLogin(token);
}

window.addEventListener('storage', function (e) {
    console.log(e);
    if (e.key === 'jwt_token' && (e.oldValue !== e.newValue)) {
        AuthInstance.checkLogin(e.newValue);
    }
});

export const Auth: AuthService = AuthInstance;