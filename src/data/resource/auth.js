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
}

type TokenSchema = {
    id: Identifier;
}

let onChange = (user) => {
};

let AuthFetcher: AuthService = {
    login(email, password) {
        return axios.post('/auth/login', {email, password})
            .then((e) => e.data.token)
            .then(_setToken);
    },
    register(email, password, username) {
        return axios.post('/auth/register', {email, username, password})
            .then((e) => e.data.token)
            .then(_setToken);
    },
    isLoggedIn() {
        return token !== undefined && token !== null;
    },
    onChange(f) {
        onChange = f;
    },
    checkLogin(token) {
        axios.defaults.headers['x-access-token'] = token;
        return axios.get('/auth/me')
            .then((e) => e.data.token)
            .then(_setToken);
    },
    logout() {
        localStorage.removeItem('jwt_token');
        token = undefined;
        onChange({});
    },
    getUser() {
        return user;
    },
    getToken() {
        return token;
    }
};


let token: (string | any) = localStorage.getItem('jwt_token');
if (token !== null) {
    AuthFetcher.checkLogin(token);
}

window.addEventListener('storage', function (e) {
    console.log(e);
    if (e.key === 'jwt_token' && (e.oldValue !== e.newValue)) {
        AuthFetcher.checkLogin(e.newValue);
    }
});

let user: UserSchema | any = {};

function _setToken(_token) {
    token = _token;
    if (_token === null || _token === undefined) {
        AuthFetcher.logout();
        return;
    }
    localStorage.setItem('jwt_token', _token);
    let data: TokenSchema = decode(token);
    UserStore
        .getById(data.id)
        .then(e => {
            user = e;
            return user;
        })
        .then(onChange);

    return _token;
}

export const Auth: AuthService = AuthFetcher;