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

    getUser(): Promise<UserSchema>;

    getToken(): string | void;
}

type TokenSchema = {
    id: Identifier;
}

let token: (string | void) = localStorage.getItem('jwt_token');

function _setToken(_token) {
    token = _token;
    localStorage.setItem('jwt_token', _token);
    return _token;
}

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
        return token !== undefined;
    },
    logout() {
        localStorage.removeItem('jwt_token');
        token = undefined;
    },
    getUser() {
        return new Promise((resolve, reject) => {
            if (!this.isLoggedIn()) {
                reject('Not logged in');
            }

            let data: TokenSchema = decode(token);

            UserStore.getById(data.id).then(resolve);
        });
    },
    getToken() {
        return token;
    }
};

export const Auth: AuthService = AuthFetcher;