import decode from 'jwt-decode';
import axios from 'axios';

export default class AuthService {
    static instance = null;

    constructor() {
        this.domain = 'http://localhost:4000/api/v1';
        this.fetch = this.fetch.bind(this);
        this.login = this.login.bind(this);
        this.getUserID = this.getUserID.bind(this);
    }

    static getInstance() {
        if (AuthService.instance == null) {
            AuthService.instance = new AuthService();
        }

        return this.instance;
    }

    static setToken(idToken) {
        localStorage.setItem('user_id', decode(idToken).id);
        localStorage.setItem('id_token', idToken);
    }

    static getToken() {
        return localStorage.getItem('id_token')
    }

    static logout() {
        localStorage.removeItem('id_token');
    }

    static _checkStatus(response) {
        if (response.status >= 200 && response.status < 300) {
            return response
        } else {
            let error = new Error(response.statusText);
            error.response = response;
            throw error
        }
    }

    login(email, password) {
        return this.fetch('/auth/login', {
            method: 'POST',
            data: {
                email,
                password
            }
        }).then(res => {
            AuthService.setToken(res.token);
            return Promise.resolve(res);
        })
    }

    register(username, email, password) {
        return this.fetch('/auth/register', {
            method: 'POST',
            data: {
                username,
                email,
                password
            }
        }).then(res => {
            AuthService.setToken(res.token);
            return Promise.resolve(res);
        })
    }

    static isTokenExpired(token) {
        try {
            console.log('Checking expiry');
            const decoded = decode(token);
            let b = decoded.exp < Date.now() / 1000;
            console.log('Expired: ' + b);
            return b;
        }
        catch (err) {
            console.log('Error occurred');
            console.error(err);
            return false;
        }
    }

    isLoggedIn() {
        const token = AuthService.getToken();
        let b = !!token && !AuthService.isTokenExpired(token);
        console.log('Logged in: ' + b);
        return b;
    }

    getUserID() {
        return decode(AuthService.getToken()).id;
    }

    fetch(url, options) {
        const headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        };

        if (this.isLoggedIn()) {
            headers['Authorization'] = 'Bearer ' + AuthService.getToken()
        }

        return axios({
            baseURL: this.domain,
            url: url,
            headers: headers,
            ...options
        })
            .then(AuthService._checkStatus)
            .then(response => response.data);
    }
}
