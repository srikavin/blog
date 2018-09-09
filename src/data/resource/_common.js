// @flow
import axios, {AxiosInstance} from 'axios';
import {Auth} from './auth.js'
import type {Identifier} from './identifier';

export const baseURL = process.env.NODE_ENV === 'production' ? 'https://srikavin.me/api/v1' : 'http://localhost:4000/api/v1';

const axiosInstance: AxiosInstance = axios.create({
    baseURL: baseURL,
    timeout: 100000
});

export function _v(url: string, vars: any): string {
    url.split('/').forEach((e) => {
        if (e.startsWith(':')) {
            url = url.replace(e, vars[e.substring(1)]);
        }
    });

    return url;
}

export function auth(axios: AxiosInstance) {
    axios.defaults.headers['x-access-token'] = Auth.getToken();
    return axios;
}

export default axiosInstance;

export class Resource {
    axios: AxiosInstance;
    endpoint: string;

    constructor(endpoint: string, axios: AxiosInstance) {
        this.endpoint = endpoint;
        this.axios = axios;
    }

    getById(id: Identifier) {
        this.axios.get(`${this.endpoint}/:id`)
            .then((e) => {
                return e.data;
            });
    }
}

