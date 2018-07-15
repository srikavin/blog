// @flow
import axios, {AxiosInstance} from 'axios';
import authService from '../../util/AuthController';
import type {Identifier} from './identifier';

console.log(process.env.NODE_ENV);

const baseURL = process.env.NODE_ENV === 'production' ? 'http://ssh.sharath.pro:4000/api/v1' : 'http://localhost:4000/api/v1';

const axiosInstance: AxiosInstance = axios.create({
    baseURL: baseURL,
    timeout: 3500
});

export function _v(url: string, vars: any): string {
    console.log(url, vars);
    url.split('\/').forEach((e) => {
        if (e.startsWith(':')) {
            url = url.replace(e, vars[e.substring(1)]);
        }
    });

    return url;
}

export function auth(axios: AxiosInstance) {
    axios.defaults.headers['x-access-token'] = authService.getToken();
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

