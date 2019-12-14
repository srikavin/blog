// @flow
import axios, {AxiosInstance} from 'axios';
import type {Identifier} from './identifier';

export const baseURL = '/api/v1';

const axiosInstance: AxiosInstance = axios.create({
    baseURL: baseURL,
    timeout: 100000
});

console.log(axiosInstance, 1111111111111);

export function _v(url: string, vars: any): string {
    url.split('/').forEach((e) => {
        if (e.startsWith(':')) {
            url = url.replace(e, vars[e.substring(1)]);
        }
    });

    return url;
}


export default axiosInstance;
export const axiosInstanceRoot: AxiosInstance = axios.create({
    baseURL: '/',
    timeout: 100000
});


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

