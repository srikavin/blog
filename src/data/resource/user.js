//@flow
import axios, {_v} from './_common';
import {Identifier} from './identifier'
import {AxiosResponse} from 'axios';

export type user = {
    username: string,
    email?: string,
    password?: string,
}

function getUserByID(id: Identifier): Promise<AxiosResponse<user>> {
    return axios.get(_v('/user/:id', {id: id}));
}
