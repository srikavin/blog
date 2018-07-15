//@flow
import axios, {_v} from './_common';
import {Identifier} from './identifier'
import {AxiosResponse} from 'axios';

export type UserSchema = {
    id: Identifier;
    username: string,
    email?: string,
    password?: string,
}

interface UserResource {
    getById(id: Identifier): Promise<AxiosResponse<UserSchema>>;
}

let UserFetcher: UserResource = {
    getById(id: Identifier): Promise<AxiosResponse<UserSchema>> {
        return axios.get(_v('/users/:id', {id: id}));
    }
};

export const UserStore: UserResource = UserFetcher;
