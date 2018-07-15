//@flow
import axios, {_v} from './_common';
import {Identifier} from './identifier'

export type TagSchema = {
    id: Identifier;
    name: string;
    description: string;
}

interface TagResource {
    getById(id: Identifier): Promise<TagSchema>;

    getAll(): Promise<TagSchema[]>
}


let TagFetcher: TagResource = {
    getById(id: Identifier): Promise<TagSchema> {
        return axios.get(_v('/tags/:id', {id: id}))
            .then((e) => e.data);
    },

    getAll() {
        return axios.get('/tags/')
            .then((e) => e.data);
    }
};

export const TagStore: TagResource = TagFetcher;