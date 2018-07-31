//@flow
import axios, {_v, auth} from './_common';
import {Identifier} from './identifier'
import {MemoryCache} from '../cache';

export type TagSchema = {
    id?: Identifier;
    name: string;
}

interface TagResource {
    getById(id: Identifier): Promise<TagSchema>;

    getAll(): Promise<TagSchema[]>;

    add(tag: TagSchema): Promise<TagSchema>;
}

let TagCache: MemoryCache<Identifier, TagSchema> = new MemoryCache();

let TagFetcher: TagResource = {
    getById(id: Identifier): Promise<TagSchema> {
        let val = TagCache.get(id);
        if (val) {
            return Promise.resolve(val);
        }
        return axios.get(_v('/tags/:id', {id: id}))
            .then((e) => e.data)
            .then((e) => {
                TagCache.set(id, e);
                return e;
            });
    },

    getAll() {
        return axios.get('/tags/')
            .then((e) => e.data);
    },

    add(tag: TagSchema) {
        auth(axios);
        return axios.post('/tags', tag)
            .then((e) => e.data);
    }
};

export const TagStore: TagResource = TagFetcher;