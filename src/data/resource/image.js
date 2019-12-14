//@flow
import axios, {_v, axiosInstanceRoot, baseURL} from './_common';
import {Identifier} from './identifier'
import {MemoryCache} from '../cache';
import {auth} from "./auth";

export type ImageSchema = {
    id?: Identifier;
    contents?: string;
    url: string;
    small: string;
    title: string;
    width: number;
    height: number;
}

interface ImageResource {
    getById(id: Identifier): Promise<ImageSchema>;

    resolveFull(image: ImageSchema): Promise<ImageSchema>;

    add(image: ImageSchema): Promise<ImageSchema>;
}

let ImageCache: MemoryCache<Identifier, ImageSchema> = new MemoryCache();

let ImageFetcher: ImageResource = {
    getById(id: Identifier): Promise<ImageSchema> {
        let val = ImageCache.get(id);
        if (val) {
            return Promise.resolve(val);
        }
        return axios.get(_v('/images/:id', {id: id}))
            .then((e) => e.data)
            .then((e: ImageSchema) => {
                e.url = baseURL + e.url;
                return e;
            })
            .then((e) => {
                ImageCache.set(id, e);
                return e;
            });
    },

    resolveFull(image: ImageSchema): Promise<ImageSchema> {
        let val = ImageCache.get(image.id);
        if (val && val.contents) {
            return Promise.resolve(val);
        }
        return axiosInstanceRoot
            .get(image.url, {
                responseType: 'blob'
            })
            .then(e => e.data)
            .then(e => {
                return new Promise(resolve => {
                    let reader = new FileReader();
                    reader.onload = (res) => resolve(res.target.result);
                    reader.readAsDataURL(e);
                })
            })
            .then(e => {
                image.contents = e;
                return image;
            })
            .then((e) => {
                ImageCache.set(e.id, e);
                return e;
            });
    },

    add(image: ImageSchema) {
        auth(axios);
        return axios.post('/images', image)
            .then((e) => e.data);
    }
};

export const ImageStore: ImageResource = ImageFetcher;