//@flow
import type {TagSchema} from './tag';
import {TagStore} from './tag';
import type {user} from './user';
import axios, {_v, auth} from './_common';
import {Identifier} from './identifier'


export type PostSchema = {
    title: string;
    author: user;
    contents: string;
    overview: string;
    tags: Array<TagSchema>;
    slug: string;
}

interface PostResource {
    getById(id: Identifier): Promise<PostSchema>;

    getAll(): Promise<Array<PostSchema>>;

    getBySlug(slug: string): Promise<Array<PostSchema>>;

    updatePost(id: Identifier, post: PostSchema): Promise<PostSchema>;
}

function normalizePost(post: PostSchema): Promise<PostSchema> {
    if (post.tags.length !== 0) {
        let newTags = [];
        post.tags.forEach((e, index) => {
            if (typeof e === 'string') {
                newTags.push({index, id: e});
            }
        });

        if (newTags.length !== 0) {
            let tagPromises: Array<Promise<TagSchema>> = [];
            newTags.forEach((e) => {
                tagPromises.push(TagStore.getById(e.id));
            });

            return new Promise((resolve, reject) => {
                Promise.all(tagPromises).then((e: Array<TagSchema>) => {
                    post.tags = e;
                    resolve(post)
                }).catch(e => reject(e));
            });
        }
    }

    return Promise.resolve(post);
}

function normalizePostArray(posts: Array<PostSchema>): Promise<PostSchema[]> {
    let normalized: Array<Promise<PostSchema>> = [];

    posts.forEach(post => {
        normalized.push(normalizePost(post));
    });

    return Promise.all(normalized);
}

let PostFetcher: PostResource = {
    getById(id: Identifier) {
        console.log(id);
        console.log(_v('/posts/:id', {id: id}));
        return axios.get(_v('/posts/:id', {id: id}))
            .then((e) => e.data)
            .then(normalizePost);
    },

    getBySlug(slug: string) {
        return axios.get(`/posts?slug=${slug}`)
            .then(e => e.data)
            .then(normalizePostArray);
    },

    getAll() {
        return axios.get('/posts/')
            .then((e) => e.data)
            .then(normalizePostArray);
    },

    updatePost(id: Identifier, post: PostSchema) {
        auth(axios);
        return axios.put(_v('/posts/:id', {id: id}), post)
            .then((e) => e.data)
            .then(normalizePost);
    }
};

export const PostStore: PostResource = PostFetcher;