//@flow
import type {TagSchema} from './tag';
import {TagStore} from './tag';
import type {UserSchema} from './user';
import {UserStore} from './user';
import axios, {_v, auth} from './_common';
import {Identifier} from './identifier'


export type PostSchema = {
    id: Identifier;
    title: string;
    author: UserSchema;
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
    let tagPromise: Promise<Array<any>> = Promise.resolve([]);
    if (post.tags.length !== 0) {
        let newTags = [];
        post.tags.forEach((e, index) => {
            if (typeof e === 'string') {
                newTags.push({index, id: e});
            }
        });

        if (newTags.length !== 0) {
            let tagPromises = [];
            newTags.forEach((e) => {
                tagPromises.push(TagStore.getById(e.id).then(val => {
                    return {index: e.index, value: val};
                }));
            });

            tagPromise = Promise.all(tagPromises);
        }
    }

    let authorPromise = Promise.resolve(post.author);
    if (typeof post.author === 'string') {
        authorPromise = UserStore.getById(post.author);
    }

    return Promise.all([tagPromise, authorPromise]).then(([tags, author]) => {
        tags.forEach(({index, value}) => {
            post.tags[index] = value;
        });
        post.author = author;
        return post;
    });
}

function normalizePostArray(posts: Array<PostSchema>): Promise<PostSchema[]> {
    let normalized: Array<Promise<PostSchema>> = [];

    posts.forEach(post => {
        normalized.push(normalizePost(post));
    });

    return Promise.all(normalized);
}

function restorePost(post: PostSchema) {
    let tagObjs = post.tags;
    post.tags = [];
    delete post.author;
    tagObjs.forEach((e) => post.tags.push(e.id));
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
    },
    createPost(post: PostSchema) {
        restorePost(post);
        auth(axios);
        return axios.post('/posts', post)
            .then((e) => e.data)
            .then(normalizePost);
    }
};

export const PostStore: PostResource = PostFetcher;