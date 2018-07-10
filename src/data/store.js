import {DataStore} from 'js-data'
import {HttpAdapter} from 'js-data-http'
import {userSchema} from './model/user'
import {tagRelations, tagSchema} from './model/tag';
import {postRelations, postSchema} from './model/post';

export const adapter = new HttpAdapter({
    basePath: 'http://localhost:4000/api/v1',
    useFetch: true
});

export const store = new DataStore();

store.registerAdapter('http', adapter, {default: true});

// The User Resource
store.defineMapper('user', {
    endpoint: 'users',
    schema: userSchema
});

// The Tag Resource
store.defineMapper('tag', {
    endpoint: 'tags',
    schema: tagSchema,
    relations: tagRelations
});


// The Post Resource
store.defineMapper('post', {
    debug: true,
    endpoint: 'posts',
    schema: postSchema,
    relations: postRelations
});
