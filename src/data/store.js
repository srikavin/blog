import {DataStore} from 'js-data'
import {HttpAdapter} from 'js-data-http'
import {userSchema} from './model/user'
import {tagRelations, tagSchema} from './model/tag';
import {postRelations, postSchema} from './model/post';
import auth from '../util/AuthController';

export const adapter = new HttpAdapter({
    basePath: 'http://localhost:4000/api/v1',
    beforeHTTP(config, opts) {
        config.headers || (config.headers = {});
        config.headers['x-access-token'] = auth.getToken();
        return HttpAdapter.prototype.beforeHTTP.call(this, config, opts);
    }
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
