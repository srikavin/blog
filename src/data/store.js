import {DataStore, utils} from 'js-data'
import {HttpAdapter} from 'js-data-http'
import {userSchema} from './model/user'
import {postRelations, postSchema} from './model/post';

export const adapter = new HttpAdapter({
    basePath: 'http://localhost:4000/api/v1',
    debug: true,
    useFetch: true
});

export const store = new DataStore();

store.registerAdapter('http', adapter, {default: true});

// The User Resource
store.defineMapper('user', {
    endpoint: 'users',
    schema: userSchema
});

store.find('user', '5b416147fc0cac3da2474db5').then((user) => {
    console.log(user);
});

// The Post Resource
store.defineMapper('post', {
    endpoint: 'posts',
    schema: postSchema,
    relations: postRelations,
});

store.find('post', '5b416258e445f242f6c3ce28').then((post) => {
    console.log(post);
    store.get('user', post.author._id).then(user => {
        console.log(user);
    })
});

// store.defineMapper('tag', {
//     Our API endpoints use plural form in the path
// endpoint: 'comments',
// schema: tag,
// relations: relations.comment
// })
