import {Schema} from 'js-data';

export const userSchema = new Schema({
    title: 'User',
    type: 'object',
    properties: {
        id: {type: 'string'},
        username: {type: 'string'},
        email: {type: 'string'},
    }
});

