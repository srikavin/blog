import {Schema} from 'js-data';

export const postSchema = new Schema({
    title: 'Post',
    type: 'object',
    properties: {
        _id: {type: 'string'},
        title: {type: 'string'},
        contents: {type: 'string'},
        slug: {type: 'string'},
    }
});

export const postRelations = {
    belongsTo: {
        user: {
            foreignKey: 'user_id',
            localField: 'author'
        }
    }
};