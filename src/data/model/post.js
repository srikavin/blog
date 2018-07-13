import {Schema} from 'js-data';

export const postSchema = new Schema({
    title: 'Post',
    type: 'object',
    properties: {
        id: {type: 'string'},
        title: {type: 'string'},
        contents: {type: 'string'},
        slug: {type: 'string'},
        overview: {type: 'string'}
    }
});

export const postRelations = {
    belongsTo: {
        user: {
            localField: 'author',
            foreignKey: 'author_id'
        }
    },
    hasMany: {
        tag: {
            localField: 'tags',
            localKeys: 'tagIds'
        }
    }
};