import {Schema} from 'js-data';

export const tagSchema = new Schema({
    title: 'Tag',
    type: 'object',
    properties: {
        id: {type: 'string'},
        name: {type: 'string'},
        description: {type: 'string'}
    }
});

export const tagRelations = {
    belongsTo: {
        post: {
            localField: 'id',
            foreignKey: 'tags'
        }
    }
};