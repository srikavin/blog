import {LOGIN} from './actions';
import {combineReducers} from 'redux';


const initialState = {
    auth: {
        loggedIn: false,
    }
};

function login(state = initialState, action) {
    if (state === undefined) {
        return initialState;
    }

    switch (action.type) {
        case LOGIN:

    }
    return state;
}

const auth = combineReducers({});


export default auth;