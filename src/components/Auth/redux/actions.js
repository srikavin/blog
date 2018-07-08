const LOGIN = 'LOGIN';
const REGISTER = 'REGISTER';

export {LOGIN, REGISTER};

export function login(email, password) {
    return {
        type: LOGIN,
        email,
        password
    }
}

export function register(username, email, password) {
    return {
        type: REGISTER,
        username,
        email,
        password
    }
}