let backendHost;
const apiVersion = 'v1';

const hostname = window && window.location && window.location.hostname;

if (hostname === 'realsite.com') {
    backendHost = 'https://api.realsite.com';
} else {
    backendHost = 'http://localhost:4000';
}

export const API_ROOT = `${backendHost}/api/${apiVersion}`;