'use strict';

/* THIS IS A DEMO SAMPLE */
/* DO NOT ATTEMPT USING THIS IN PRODUCTION */
/* THIS IS A DEMO SAMPLE */
/* DO NOT ATTEMPT USING THIS IN PRODUCTION */
/* THIS IS A DEMO SAMPLE */
/* DO NOT ATTEMPT USING THIS IN PRODUCTION */
/* THIS IS A DEMO SAMPLE */
/* DO NOT ATTEMPT USING THIS IN PRODUCTION */
/* THIS IS A DEMO SAMPLE */
/* DO NOT ATTEMPT USING THIS IN PRODUCTION */
/* THIS IS A DEMO SAMPLE */
/* DO NOT ATTEMPT USING THIS IN PRODUCTION */

let db = {
    'addUser': (username, struct) => {
        localStorage.setItem(username, JSON.stringify(struct))
    },
    'getUser': (username) => {
        let userJSON = localStorage.getItem(username);
        if(!userJSON)
            throw new Error(`Username "${username}" does not exist!`);

        return JSON.parse(userJSON)
    }, 
    'userExists': (username) => {
        let userJSON = localStorage.getItem(username);
        if(!userJSON)
            return false

        return true
    }, 
    'updateUser': (username, struct) => {
        let userJSON = localStorage.getItem(username);
        if(!userJSON)
            throw new Error(`Username "${username}" does not exist!`);

        localStorage.setItem(username, JSON.stringify(struct))
    },
    'deleteUser': (username) => {
        localStorage.removeItem(username)
    }
}

let session = {};

let registerPassword = (payload) => {
    session = {};
    if(db.userExists(payload.username) && db.getUser(payload.username).registrationComplete)
        return Promise.reject({'status': 'failed', 'errorMessage': 'User already exists!'})

    db.deleteUser(payload.username)

    payload.id = base64url.encode(generateRandomBuffer(32));
    payload.credentials = [];

    db.addUser(payload.username, payload)

    session.username = payload.username;

    return Promise.resolve({'status': 'startFIDOEnrollment'})
}

let loginPassword = (payload) => {
    if(!db.userExists(payload.username))
        return Promise.reject('Wrong username or password!');

    let user = db.getUser(payload.username);
    if(user.password !== payload.password)
        return Promise.reject('Wrong username or password!');

    session.username = payload.username;

    return Promise.resolve({'status': 'startFIDOAuthentication'})
}

let getMakeCredentialChallenge = (attestation) => {
    if(!session.username)
        return Promise.reject({'status': 'failed', 'errorMessage': 'Access denied!'})

    let user = db.getUser(session.username);
    session.challenge = base64url.encode(generateRandomBuffer(32));

    var publicKey = {
        'challenge': session.challenge,

        'rp': {
            'name': 'Example Inc.'
        },

        'user': {
            'id': user.id,
            'name': user.username,
            'displayName': user.displayName
        },

        'pubKeyCredParams': [
            { 'type': 'public-key', 'alg': -7  },
            { 'type': 'public-key', 'alg': -257 }
        ],

        'status': 'ok'
    }

    if(attestation)
        publicKey.attestation = attestation;

    return Promise.resolve(publicKey)
}

let makeCredentialResponse = (payload) => {
    if(!session.username)
        return Promise.reject({'status': 'failed', 'errorMessage': 'Access denied!'})

    let user = db.getUser(session.username);
    
    /* server processing and verifying response, blah blah blah */
    user.registrationComplete = true;
    user.credentials.push(payload.id);

    db.updateUser(session.username, user);

    session = {};

    return Promise.resolve({'status': 'ok'})
}

let getGetAssertionChallenge = () => {
    if(!session.username)
        return Promise.reject({'status': 'failed', 'errorMessage': 'Access denied!'})

    let user = db.getUser(session.username);
    session.challenge = base64url.encode(generateRandomBuffer(32));

    var publicKey = {
        'challenge': session.challenge,

        'allowCredentials': user.credentials.map((credId) => {
            return { 'type': 'public-key', 'id': credId }
        }),

        'status': 'ok'
    }

    return Promise.resolve(publicKey)
}

let getAssertionResponse = (payload) => {
    if(!session.username)
        return Promise.reject({'status': 'failed', 'errorMessage': 'Access denied!'})
    
    /* server processing and verifying response, blah blah blah */

    session = {};

    return Promise.resolve({'status': 'ok'})
}