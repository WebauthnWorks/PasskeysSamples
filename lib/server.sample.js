'use strict';

/* THIS IS A DEMO SAMPLE ONLY INTENDED FOR DEMONSTATION PURPOSES*/
/* DO NOT ATTEMPT USING THIS IN PRODUCTION */
/* FOR PROPER SERVER VERIFICATION VISIT: https://medium.com/@herrjemand/verifying-fido2-responses-4691288c8770 */
/* THIS IS A DEMO SAMPLE ONLY INTENDED FOR DEMONSTATION PURPOSES*/
/* DO NOT ATTEMPT USING THIS IN PRODUCTION */
/* FOR PROPER SERVER VERIFICATION VISIT: https://medium.com/@herrjemand/verifying-fido2-responses-4691288c8770 */
/* THIS IS A DEMO SAMPLE ONLY INTENDED FOR DEMONSTATION PURPOSES*/
/* DO NOT ATTEMPT USING THIS IN PRODUCTION */
/* FOR PROPER SERVER VERIFICATION VISIT: https://medium.com/@herrjemand/verifying-fido2-responses-4691288c8770 */
/* THIS IS A DEMO SAMPLE ONLY INTENDED FOR DEMONSTATION PURPOSES*/
/* DO NOT ATTEMPT USING THIS IN PRODUCTION */
/* FOR PROPER SERVER VERIFICATION VISIT: https://medium.com/@herrjemand/verifying-fido2-responses-4691288c8770 */
/* THIS IS A DEMO SAMPLE ONLY INTENDED FOR DEMONSTATION PURPOSES*/
/* DO NOT ATTEMPT USING THIS IN PRODUCTION */
/* FOR PROPER SERVER VERIFICATION VISIT: https://medium.com/@herrjemand/verifying-fido2-responses-4691288c8770 */
/* THIS IS A DEMO SAMPLE ONLY INTENDED FOR DEMONSTATION PURPOSES*/
/* DO NOT ATTEMPT USING THIS IN PRODUCTION */
/* FOR PROPER SERVER VERIFICATION VISIT: https://medium.com/@herrjemand/verifying-fido2-responses-4691288c8770 */

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

/* Password section */
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
/* Password section ends */

/* RK passwordless section */
    let startPasswordlessEnrollment = (payload) => {
        session = {};
        if(db.userExists(payload.username) && db.getUser(payload.username).registrationComplete)
            return Promise.reject({'status': 'failed', 'errorMessage': 'User already exists!'})

        db.deleteUser(payload.username)

        payload.id = base64url.encode(generateRandomBuffer(32));
        payload.credentials = [];

        db.addUser(payload.username, payload)

        session.username = payload.username;

        return Promise.resolve({'status': 'startFIDOEnrollmentRK'})
    }

    let startAuthenticationPasswordless = (payload) => {
        if(!db.userExists(payload.username))
            return Promise.reject('Wrong username or password!');

        session.username = payload.username;
        session.rk = true;

        return Promise.resolve({'status': 'startFIDOAuthenticationRK'})
    }
/* RK passwordless section ends */

/* MakeCred sections */
    let getMakeCredentialChallenge = (options) => {
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

        if(options) {
            if(options.attestation)
                publicKey.attestation = options.attestation;

            if(options.rpId)
                publicKey.rp.id = options.rpId;
        }

        if(session.rk) {
            if(!publicKey.authenticatorSelection)
                publicKey.authenticatorSelection = {};

            publicKey.authenticatorSelection.requireResidentKey = true;
        }
        
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
/* MakeCred Section Ends */

/* GetAssertion section */
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

        if(session.rk) {
            delete publicKey.allowCredentials
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
/* GetAssertion ends */
