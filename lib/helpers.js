'use strict';

var bufferToString = (buff) => {
    var enc = new TextDecoder(); // always utf-8
    return enc.decode(buff)
}

var getEndian = () => {
    let arrayBuffer = new ArrayBuffer(2);
    let uint8Array = new Uint8Array(arrayBuffer);
    let uint16array = new Uint16Array(arrayBuffer);
    uint8Array[0] = 0xAA; // set first byte
    uint8Array[1] = 0xBB; // set second byte

    if(uint16array[0] === 0xBBAA)
        return 'little';
    else
        return 'big';
}

var readBE16 = (buffer) => {
    if(buffer.length !== 2)
        throw new Error('Only 2byte buffer allowed!');

    if(getEndian() !== 'big')
        buffer = buffer.reverse();

    return new Uint16Array(buffer.buffer)[0]
}

var readBE32 = (buffer) => {
    if(buffer.length !== 4)
        throw new Error('Only 4byte buffers allowed!');

    if(getEndian() !== 'big')
        buffer = buffer.reverse();

    return new Uint32Array(buffer.buffer)[0]
}

var bufToHex = (buffer) => { // buffer is an ArrayBuffer
    return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

// https://gist.github.com/herrjemand/dbeb2c2b76362052e5268224660b6fbc
var parseAuthData = (buffer) => {
    let rpIdHash      = buffer.slice(0, 32);            buffer = buffer.slice(32);
    let flagsBuf      = buffer.slice(0, 1);             buffer = buffer.slice(1);
    let flagsInt      = flagsBuf[0];
    let flags = {
        up: !!(flagsInt & 0x01),
        uv: !!(flagsInt & 0x04),
        at: !!(flagsInt & 0x40),
        ed: !!(flagsInt & 0x80),
        flagsInt
    }

    let counterBuf    = buffer.slice(0, 4);             buffer = buffer.slice(4);
    let counter       = readBE32(counterBuf);

    let aaguid        = undefined;
    let credID        = undefined;
    let COSEPublicKey = undefined;

    if(flags.at) {
        aaguid           = buffer.slice(0, 16);          buffer = buffer.slice(16);
        let credIDLenBuf = buffer.slice(0, 2);           buffer = buffer.slice(2);
        let credIDLen    = readBE16(credIDLenBuf);
        credID           = buffer.slice(0, credIDLen);   buffer = buffer.slice(credIDLen);
        COSEPublicKey    = buffer;
    }

    return {rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, COSEPublicKey}
}

var generateRandomBuffer = (length) => {
    if(!length)
        length = 32;

    var randomBuff = new Uint8Array(length);
    window.crypto.getRandomValues(randomBuff);
    return randomBuff
}

var publicKeyCredentialToJSON = (pubKeyCred) => {
    if(pubKeyCred instanceof Array) {
        let arr = [];
        for(let i of pubKeyCred)
            arr.push(publicKeyCredentialToJSON(i));

        return arr
    }

    if(pubKeyCred instanceof ArrayBuffer) {
        return base64url.encode(pubKeyCred)
    }

    if(pubKeyCred instanceof Object) {
        let obj = {};

        for (let key in pubKeyCred) {
            obj[key] = publicKeyCredentialToJSON(pubKeyCred[key])
        }

        return obj
    }

    return pubKeyCred
}

var preformatMakeCredReq = (makeCredReq) => {
    makeCredReq.challenge = base64url.decode(makeCredReq.challenge);
    makeCredReq.user.id   = base64url.decode(makeCredReq.user.id);

    return makeCredReq
}

var preformatGetAssertReq = (getAssert) => {
    getAssert.challenge = base64url.decode(getAssert.challenge);
    
    if(getAssert.allowCredentials) {
        for(let allowCred of getAssert.allowCredentials) {
            allowCred.id = base64url.decode(allowCred.id);
        }
    }

    return getAssert
}
 

/* ----- Core Testers ----- */
var challenge = new Uint8Array(32);
window.crypto.getRandomValues(challenge);

var userID = new Uint8Array(32);
window.crypto.getRandomValues(userID);


var credID = new Uint8Array(32);
window.crypto.getRandomValues(credID);

var generateMakeCredParams = () => {
    return {
        'challenge': challenge,

        'rp': {
            'name': 'Example Inc.'
        },

        'user': {
            'id': userID,
            'name': 'alice@example.com',
            'displayName': 'Alice von Wunderland'
        },

        'pubKeyCredParams': [
            { 'type': 'public-key', 'alg': -7  },
            { 'type': 'public-key', 'alg': -257 }
        ],
    }
}

var executeMakeCredential = (publicKey, skipAlert) => {
    return navigator.credentials.create({ 'publicKey': publicKey })
    .then((newCredentialInfo) => {
        if(!skipAlert) {
            alert('Open your browser console!');
        }

        console.log('SUCCESS', newCredentialInfo)
        console.log('ClientDataJSON: ', bufferToString(newCredentialInfo.response.clientDataJSON))
        let attestationObject = CBOR.decode(newCredentialInfo.response.attestationObject);
        console.log('AttestationObject: ', attestationObject)
        let authData = parseAuthData(attestationObject.authData);
        console.log('AuthData: ', authData);
        console.log('CredID: ', bufToHex(authData.credID));
        console.log('AAGUID: ', bufToHex(authData.aaguid));
        console.log('PublicKey', CBOR.decode(authData.COSEPublicKey.buffer));

        return authData.credID
    })
    .catch((error) => {
        alert('Open your browser console!')
        console.log('FAIL', error)
    })
}

var generateGetAssertion = () => {
    return {
        'challenge': challenge,
    }
}

var executeGetAssertion = async (publicKey, skipAlert, enforceConditionalUi) => {
    var conditionalUiMediation = undefined;
    if(enforceConditionalUi) {
        conditionalUiMediation = 'conditional';
    }

    var abortController = new AbortController();
    var abortSignal = abortController.signal;
  
    try {
        await navigator.credentials.get({
            'signal': abortSignal,
            'mediation': conditionalUiMediation,
            'publicKey': publicKey
        });

        if (!skipAlert) {
            alert('SUCCESSFULLY GOT AN ASSERTION! Open your browser console!');
        }
        console.log('\n\n\nSUCCESSFULLY GOT AN ASSERTION!', getAssertionResponse);
    } catch (error) {
        alert('Open your browser console!');
        console.log('FAIL', error);
    }
}
