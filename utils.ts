import crypto = require('crypto');
import base64url from "base64url";
import cbor from 'cbor';
import elliptic from 'elliptic';
import NodeRSA from 'node-rsa';
import { authenticatorInfo } from './routes/db';
import { Certificate } from '@fidm/x509';


/**
 * @see {@link https://w3c.github.io/webauthn/#dictdef-publickeycredentialrpentity}
 */
interface PublicKeyCredentialRpEntity {
    id: string;
    name: string;
}

/**
 * @see {@link https://w3c.github.io/webauthn/#dictdef-publickeycredentialuserentity}
 */
interface PublicKeyCredentialUserEntity {
    id: string;
    name: string;
    displayName: string;
}

/**
 * @see {@link https://w3c.github.io/webauthn/#enumdef-publickeycredentialtype}
 */
type PublicKeyCredentialType = "public-key";

/**
 * @see {@link https://w3c.github.io/webauthn/#dictdef-publickeycredentialparameters}
 */
interface PublicKeyCredentialParameters {
    type: PublicKeyCredentialType;
    alg: number;
}

/**
 * @see {@link https://w3c.github.io/webauthn/#enum-attestation-convey}
 */
type AttestationConveyancePreference = "none" | "indirect" | "direct";

/**
 * @see {@link https://w3c.github.io/webauthn/#enum-transport}
 */
type AuthenticatorTransport = "usb" | "nfc" | "ble" | "internal";

/**
 * @see {@link https://w3c.github.io/webauthn/#dictdef-publickeycredentialdescriptor}
 */
interface PublicKeyCredentialDescriptor {
    type: PublicKeyCredentialType;
    id: string;
    transports?: AuthenticatorTransport[];
}

/**
 * @see {@link https://w3c.github.io/webauthn/#enumdef-userverificationrequirement}
 */
type UserVerificationRequirement = "required" | "preferred" | "discouraged";

/**
 * @see {@link https://w3c.github.io/webauthn/#dictdef-publickeycredentialrequestoptions}
 */
interface PublicKeyCredentialRequestOptions {
    challenge: string;
    timeout?: number;
    rpId?: string;
    allowCredentials?: PublicKeyCredentialDescriptor[];
    userVerification?: UserVerificationRequirement;
    extensions?: any;
}

/**
 * U2F Presence constant
 */
let U2F_USER_PRESENTED = 0x01;

export interface PKCRequestOptions extends PublicKeyCredentialRequestOptions {
    status?: string;
}

export interface MakePublicKeyCredentialOptions {
    challenge: string;
    rp: PublicKeyCredentialRpEntity;
    user: PublicKeyCredentialUserEntity;
    attestation?: AttestationConveyancePreference;
    pubKeyCredParams: Array<PublicKeyCredentialParameters>;
    status?: string;
}

/**
 * Returns base64url encoded buffer of the given length
 * @param  {Number} len - length of the buffer
 * @return {String}     - base64url random buffer
 */
export function randomBase64URLBuffer(len?: number) {
    len = len || 32;

    let buff = crypto.randomBytes(len);

    return base64url(buff);
}

/**
 * Generates makeCredentials request
 * @param  {String} username       - username
 * @param  {String} displayName    - user's personal display name
 * @param  {String} id             - user's base64url encoded id
 * @return {MakePublicKeyCredentialOptions} - server encoded make credentials request
 */
export function generateServerMakeCredRequest(username: string, displayName: string, id: string) {
    const options = <MakePublicKeyCredentialOptions>{
        challenge: randomBase64URLBuffer(32),

        rp: {
            name: "ACME Corporation"
        },

        user: {
            id: id,
            name: username,
            displayName: displayName
        },

        attestation: 'direct',

        pubKeyCredParams: [
            {
                type: "public-key", alg: -7 // "ES256" IANA COSE Algorithms registry
            }
        ]
    }
    return options;
}

/**
 * Generates new credential option for a user
 * @param  {Array<authenticatorInfo>} authenticators - list of authenticators
 * @return {PKCRequestOptions}                       - server encoded make credentials request
 */
export function generateServerGetAssertion(authenticators: Array<authenticatorInfo>) {
    let allowCredentials = new Array<PublicKeyCredentialDescriptor>();
    for (let authr of authenticators) {
        allowCredentials.push({
            type: 'public-key',
            id: authr.credID,
            transports: ['usb', 'nfc', 'ble', 'internal']
        })
    }
    const options = <PKCRequestOptions>{
        challenge: randomBase64URLBuffer(32),
        allowCredentials: allowCredentials
    }
    return options;
}

/**
 * Parses authenticatorData buffer.
 * @param  {Buffer} buffer - authenticatorData buffer
 * @return {Object}        - parsed authenticatorData struct
 */
function parseMakeCredAuthData(buffer: Buffer) {
    let rpIdHash = buffer.slice(0, 32); buffer = buffer.slice(32);
    let flagsBuf = buffer.slice(0, 1); buffer = buffer.slice(1);
    let flags = flagsBuf[0];
    let counterBuf = buffer.slice(0, 4); buffer = buffer.slice(4);
    let counter = counterBuf.readUInt32BE(0);
    let aaguid = buffer.slice(0, 16); buffer = buffer.slice(16);
    let credIDLenBuf = buffer.slice(0, 2); buffer = buffer.slice(2);
    let credIDLen = credIDLenBuf.readUInt16BE(0);
    let credID = buffer.slice(0, credIDLen); buffer = buffer.slice(credIDLen);
    let COSEPublicKey = buffer;

    return { rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, COSEPublicKey }
}

/**
 * Returns Algo digest of the given data.
 * @param  {string} alg     - Algo for hash
 * @param  {Buffer} message - data to hash
 * @return {Buffer}         - the hash
 */
function hash(alg: string, message: Buffer) {
    return crypto.createHash(alg).update(message).digest();
}

/**
 * Returns SHA-256 digest of the given data.
 * @param  {Buffer} data - data to hash
 * @return {Buffer}      - the hash
 */
function hash256(data: Buffer) {
    return crypto.createHash('SHA256').update(data).digest();
}

/**
 * Takes COSE encoded public key and converts it to RAW PKCS ECDHA key
 * @param  {Buffer} COSEPublicKey - COSE encoded public key
 * @return {Buffer}               - RAW PKCS encoded public key
 */
function COSEECDHAtoPKCS(COSEPublicKey: Buffer) {
    /* 
       +------+-------+-------+---------+----------------------------------+
       | name | key   | label | type    | description                      |
       |      | type  |       |         |                                  |
       +------+-------+-------+---------+----------------------------------+
       | crv  | 2     | -1    | int /   | EC Curve identifier - Taken from |
       |      |       |       | tstr    | the COSE Curves registry         |
       |      |       |       |         |                                  |
       | x    | 2     | -2    | bstr    | X Coordinate                     |
       |      |       |       |         |                                  |
       | y    | 2     | -3    | bstr /  | Y Coordinate                     |
       |      |       |       | bool    |                                  |
       |      |       |       |         |                                  |
       | d    | 2     | -4    | bstr    | Private key                      |
       +------+-------+-------+---------+----------------------------------+
    */

    let coseStruct = cbor.decodeAllSync(COSEPublicKey)[0];
    let tag = Buffer.from([0x04]);
    let x = coseStruct.get(-2);
    let y = coseStruct.get(-3);

    return Buffer.concat([tag, x, y])
}

/**
 * Convert binary certificate or public key to an OpenSSL-compatible PEM text format.
 * @param  {Buffer} buffer - Cert or PubKey buffer
 * @return {String}             - PEM
 */
function ASN1toPEM(pkBuffer: Buffer) {
    if (!Buffer.isBuffer(pkBuffer))
        throw new Error("ASN1toPEM: pkBuffer must be Buffer.")

    let type;
    if (pkBuffer.length == 65 && pkBuffer[0] == 0x04) {
        /*
            If needed, we encode rawpublic key to ASN structure, adding metadata:
            SEQUENCE {
              SEQUENCE {
                 OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
                 OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
              }
              BITSTRING <raw public key>
            }
            Luckily, to do that, we just need to prefix it with constant 26 bytes (metadata is constant).
        */

        pkBuffer = Buffer.concat([
            Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex"),
            pkBuffer
        ]);

        type = 'PUBLIC KEY';
    } else {
        type = 'CERTIFICATE';
    }

    let b64cert = pkBuffer.toString('base64');

    let PEMKey = '';
    for (let i = 0; i < Math.ceil(b64cert.length / 64); i++) {
        let start = 64 * i;

        PEMKey += b64cert.substr(start, 64) + '\n';
    }

    PEMKey = `-----BEGIN ${type}-----\n` + PEMKey + `-----END ${type}-----\n`;

    return PEMKey
}

/**
 * Takes signature, data and PEM public key and tries to verify signature
 * @param  {Buffer} signature
 * @param  {Buffer} data
 * @param  {String} publicKey - PEM encoded public key
 * @return {Boolean}
 */
function verifySignature(signature: Buffer, data: Buffer, publicKey: string) {
    return crypto.createVerify('SHA256')
        .update(data)
        .verify(publicKey, signature);
}

interface verifyAuthAttestation {
    verified: boolean;
    authrInfo: authenticatorInfo;
}

let COSEKEYS = {
    'kty': 1,
    'alg': 3,
    'crv': -1,
    'x': -2,
    'y': -3,
    'n': -1,
    'e': -2
}

let COSEKTY = {
    'OKP': 1,
    'EC2': 2,
    'RSA': 3
}

let COSEALGHASH: { [id: string]: string } = {
    '-257': 'sha256',
    '-258': 'sha384',
    '-259': 'sha512',
    '-65535': 'sha1',
    '-39': 'sha512',
    '-38': 'sha384',
    '-37': 'sha256',
    '-260': 'sha256',
    '-261': 'sha512',
    '-7': 'sha256',
    '-36': 'sha384'
}

let COSERSASCHEME: { [id: string]: string } = {
    '-3': 'pss-sha256',
    '-39': 'pss-sha512',
    '-38': 'pss-sha384',
    '-65535': 'pkcs1-sha1',
    '-257': 'pkcs1-sha256',
    '-258': 'pkcs1-sha384',
    '-259': 'pkcs1-sha512'
}

let COSECRV: { [id: string]: string } = {
    '1': 'p256',
    '2': 'p384',
    '3': 'p521'
}

function getCertificateCommonName(certificate: string) {
    let issuer = Certificate.fromPEM(Buffer.from(certificate, 'utf8'));

    return issuer.subject.commonName
}

function validateCertificatePath(certificates: string[]) {
    if ((new Set(certificates)).size !== certificates.length)
        throw new Error('Failed to validate certificates path! Duplicate certificates detected!');

    for (let i = 0; i < certificates.length; i++) {
        let subjectPem = certificates[i];
        let subjectCert = Certificate.fromPEM(Buffer.from(subjectPem, 'utf8'));

        let issuerPem = '';
        if (i + 1 >= certificates.length)
            break;
        else
            issuerPem = certificates[i + 1];

        let issuerCert = Certificate.fromPEM(Buffer.from(issuerPem, 'utf8'));

        if (!subjectCert.isIssuer(issuerCert)) {
            console.log('Check cert if from issuer failed');
            return false;
        }
        if (!issuerCert.verifySubjectKeyIdentifier()) {
            console.log('Check issuer SubjectKeyIdentifier failed');
            return false;
        }
        if (!subjectCert.verifySubjectKeyIdentifier()) {
            console.log('Check cert SubjectKeyIdentifier failed');
            return false;
        }
        let error = issuerCert.checkSignature(subjectCert);
        if (error !== null) {
            console.log('Check Signature failed');
            console.log(error);
            return false;
        }
    }

    return true
}

export function verifyAuthenticatorAttestationResponse(webAuthnResponse: any) {
    let attestationBuffer = base64url.toBuffer(webAuthnResponse.response.attestationObject);
    let ctapMakeCredResp = cbor.decodeAllSync(attestationBuffer)[0];
    let authrDataStruct = parseMakeCredAuthData(ctapMakeCredResp.authData);

    let response = <verifyAuthAttestation>{
        'verified': false
    };
    console.log(ctapMakeCredResp.fmt);
    if (ctapMakeCredResp.fmt === 'fido-u2f') {
        if (!(authrDataStruct.flags & U2F_USER_PRESENTED))
            throw new Error('User was NOT presented durring authentication!');

        let clientDataHash = hash256(base64url.toBuffer(webAuthnResponse.response.clientDataJSON))
        let reservedByte = Buffer.from([0x00]);
        let publicKey = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey)
        let signatureBase = Buffer.concat([reservedByte, authrDataStruct.rpIdHash, clientDataHash, authrDataStruct.credID, publicKey]);

        let PEMCertificate = ASN1toPEM(ctapMakeCredResp.attStmt.x5c[0]);
        let signature = ctapMakeCredResp.attStmt.sig;

        response.verified = verifySignature(signature, signatureBase, PEMCertificate);

        if (response.verified) {
            response.authrInfo = {
                fmt: 'fido-u2f',
                publicKey: base64url.encode(publicKey),
                counter: authrDataStruct.counter,
                credID: base64url.encode(authrDataStruct.credID)
            }
        }
    }
    else if (ctapMakeCredResp.fmt === 'packed') {
        if (!(authrDataStruct.flags & U2F_USER_PRESENTED))
            throw new Error('User was NOT presented durring authentication!');

        let clientDataHash = hash256(base64url.toBuffer(webAuthnResponse.response.clientDataJSON))
        let reservedByte = Buffer.from([0x00]);
        let publicKey = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey)
        let signatureBase = Buffer.concat([reservedByte, authrDataStruct.rpIdHash, clientDataHash, authrDataStruct.credID, publicKey]);


        // Verify signature attestation
        if (ctapMakeCredResp.attStmt.x5c) {
            console.log('Check signature');
            let PEMCertificate = ASN1toPEM(ctapMakeCredResp.attStmt.x5c[0]);
            let signature = ctapMakeCredResp.attStmt.sig;

            response.verified = verifySignature(signature, signatureBase, PEMCertificate);
        }
        else {
            // Verify SURROGATE attestation
            let pubKeyCose = cbor.decodeAllSync(authrDataStruct.COSEPublicKey)[0];
            let hashAlg = COSEALGHASH[pubKeyCose.get(COSEKEYS.alg)];
            let signatureBaseBuffer = Buffer.concat([ctapMakeCredResp.authData, clientDataHash]);
            let signatureBuffer = ctapMakeCredResp.attStmt.sig;
            if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.EC2) {
                let x = pubKeyCose.get(COSEKEYS.x);
                let y = pubKeyCose.get(COSEKEYS.y);

                let ansiKey = Buffer.concat([Buffer.from([0x04]), x, y]);

                let signatureBaseHash = hash(hashAlg, signatureBaseBuffer);

                let ec = new elliptic.ec(COSECRV[pubKeyCose.get(COSEKEYS.crv)]);
                let key = ec.keyFromPublic(ansiKey);

                response.verified = key.verify(signatureBaseHash, signatureBuffer);
            } else if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.RSA) {
                //let signingScheme = COSERSASCHEME[pubKeyCose.get(COSEKEYS.alg)];

                let key = new NodeRSA(undefined);
                key.importKey({
                    n: pubKeyCose.get(COSEKEYS.n),
                    e: 65537,
                }, 'components-public');

                response.verified = key.verify(signatureBaseBuffer, signatureBuffer)
            } else if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.OKP) {
                let x = pubKeyCose.get(COSEKEYS.x);
                let signatureBaseHash = hash(hashAlg, signatureBaseBuffer);

                let key = new elliptic.eddsa('ed25519');

                response.verified = key.verify(signatureBaseHash, signatureBuffer, x);
            }
        }
        if (response.verified) {
            response.authrInfo = {
                fmt: 'packed',
                publicKey: base64url.encode(publicKey),
                counter: authrDataStruct.counter,
                credID: base64url.encode(authrDataStruct.credID)
            }
        }
    }
    else if (ctapMakeCredResp.fmt === 'android-safetynet') {
        let jwsString = ctapMakeCredResp.attStmt.response.toString('utf8');
        let jwsParts = jwsString.split('.');
        let publicKey = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey);

        let HEADER = JSON.parse(base64url.decode(jwsParts[0]));
        let PAYLOAD = JSON.parse(base64url.decode(jwsParts[1]));
        let SIGNATURE = jwsParts[2];

        /* ----- Verify payload ----- */
        let clientDataHashBuf = hash('sha256', base64url.toBuffer(webAuthnResponse.response.clientDataJSON));
        let nonceBase = Buffer.concat([ctapMakeCredResp.authData, clientDataHashBuf]);
        let nonceBuffer = hash('sha256', nonceBase);
        let expectedNonce = nonceBuffer.toString('base64');

        if (PAYLOAD.nonce !== expectedNonce)
            throw new Error(`PAYLOAD.nonce does not contains expected nonce! Expected ${PAYLOAD.nonce} to equal ${expectedNonce}!`);

        if (!PAYLOAD.ctsProfileMatch)
            throw new Error('PAYLOAD.ctsProfileMatch is FALSE!');
        /* ----- Verify payload ENDS ----- */

        /* ----- Verify header ----- */
        let certPath = HEADER.x5c.map((cert: any) => {
            let pemcert = '';
            for (let i = 0; i < cert.length; i += 64)
                pemcert += cert.slice(i, i + 64) + '\n';

            return '-----BEGIN CERTIFICATE-----\n' + pemcert + '-----END CERTIFICATE-----';
        })
        if (getCertificateCommonName(certPath[0]) !== 'attest.android.com')
            throw new Error('The common name is not set to "attest.android.com"!');

        if (!validateCertificatePath(certPath))
            throw new Error('Could not validate the certificate');
        /* ----- Verify header ENDS ----- */

        /* ----- Verify signature ----- */
        let signatureBaseBuffer = Buffer.from(jwsParts[0] + '.' + jwsParts[1]);
        let certificate = certPath[0];
        let signatureBuffer = base64url.toBuffer(SIGNATURE);

        let signatureIsValid = crypto.createVerify('sha256')
            .update(signatureBaseBuffer)
            .verify(certificate, signatureBuffer);

        if (!signatureIsValid)
            throw new Error('Failed to verify the signature!');

        /* ----- Verify signature ENDS ----- */

        response.verified = true;
        response.authrInfo = {
            fmt: 'android-safetynet',
            publicKey: base64url.encode(publicKey),
            counter: authrDataStruct.counter,
            credID: base64url.encode(authrDataStruct.credID)
        }
    }

    return response
}

/**
 * Takes an array of registered authenticators and find one specified by credID
 * @param  {String} credID        - base64url encoded credential
 * @param  {Array<authenticatorInfo>} authenticators - list of authenticators
 * @return {authenticatorInfo}               - found authenticator
 */
function findAuthr(credID: string, authenticators: Array<authenticatorInfo>) {
    for (let authr of authenticators) {
        if (authr.credID === credID)
            return authr
    }

    throw new Error(`Unknown authenticator with credID ${credID}!`)
}

/**
 * Parses AuthenticatorData from GetAssertion response
 * @param  {Buffer} buffer - Auth data buffer
 * @return {Object}        - parsed authenticatorData struct
 */
function parseGetAssertAuthData(buffer: Buffer) {
    let rpIdHash = buffer.slice(0, 32); buffer = buffer.slice(32);
    let flagsBuf = buffer.slice(0, 1); buffer = buffer.slice(1);
    let flags = flagsBuf[0];
    let counterBuf = buffer.slice(0, 4); buffer = buffer.slice(4);
    let counter = counterBuf.readUInt32BE(0);

    return { rpIdHash, flagsBuf, flags, counter, counterBuf }
}

interface verifyAuthAssertion {
    verified: boolean;
    counter: number;
}

export function verifyAuthenticatorAssertionResponse(webAuthnResponse: any, authenticators: Array<authenticatorInfo>) {
    let authr = findAuthr(webAuthnResponse.id, authenticators);
    let authenticatorData = base64url.toBuffer(webAuthnResponse.response.authenticatorData);
    let authrDataStruct = parseGetAssertAuthData(authenticatorData);

    let response = <verifyAuthAssertion>{ 'verified': false };
    if (!(authrDataStruct.flags & U2F_USER_PRESENTED))
        throw new Error('User was NOT presented durring authentication!');

    let clientDataHash = hash256(base64url.toBuffer(webAuthnResponse.response.clientDataJSON))
    let signatureBase = Buffer.concat([authrDataStruct.rpIdHash, authrDataStruct.flagsBuf, authrDataStruct.counterBuf, clientDataHash]);

    let publicKey = ASN1toPEM(base64url.toBuffer(authr.publicKey));
    let signature = base64url.toBuffer(webAuthnResponse.response.signature);

    response.verified = verifySignature(signature, signatureBase, publicKey)

    if (response.verified) {
        if (response.counter <= authr.counter)
            throw new Error('Authr counter did not increase!');

        authr.counter = authrDataStruct.counter
    }

    return response
}