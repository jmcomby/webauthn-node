import * as express from 'express';
import { database } from './db';
import { randomBase64URLBuffer, generateServerMakeCredRequest,
    generateServerGetAssertion, verifyAuthenticatorAttestationResponse,
    verifyAuthenticatorAssertionResponse } from '../utils';
import base64url from "base64url";
import config = require('../config.json');

export class webauthnRoutes {
    public router = express.Router();

    constructor() {
        this.router.post('/register', (request, response) => {
            if (!request.body || !request.body.username || !request.body.name) {
                response.json({
                    'status': 'failed',
                    'message': 'Request missing name or username field!'
                })

                return
            }

            let username = request.body.username;
            let name = request.body.name;

            if (database[username] && database[username].registered) {
                response.json({
                    'status': 'failed',
                    'message': `Username ${username} already exists`
                })

                return
            }

            database[username] = {
                'name': name,
                'registered': false,
                'id': randomBase64URLBuffer(),
                'authenticators': []
            }

            let challengeMakeCred = generateServerMakeCredRequest(username, name, database[username].id)
            challengeMakeCred.status = 'ok'

            if (request && request.session) {
                request.session.challenge = challengeMakeCred.challenge;
                request.session.username = username;
            }

            response.json(challengeMakeCred)
        })

        this.router.post('/login', (request, response) => {
            if (!request.body || !request.body.username) {
                response.json({
                    'status': 'failed',
                    'message': 'Request missing username field!'
                })

                return
            }

            let username = request.body.username;

            if (!database[username] || !database[username].registered) {
                response.json({
                    'status': 'failed',
                    'message': `User ${username} does not exist!`
                })

                return
            }

            let getAssertion = generateServerGetAssertion(database[username].authenticators)
            getAssertion.status = 'ok'

            if (request && request.session) {
                request.session.challenge = getAssertion.challenge;
                request.session.username = username;
            }
            response.json(getAssertion)
        })

        this.router.post('/response', (request, response) => {
            if (!request || !request.session
                || !request.body || !request.body.id
                || !request.body.rawId || !request.body.response
                || !request.body.type || request.body.type !== 'public-key') {
                response.json({
                    'status': 'failed',
                    'message': 'Response missing one or more of id/rawId/response/type fields, or type is not public-key!'
                })

                return
            }

            let webauthnResp = request.body
            let clientData = JSON.parse(base64url.decode(webauthnResp.response.clientDataJSON));

            /* Check challenge... */
            if (clientData.challenge !== request.session.challenge) {
                response.json({
                    'status': 'failed',
                    'message': 'Challenges don\'t match!'
                })
                return;
            }

            /* ...and origin */
            if (clientData.origin !== config.origin) {
                response.json({
                    'status': 'failed',
                    'message': 'Origins don\'t match!'
                })
                return;
            }

            let result;
            if (webauthnResp.response.attestationObject !== undefined) {
                /* This is create cred */
                result = verifyAuthenticatorAttestationResponse(webauthnResp);

                if (result.verified) {
                    database[request.session.username].authenticators.push(result.authrInfo);
                    database[request.session.username].registered = true
                }
            } else if (webauthnResp.response.authenticatorData !== undefined) {
                /* This is get assertion */
                result = verifyAuthenticatorAssertionResponse(webauthnResp, database[request.session.username].authenticators);
            } else {
                response.json({
                    'status': 'failed',
                    'message': 'Can not determine type of response!'
                })
                return;
            }

            if (result.verified) {
                request.session.loggedIn = true;
                response.json({ 'status': 'ok' })
            } else {
                response.json({
                    'status': 'failed',
                    'message': 'Can not authenticate signature!'
                })
            }
        })
    }
}