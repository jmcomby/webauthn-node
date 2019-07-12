import * as express from 'express';
import { database } from './db';
import { randomBase64URLBuffer } from '../utils';

export class defaultRoutes {
    public router = express.Router();
    // private counter = 0;
    constructor() {
        // this.router.get('/t', (request, response) => {
        //     database[`t${this.counter}`] = {
        //         'name': 'tt',
        //         'registered': false,
        //         'id': randomBase64URLBuffer(),
        //         'authenticators': []
        //     }
        //     this.counter++;
        //     response.send('THX');
        // })

        // this.router.get('/t0', (request, response) => {
        //     database['t0'].id
        //     response.send(database['t0'].id);
        // })
        // this.router.get('/t1', (request, response) => {
        //     database['t1'].id
        //     response.send(database['t1'].id);
        // })

        /* Returns if user is logged in */
        this.router.get('/isLoggedIn', (request, response) => {
            if (request && request.session) {
                if (!request.session.loggedIn) {
                    response.json({
                        'status': 'failed'
                    })
                } else {
                    response.json({
                        'status': 'ok'
                    })
                }
            }
            else {
                response.json({
                    'status': 'failed'
                })
            }
        })

        /* Logs user out */
        this.router.get('/logout', (request, response) => {
            if (request && request.session) {
                request.session.loggedIn = false;
                request.session.username = undefined;

                response.json({
                    'status': 'ok'
                })
            }
            else {
                response.json({
                    'status': 'failed'
                })
            }
        })

        /* Returns personal info and THE SECRET INFORMATION */
        this.router.get('/personalInfo', (request, response) => {
            if (request && request.session) {
                if (!request.session.loggedIn) {
                    response.json({
                        'status': 'failed',
                        'message': 'Access denied'
                    })
                } else {
                    response.json({
                        'status': 'ok',
                        'name': database[request.session.username].name,
                        'theSecret': '<img width="250px" src="img/theworstofthesecrets.jpg">'
                    })
                }
            }
            else {
                response.json({
                    'status': 'failed',
                    'message': 'No request or session'
                })
            }
        })
    }
}
