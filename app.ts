import express = require('express');
import bodyParser = require('body-parser');
import cookieSession = require('cookie-session');
import crypto = require('crypto');
import cookieParser = require('cookie-parser');
import path from 'path';

import config = require('./config.json');
import { defaultRoutes } from './routes/default';
import { webauthnRoutes } from './routes/webauthn';

const app: express.Application = express();

app.use(bodyParser.json());

/* ----- session ----- */
app.use(cookieSession({
    name: 'session',
    keys: [crypto.randomBytes(32).toString('hex')],

    // Cookie Options
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
}))
app.use(cookieParser())

app.use(express.static(path.join(__dirname, '../static')));

// Create default routes
let defaultroutes = new defaultRoutes();
// Add default route to express
app.use('/', defaultroutes.router);

// Create route for webautn
let webautnroutes = new webauthnRoutes();
// Add route
app.use('/webauthn', webautnroutes.router);

let port = config.port || 3000;
app.listen(port, function () {
    console.log(`Started app on port ${port}`);
});
