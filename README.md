# Webauthn demo server node typescript

Webauthn demo server in typescript based on the [FIDO Alliance javascript demo](https://github.com/fido-alliance/webauthn-demo)

## Installing / Getting started

You can quickly start the server by running
```shell
npm install
npm run tsc
node build/app.js
```

### Initial Configuration

The adresse of the server and port are located in the config.json. Keep in mind that webauthn works only with https except for localhost!

## Developing

If you are using Docker & Visual Studio Code (with the extension Remote - Container, ext install ms-vscode-remote.remote-containers), open the project inside the container. Everything is ready for debugging inside the container.

```shell
git clone https://github.com/jmcomby/webauthn-node.git
cd webauthn-node/
```

Open with your favorite editor.

### Building

Build the typescript into javascript
```shell
npm run tsc
```

This command will create a "build" directory in the root of your project.

### Deploying

Now you can start the server node
```shell
node build/app.js
```
By default, the server will serve the static small website (static folder) and be ready to authentify using WebAuthn.
Navigate to `http://localhost:3001`

## Features

* Minimal server for Web Authentication using node & typescript.
* Safari Mac OS Touch ID supported
* Android Chrome Fingerprint supported

## Contributing

If you'd like to contribute, please fork the repository and use a feature branch. Pull requests are warmly welcome.

## Links

- Project homepage: https://github.com/jmcomby/webauthn-node
- Guide Webauthn: https://webauthn.guide/
- FIDO Alliance WebAuthn demo javascript: https://github.com/fido-alliance/webauthn-demo
- WebAuthn Packed attestation: https://medium.com/@herrjemand/verifying-fido2-packed-attestation-a067a9b2facd
- WebAuthn SafetyNet attestation: https://medium.com/@herrjemand/verifying-fido2-safetynet-attestation-bd261ce1978d
- Types webauthn: https://github.com/DefinitelyTyped/DefinitelyTyped/blob/master/types/webappsec-credential-management/index.d.ts

## Licensing

The code in this project is licensed under MIT license.