# criipto-verify-express

Accept MitID, NemID, Swedish BankID, Norwegian BankID and more logins in your Node.js app using Passport or plain Express.js

## Installation

Using [npm](https://npmjs.org/)

```sh
npm install @criipto/verify-express
```

## Getting Started

You can find your domain and application client id on the [Criipto Dashboard](https://dashboard.criipto.com/).

If you do not have your client secret stored anywhere, make sure to enable Code Flow and/or regenerate your client secret.

## Single-page application

SPAs can utilize frontend frameworks like [@criipto/auth-js](https://www.npmjs.com/package/@criipto/auth-js) or [@criipto/verify-react](https://www.npmjs.com/package/@criipto/verify-react)
to handle the login in the frontend and then send a Bearer token to their API.

### Passport

```js
// server.js
const express = require('express');
const passport = require('passport');
const CriiptoVerifyJwtPassportStrategy = require('@criipto/verify-express').CriiptoVerifyJwtPassportStrategy;

const app = express();

app.use(passport.initialize());
passport.serializeUser(function(user, done) {
  done(null, user);
});
passport.deserializeUser(function(user, done) {
  done(null, user);
});

passport.use(
  'criiptoVerifyJwt',
  new CriiptoVerifyJwtPassportStrategy({
    domain: "{{YOUR_CRIIPTO_DOMAIN}}",
    clientID: "{{YOUR_CLIENT_ID}}"
  },
  // Map claims to an express user
  async (jwtClaims) => {
    return jwtClaims;
  })
);

app.get('/jwt-protected-route', passport.authenticate('criiptoVerifyJwt', { session: false }), (req, res) => {
  res.json({
    ...req.user,
    passport: 'says hi'
  });
});

// client.js
const {id_token} = login();

fetch(`{server}/jwt-protected-route`, {
  headers: {
    Authorization: `Bearer ${id_token}`
  }
})
```

### Plain express

```js
// server.js

const express = require('express');
const CriiptoVerifyExpressJwt = require('@criipto/verify-express').CriiptoVerifyExpressJwt;
const app = express();

const expressJwt = new CriiptoVerifyExpressJwt({
  domain: "{{YOUR_CRIIPTO_DOMAIN}}",
  clientID: "{{YOUR_CLIENT_ID}}"
});

app.get('/jwt-protected-route', expressJwt.middleware(), (req, res) => {
  res.json({
    ...req.user,
    express: 'says hi'
  });
});

// client.js
const {id_token} = login();

fetch(`{server}/jwt-protected-route`, {
  headers: {
    Authorization: `Bearer ${id_token}`
  }
})
```