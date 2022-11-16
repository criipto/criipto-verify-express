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

Below you will find examples for both Single-page application and Web-application use cases. You can also [download a full sample from GitHub](https://github.com/criipto/criipto-verify-express/blob/master/example)

### Debugging

`DEBUG=@criipto/verify-express*`

## Web-application with sessions and redirect.

Sessions must be setup when using redirect based authentication.

You must also register a Callback URL on your Criipto Application matching the URL of your redirect handling route.

```js
// server.js

const express = require('express');
const expressSesssion = require('express-session');
const app = express();

app.use(
  expressSesssion({
    secret: '{{YOUR_SESSION_SECRET}}',
    resave: false,
    saveUninitialized: true
  })
);
```

### Passport

```js
// server.js

app.use(passport.initialize());
app.use(passport.session());
passport.serializeUser(function(user, done) {
  done(null, user);
});
passport.deserializeUser(function(user, done) {
  done(null, user);
});

const redirectPassport = new CriiptoVerifyRedirectPassportStrategy(
  {
    domain: "{{YOUR_CRIIPTO_DOMAIN}}",
    clientID: "{{YOUR_CLIENT_ID}}",
    clientSecret: CRIIPTO_CLIENT_SECRET,
    // Should match an express route that is an allowed callback URL in your application
    // This route should also have the authentication middleware applied.
    redirectUri: '/login',
    postLogoutRedirectUri: '/',

    // Ammend authorize request if you wish
    beforeAuthorize(req, options) {
      return {
        ...options,
        acr_values: req.query.acr_values,
        prompt: req.query.prompt
      }
    }
  },
  // Map claims to an express user
  async (jwtClaims) => {
    return jwtClaims;
  }
);

// Route to both trigger and handle redirect
app.get('/login', passport.authenticate('criiptoVerifyRedirect', {failureRedirect: '/error', successReturnToOrRedirect: '/passport/protected'}), (req, res) => {
  res.json(req.user);
});
app.get('/protected', passport.authenticate('criiptoVerifyRedirect', {}), (req, res) => {
  res.json(req.user);
});
app.get('/logout', redirectPassport.logout.bind(redirectPassport));
app.get('/error', function (req, res, next) {
  res.json({
    error: req.query.error,
    error_description: req.query.error_description,
  });
});
```

### Plain express

```js
const expressRedirect = new CriiptoVerifyExpressRedirect({
  domain: "{{YOUR_CRIIPTO_DOMAIN}}",
  clientID: "{{YOUR_CLIENT_ID}}",
  clientSecret: CRIIPTO_CLIENT_SECRET,
  // Should match an express route that is an allowed callback URL in your application
  // This route should also have the authentication middleware applied.
  redirectUri: '/login',
  postLogoutRedirectUri: '/',

  // Ammend authorize request if you wish
  beforeAuthorize(req, options) {
    return {
      ...options,
      acr_values: req.query.acr_values,
      prompt: req.query.prompt
    }
  }
});

// Route to both trigger and handle redirect
app.get('/login', expressRedirect.middleware({failureRedirect: '/error', successReturnToOrRedirect: '/plain/protected'}), (req, res) => {
  res.json(req.claims);
});
app.get('/protected', expressRedirect.middleware({}), (req, res) => {
  res.json(req.claims);
});

app.get('/logout', expressRedirect.logout.bind(expressRedirect));

app.get('/error', function (req, res, next) {
  res.json({
    error: req.query.error,
    error_description: req.query.error_description,
  });
});
```

## Single-page application

SPAs can utilize frontend frameworks like [@criipto/auth-js](https://www.npmjs.com/package/@criipto/auth-js) or [@criipto/verify-react](https://www.npmjs.com/package/@criipto/verify-react)
to handle the login in the frontend and then send a Bearer token to their API.

You must register a Callback URL on your Criipto Application matching the `href` of the URL you are triggering SPA login from.

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