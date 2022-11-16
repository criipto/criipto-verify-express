const express = require('express');
const expressSesssion = require('express-session');
const passport = require('passport');
const CriiptoVerifyJwtPassportStrategy = require('@criipto/verify-express').CriiptoVerifyJwtPassportStrategy;
const CriiptoVerifyRedirectPassportStrategy = require('@criipto/verify-express').CriiptoVerifyRedirectPassportStrategy;
const CriiptoVerifyExpressJwt = require('@criipto/verify-express').CriiptoVerifyExpressJwt;
const CriiptoVerifyExpressRedirect = require('@criipto/verify-express').CriiptoVerifyExpressRedirect;
const app = express();
const port = 3000;

const CRIIPTO_DOMAIN = 'samples.criipto.id';
const CRIIPTO_CLIENT_ID = 'urn:my:application:identifier:9134';
const CRIIPTO_CLIENT_SECRET = 'NcOhZnGxQd++/xO6KgbL2iII0tqWFiLv571bWLIOWVA=';

app.use(
  expressSesssion({
    secret: '{{YOUR_SESSION_SECRET}}',
    resave: false,
    saveUninitialized: true
  })
);
app.use(passport.initialize());
app.use(passport.session());
passport.serializeUser(function(user, done) {
  done(null, user);
});
passport.deserializeUser(function(user, done) {
  done(null, user);
});

passport.use(
  'criiptoVerifyJwt',
  new CriiptoVerifyJwtPassportStrategy({
    domain: CRIIPTO_DOMAIN,
    clientID: CRIIPTO_CLIENT_ID
  },
  // Map claims to an express user
  async (jwtClaims) => {
    return jwtClaims;
  })
);

const redirectPassport = new CriiptoVerifyRedirectPassportStrategy(
  {
    domain: CRIIPTO_DOMAIN,
    clientID: CRIIPTO_CLIENT_ID,
    clientSecret: CRIIPTO_CLIENT_SECRET,
    // Should match an express route that is an allowed callback URL in your application
    // This route should also have the authentication middleware applied.
    redirectUri: '/passport/redirect',
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
passport.use(
  'criiptoVerifyRedirect',
  redirectPassport
);
app.get('/passport/jwt', passport.authenticate('criiptoVerifyJwt', { session: false }), (req, res) => {
  res.json({
    ...req.user,
    passport: 'says hi'
  });
});
app.get('/passport/redirect', passport.authenticate('criiptoVerifyRedirect', {failureRedirect: '/error', successReturnToOrRedirect: '/passport/protected'}), (req, res) => {
  res.json({
    user: req.user,
    home: `${req.protocol}://${req.get('host')}/`
  });
});
app.get('/passport/protected', passport.authenticate('criiptoVerifyRedirect', {}), (req, res) => {
  res.json({
    user: req.user,
    home: `${req.protocol}://${req.get('host')}/`
  });
});
app.get('/passport/logout', redirectPassport.logout.bind(redirectPassport));

const expressJwt = new CriiptoVerifyExpressJwt({
  domain: CRIIPTO_DOMAIN,
  clientID: CRIIPTO_CLIENT_ID
});
app.get('/plain/jwt', expressJwt.middleware(), (req, res) => {
  res.json({
    ...req.claims,
    express: 'says hi'
  });
});

const expressRedirect = new CriiptoVerifyExpressRedirect({
  domain: CRIIPTO_DOMAIN,
  clientID: CRIIPTO_CLIENT_ID,
  clientSecret: CRIIPTO_CLIENT_SECRET,
  // Should match an express route that is an allowed callback URL in your application
  // This route should also have the authentication middleware applied.
  redirectUri: '/plain/redirect',
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
app.get('/plain/redirect', expressRedirect.middleware({failureRedirect: '/error', successReturnToOrRedirect: '/plain/protected'}), (req, res) => {
  res.json({
    claims: req.claims,
    home: `${req.protocol}://${req.get('host')}/`
  });
});
app.get('/plain/protected', expressRedirect.middleware({}), (req, res) => {
  res.json({
    claims: req.claims,
    home: `${req.protocol}://${req.get('host')}/`
  });
});

app.get('/plain/logout', expressRedirect.logout.bind(expressRedirect));

app.get('/error', function (req, res, next) {
  res.json({
    error: req.query.error,
    error_description: req.query.error_description,
  });
});

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/views/index.html');
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
});