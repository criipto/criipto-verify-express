const express = require('express');
const expressSesssion = require('express-session');
const passport = require('passport');
const CriiptoVerifyPassportStrategy = require('@criipto/verify-express').CriiptoVerifyPassportStrategy;
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

passport.use(
  'criiptoVerifyJwt',
  new CriiptoVerifyPassportStrategy({
    domain: CRIIPTO_DOMAIN,
    clientID: CRIIPTO_CLIENT_ID,
    mode: 'jwt'
  },
  async (jwtClaims) => {
    return jwtClaims;
  })
);
passport.use(
  'criiptoVerifyRedirect',
  new CriiptoVerifyPassportStrategy({
    domain: CRIIPTO_DOMAIN,
    clientID: CRIIPTO_CLIENT_ID,
    clientSecret: CRIIPTO_CLIENT_SECRET,
    mode: 'redirect',
    redirectUri: '/passport/redirect'
  },
  async (jwtClaims) => {
    return jwtClaims;
  })
);
app.use(passport.initialize());

app.get('/', (req, res) => {
  res.send('Hello World!')
});

app.get('/passport/jwt', passport.authenticate('criiptoVerifyJwt', { session: false }), (req, res) => {
  res.json(req.user);
});
app.get('/passport/redirect', passport.authenticate('criiptoVerifyRedirect', {failureRedirect: '/loginerror'}), (req, res) => {
  res.json(req.user);
});
app.get('/passport/protected', passport.authenticate('criiptoVerifyRedirect', {failureRedirect: '/loginerror'}), (req, res) => {
  res.json(req.user);
});
app.get('/protected', function (req, res, next) {
  if (!req.isAuthenticated()) {
    res.json({}, 401);
    return;
  }
  next();
}, (req, res) => {
  res.json(req.user);
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
});