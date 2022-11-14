import './fetch-polyfill';
import { Request } from 'express';
import { buildAuthorizeURL, OpenIDConfigurationManager, codeExchange } from '@criipto/oidc';
import { ParamsDictionary } from 'express-serve-static-core';
import passport from 'passport';
import { ParsedQs } from 'qs';
import { createRemoteJWKSet, JWTPayload, jwtVerify } from 'jose';
import { CRIIPTO_SDK, extractBearerToken, memoryStorage } from './utils';

const debug = require('debug')('@criipto/verify-express');

export interface CriiptoVerifyJwtOptions {
  // Whether or not the strategy should operate simply as an JWT-validator or if it should redirect to start a new session.
  // Express sessions must be configured for 'redirect'
  mode: 'jwt'
  domain: string
  clientID: string
}

export interface CriiptoVerifyRedirectOptions {
  // Whether or not the strategy should operate simply as an JWT-validator or if it should redirect to start a new session.
  // Express sessions must be configured for 'redirect'
  mode: 'redirect'
  domain: string
  clientID: string
  clientSecret: string
  // If no host is included, the current request host will be used.
  redirectUri: string
}

export type CriiptoVerifyOptions = CriiptoVerifyJwtOptions | CriiptoVerifyRedirectOptions;

export class CriiptoVerifyPassportStrategy implements passport.Strategy  {
  options: CriiptoVerifyOptions
  claimsToUser: (input: JWTPayload) => Express.User
  jwks: ReturnType<typeof createRemoteJWKSet>
  configurationManager: OpenIDConfigurationManager

  constructor(options: CriiptoVerifyOptions, claimsToUser: (input: JWTPayload) => Express.User) {
    this.options = options;
    this.claimsToUser = claimsToUser;
    this.jwks = createRemoteJWKSet(new URL(`https://${options.domain}/.well-known/jwks`));
    this.configurationManager = new OpenIDConfigurationManager(`https://${options.domain}`, options.clientID, memoryStorage);
  }

  authenticate(
    this: passport.StrategyCreated<this, this & passport.StrategyCreatedStatic> & this,
    req: Request<ParamsDictionary, any, any, ParsedQs, Record<string, any>>,
    options?: {force?: boolean}
  ) {
    if (this.options.mode === 'jwt') {
      Promise.resolve().then(async () => {
        const jwt = extractBearerToken(req);
        if (!jwt) throw new Error('No bearer token found in request');
        
        const { payload, protectedHeader } = await jwtVerify(jwt, this.jwks, {
          issuer: `https://${this.options.domain}`,
          audience: this.options.clientID,
        });

        return this.claimsToUser(payload);
      }).then(this.success)
      .catch(err => {
        debug(err);
        this.fail(err);
      });
    }
    else if (this.options.mode === "redirect") {
      const strategyOptions = this.options as CriiptoVerifyRedirectOptions;
      const force = options?.force || false;
      const isAuthenticated = req.isAuthenticated();

      if (!force && isAuthenticated) return this.pass();

      Promise.resolve().then(async () => {
        const protocol = req.protocol;
        const redirectUri =
          new URL(strategyOptions.redirectUri.startsWith('http') ? strategyOptions.redirectUri : `${protocol}://${req.get('host')}${strategyOptions.redirectUri}`);
        const returnTo = req.query.returnTo as string;

        if (req.query.code) {
          const code = req.query.code as string;
          const configuration = await this.configurationManager.fetch();
          const payload = await codeExchange(configuration, {
            redirect_uri: redirectUri.href,
            code,
            client_secret: strategyOptions.clientSecret
          });

          if ("error" in payload) {
            return this.redirect(`${returnTo}?error=${payload.error}&error_description=${payload.error_description}`)
          }
          return this.fail();
        }
        if (req.query.error) {
          return this.fail(req.query.error);
        }

        const configuration = await this.configurationManager.fetch();

        if (req.url !== strategyOptions.redirectUri) {
          redirectUri.searchParams.set('returnTo', req.url);
        }

        const authorizeUrl = buildAuthorizeURL(configuration, {
          scope: 'openid',
          redirect_uri: redirectUri.href,
          response_mode: 'query',
          response_type: 'code'
        });
        authorizeUrl.searchParams.set('criipto_sdk', CRIIPTO_SDK);

        this.redirect(authorizeUrl.href);
      })
      .catch(err => {
        debug(err);
        this.fail(err);
      });
    }
  }
}