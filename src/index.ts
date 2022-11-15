import './fetch-polyfill';
import { Request, Response } from 'express';
import { buildAuthorizeURL, OpenIDConfigurationManager, codeExchange, AuthorizeURLOptions, buildLogoutURL } from '@criipto/oidc';
import { ParamsDictionary } from 'express-serve-static-core';
import passport from 'passport';
import { ParsedQs } from 'qs';
import { createRemoteJWKSet, JWTPayload, jwtVerify } from 'jose';
import { CRIIPTO_SDK, extractBearerToken, memoryStorage } from './utils';

const debug = require('debug')('@criipto/verify-express');

export default class OAuth2Error extends Error {
  error: string;
  error_description?: string;
  state?: string;

  constructor(error: string, error_description?: string, state?: string) {
    super(error + (error_description ? ` (${error_description})` : ''));
    this.name = "OAuth2Error";
    this.error = error;
    this.error_description = error_description;
    this.state = state;
  }
}

export interface CriiptoVerifyJwtOptions {
  domain: string
  clientID: string
}

export interface CriiptoVerifyRedirectOptions {
  domain: string
  clientID: string
  clientSecret: string
  /** If no host is included, the current request host will be used. */
  redirectUri: string
  /** If no host is included, the current request host will be used. */
  postLogoutRedirectUri?: string
  /** Modify authorize request if needed */
  beforeAuthorize?: (req: Request, options: AuthorizeURLOptions) => AuthorizeURLOptions
}

export class CriiptoVerifyExpressJwt {
  options: CriiptoVerifyJwtOptions
  jwks: ReturnType<typeof createRemoteJWKSet>
  configurationManager: OpenIDConfigurationManager

  constructor(options: CriiptoVerifyJwtOptions) {
    this.options = options;
    this.jwks = createRemoteJWKSet(new URL(`https://${options.domain}/.well-known/jwks`));
    this.configurationManager = new OpenIDConfigurationManager(`https://${options.domain}`, options.clientID, memoryStorage);
  }

  middleware() {
    return (req: Request, res: Response, next: ((err?: Error) => {})) => {
      Promise.resolve().then(async () => {
        const jwt = extractBearerToken(req);
        if (!jwt) throw new Error('No bearer token found in request');
        
        const { payload } = await jwtVerify(jwt, this.jwks, {
          issuer: `https://${this.options.domain}`,
          audience: this.options.clientID,
        });

        req.claims = payload;
      }).then(() => {
        next();
      })
      .catch(err => {
        debug(err);
        next(err);
      });
    };
  }
}

export class CriiptoVerifyJwtPassportStrategy implements passport.Strategy  {
  options: CriiptoVerifyJwtOptions
  claimsToUser: (input: JWTPayload) => Express.User | Promise<Express.User>
  jwks: ReturnType<typeof createRemoteJWKSet>
  configurationManager: OpenIDConfigurationManager

  constructor(options: CriiptoVerifyJwtOptions, claimsToUser: (input: JWTPayload) => Express.User | Promise<Express.User>) {
    this.options = options;
    this.claimsToUser = claimsToUser;
    this.jwks = createRemoteJWKSet(new URL(`https://${options.domain}/.well-known/jwks`));
    this.configurationManager = new OpenIDConfigurationManager(`https://${options.domain}`, options.clientID, memoryStorage);
  }

  authenticate(
    this: passport.StrategyCreated<this, this & passport.StrategyCreatedStatic> & this,
    req: Request<ParamsDictionary, any, any, ParsedQs, Record<string, any>>
  ) {
    Promise.resolve().then(async () => {
      const jwt = extractBearerToken(req);
      if (!jwt) throw new Error('No bearer token found in request');
      
      const { payload } = await jwtVerify(jwt, this.jwks, {
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
}

export class CriiptoVerifyExpressRedirect {
  options: CriiptoVerifyRedirectOptions
  jwks: ReturnType<typeof createRemoteJWKSet>
  configurationManager: OpenIDConfigurationManager

  constructor(options: CriiptoVerifyRedirectOptions) {
    this.options = options;
    this.jwks = createRemoteJWKSet(new URL(`https://${options.domain}/.well-known/jwks`));
    this.configurationManager = new OpenIDConfigurationManager(`https://${options.domain}`, options.clientID, memoryStorage);
  }

  async logout(req: Request, res: Response) {
    req.session.verifyClaims = null;

    const protocol = req.protocol;
    const strategyOptions = this.options;
    const postLogoutRedirectUri = strategyOptions.postLogoutRedirectUri ?? '/';
    const redirectUri =
      new URL(postLogoutRedirectUri.startsWith('http') ? postLogoutRedirectUri : `${protocol}://${req.get('host')}${postLogoutRedirectUri}`);

    const configuration = await this.configurationManager.fetch();
    const logoutUrl = buildLogoutURL(configuration, {
      post_logout_redirect_uri: redirectUri.href
    });
    res.redirect(logoutUrl.href);
  }

  middleware(options?: {force?: boolean, failureRedirect?: string, successReturnToOrRedirect?: string}) {
    return (req: Request, res: Response, next: ((err?: Error) => {})) => {
      const strategyOptions = this.options as CriiptoVerifyRedirectOptions;
      const force = options?.force || false;

      if (!req.session) throw new Error('express-session is required when using redirect');

      Promise.resolve().then(async () => {
        const claimsJson = req.session.verifyClaims;
        if (claimsJson) {
          const claims = JSON.parse(claimsJson);
          req.claims = claims;
          
          if (!force) {
            return next();
          }
        }

        if (req.query.code) {
          const redirectUri = req.session.verifyRedirectUri;
          if (!redirectUri) throw new Error('Bad session state');

          const code = req.query.code as string;
          const configuration = await this.configurationManager.fetch();
          const codeResponse = await codeExchange(configuration, {
            redirect_uri: redirectUri,
            code,
            client_secret: strategyOptions.clientSecret
          });

          if ("error" in codeResponse) {
            throw new OAuth2Error(codeResponse.error, codeResponse.error_description, codeResponse.state);
          }
          
          const { payload } = await jwtVerify(codeResponse.id_token, this.jwks, {
            issuer: `https://${this.options.domain}`,
            audience: this.options.clientID,
          });
          req.claims = payload;
          req.session.verifyClaims = JSON.stringify(payload);
          req.session.touch();

          if (options.successReturnToOrRedirect) {
            const returnTo = req.query.returnTo as string | undefined ?? options.successReturnToOrRedirect;
            return res.redirect(returnTo);
          }
          return next();
        }
        if (req.query.error) {
          throw new OAuth2Error(req.query.error as string, req.query.error_description as string | undefined, req.query.state as string | undefined);
        }
        const protocol = req.protocol;
        const redirectUri =
          new URL(strategyOptions.redirectUri.startsWith('http') ? strategyOptions.redirectUri : `${protocol}://${req.get('host')}${strategyOptions.redirectUri}`);

        if (req.url !== strategyOptions.redirectUri) {
          redirectUri.searchParams.set('returnTo', req.url);
        }
        const configuration = await this.configurationManager.fetch();
        const beforeAuthorize = strategyOptions.beforeAuthorize ?? ((r, i) => i)
        const authorizeUrl = buildAuthorizeURL(configuration, beforeAuthorize(req, {
          scope: 'openid',
          redirect_uri: redirectUri.href,
          response_mode: 'query',
          response_type: 'code'
        }));
        authorizeUrl.searchParams.set('criipto_sdk', CRIIPTO_SDK);

        req.session.verifyRedirectUri = redirectUri.href,
        req.session.touch();
        res.redirect(authorizeUrl.href);
      })
      .catch(err => {
        debug(err);
        const failureRedirect = options.failureRedirect ?? '/';
        if (err instanceof OAuth2Error) {
          return res.redirect(`${failureRedirect}?error=${err.error}&error_description=${err.error_description || ''}&state=${err.state || ''}`)
        }
        return res.redirect(`${failureRedirect}?error=${err.toString()}`)
      });
    };
  }
}

export class CriiptoVerifyRedirectPassportStrategy implements passport.Strategy  {
  options: CriiptoVerifyRedirectOptions
  claimsToUser: (input: JWTPayload) => Express.User | Promise<Express.User>
  jwks: ReturnType<typeof createRemoteJWKSet>
  configurationManager: OpenIDConfigurationManager
  helper: CriiptoVerifyExpressRedirect

  constructor(options: CriiptoVerifyRedirectOptions, claimsToUser: (input: JWTPayload) => Express.User | Promise<Express.User>) {
    this.options = options;
    this.claimsToUser = claimsToUser;
    this.jwks = createRemoteJWKSet(new URL(`https://${options.domain}/.well-known/jwks`));
    this.configurationManager = new OpenIDConfigurationManager(`https://${options.domain}`, options.clientID, memoryStorage);
    this.helper = new CriiptoVerifyExpressRedirect(options);
    this.helper.configurationManager = this.configurationManager;
  }

  logout(req: Request, res: Response) {
    req.logout(async () => {
      this.helper.logout(req, res);
    });
  }

  authenticate(
    this: passport.StrategyCreated<this, this & passport.StrategyCreatedStatic> & this,
    req: Request<ParamsDictionary, any, any, ParsedQs, Record<string, any>>,
    options?: {force?: boolean, failureRedirect?: string}
  ) {
    const strategyOptions = this.options as CriiptoVerifyRedirectOptions;
    const force = options?.force || false;
    const isAuthenticated = req.isAuthenticated();

    if (!force && isAuthenticated) return this.pass();

    Promise.resolve().then(async () => {
      const protocol = req.protocol;
      const redirectUri =
        new URL(strategyOptions.redirectUri.startsWith('http') ? strategyOptions.redirectUri : `${protocol}://${req.get('host')}${strategyOptions.redirectUri}`);

      if (req.query.code) {
        const code = req.query.code as string;
        const configuration = await this.configurationManager.fetch();
        const codeResponse = await codeExchange(configuration, {
          redirect_uri: redirectUri.href,
          code,
          client_secret: strategyOptions.clientSecret
        });

        if ("error" in codeResponse) {
          throw new OAuth2Error(codeResponse.error, codeResponse.error_description, codeResponse.state);
        }
        
        const { payload } = await jwtVerify(codeResponse.id_token, this.jwks, {
          issuer: `https://${this.options.domain}`,
          audience: this.options.clientID,
        });
        const user = await this.claimsToUser(payload);
        return this.success(user);
      }
      if (req.query.error) {
        throw new OAuth2Error(req.query.error as string, req.query.error_description as string | undefined, req.query.state as string | undefined);
      }

      const configuration = await this.configurationManager.fetch();
      const beforeAuthorize = strategyOptions.beforeAuthorize ?? ((r, i) => i)
      const authorizeUrl = buildAuthorizeURL(configuration, beforeAuthorize(req, {
        scope: 'openid',
        redirect_uri: redirectUri.href,
        response_mode: 'query',
        response_type: 'code'
      }));
      authorizeUrl.searchParams.set('criipto_sdk', CRIIPTO_SDK);

      this.redirect(authorizeUrl.href);
    })
    .catch(err => {
      debug(err);
      if (options.failureRedirect) {
        if (err instanceof OAuth2Error) {
          return this.redirect(`${options.failureRedirect}?error=${err.error}&error_description=${err.error_description || ''}&state=${err.state || ''}`)
        }
        return this.redirect(`${options.failureRedirect}?error=${err.toString()}`)
      } else {
        this.fail(err);
      }
    });
  }
}
