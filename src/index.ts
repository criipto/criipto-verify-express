import './fetch-polyfill';
import { NextFunction, Request, Response } from 'express';
import { buildAuthorizeURL, OpenIDConfigurationManager, codeExchange, AuthorizeURLOptions, buildLogoutURL } from '@criipto/oidc';
import { ParamsDictionary } from 'express-serve-static-core';
import passport from 'passport';
import { ParsedQs } from 'qs';
import { createRemoteJWKSet, JWTPayload, jwtVerify, errors } from 'jose';
import { CRIIPTO_SDK, extractBearerToken, memoryStorage } from './utils';

const debug = require('debug')('@criipto/verify-express');
const errorDebug = require('debug')('@criipto/verify-express:error');
const clockTolerance = 5 * 60;

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

  async process(req: Request) {
    const jwt = extractBearerToken(req);
    if (!jwt) return null;
    
    try {
      const { payload } = await jwtVerify(jwt, this.jwks, {
        issuer: `https://${this.options.domain}`,
        audience: this.options.clientID,
        clockTolerance
      });

      return payload;
    } catch (err) {
      errorDebug(`Error verifying JWT: ${err.toString()}`);
      if (err instanceof errors.JWTClaimValidationFailed || err instanceof errors.JWSInvalid || err instanceof errors.JWTInvalid) {
        return null;
      }
      throw err;
    }
  }

  middleware() {
    return (req: Request, res: Response, next: NextFunction) => {
      this.process(req).then((payload) => {
        if (payload) {
          req.claims = payload;
          next();
          return;
        }
        return res.sendStatus(401);
      })
      .catch(err => {
        errorDebug(err);
        next(err);
      });
    };
  }
}

export class CriiptoVerifyJwtPassportStrategy implements passport.Strategy  {
  options: CriiptoVerifyJwtOptions
  claimsToUser: (input: JWTPayload) => Express.User | Promise<Express.User>
  helper: CriiptoVerifyExpressJwt

  constructor(options: CriiptoVerifyJwtOptions, claimsToUser: (input: JWTPayload) => Express.User | Promise<Express.User>) {
    this.options = options;
    this.claimsToUser = claimsToUser;
    this.helper = new CriiptoVerifyExpressJwt(options);
  }

  authenticate(
    this: passport.StrategyCreated<this, this & passport.StrategyCreatedStatic> & this,
    req: Request<ParamsDictionary, any, any, ParsedQs, Record<string, any>>
  ) {
    this.helper.process(req)
      .then(this.claimsToUser.bind(this))
      .then(this.success)
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

  async handleCode(req: Request, redirectUri: string | undefined) {
    if (req.query.error) {
      throw new OAuth2Error(req.query.error as string, req.query.error_description as string | undefined, req.query.state as string | undefined);
    }

    if (req.query.code) {
      const code = req.query.code as string;
      if (!redirectUri) throw new Error('Bad session state');

      const configuration = await this.configurationManager.fetch();
      const codeResponse = await codeExchange(configuration, {
        redirect_uri: redirectUri,
        code,
        client_secret: this.options.clientSecret
      });

      if ("error" in codeResponse) {
        throw new OAuth2Error(codeResponse.error, codeResponse.error_description, codeResponse.state);
      }
      
      const { payload } = await jwtVerify(codeResponse.id_token, this.jwks, {
        issuer: `https://${this.options.domain}`,
        audience: this.options.clientID,
        clockTolerance
      });

      return payload;
    }

    return null;
  }

  async authorizeURL(req: Request, returnTo?: string) {
    const protocol = req.protocol;
    const redirectUri =
      new URL(this.options.redirectUri.startsWith('http') ? this.options.redirectUri : `${protocol}://${req.get('host')}${this.options.redirectUri}`);

    if (returnTo) {
      redirectUri.searchParams.set('returnTo', returnTo);
    }
    const configuration = await this.configurationManager.fetch();
    const beforeAuthorize = this.options.beforeAuthorize ?? ((r, i) => i)
    const authorizeUrl = buildAuthorizeURL(configuration, beforeAuthorize(req, {
      scope: 'openid',
      redirect_uri: redirectUri.href,
      response_mode: 'query',
      response_type: 'code'
    }));
    authorizeUrl.searchParams.set('criipto_sdk', CRIIPTO_SDK);

    return {authorizeUrl, redirectUri};
  }

  middleware(options?: {force?: boolean, failureRedirect?: string, successReturnToOrRedirect?: string}) {
    return (req: Request, res: Response, next: ((err?: Error) => {})) => {
      const strategyOptions = this.options as CriiptoVerifyRedirectOptions;
      const force = options?.force || false;

      if (!req.session) throw new Error('express-session is required when using redirect');

      Promise.resolve().then(async () => {
        const claimsJson = req.session.verifyClaims;
        if (claimsJson) {
          const claims = JSON.parse(claimsJson) as JWTPayload;
          req.claims = claims;
          
          if (!force) {
            return next();
          }
        }
        
        const payload = await this.handleCode(req, req.session.verifyRedirectUri);
        if (payload) {
          req.claims = payload;
          req.session.verifyClaims = JSON.stringify(payload);
          req.session.touch();

          if (options.successReturnToOrRedirect) {
            const returnTo = req.query.returnTo as string | undefined ?? options.successReturnToOrRedirect;
            return res.redirect(returnTo);
          }
          return next();
        }

        const {authorizeUrl, redirectUri} = await this.authorizeURL(req, req.url !== strategyOptions.redirectUri ? undefined : req.url);

        req.session.verifyRedirectUri = redirectUri.href,
        req.session.touch();
        res.redirect(authorizeUrl.href);
      })
      .catch(err => {
        errorDebug(err);
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

      const payload = await this.helper.handleCode(req, redirectUri.href);
      if (payload) {
        const user = await this.claimsToUser(payload);
        return this.success(user);
      }

      const {authorizeUrl} = await this.helper.authorizeURL(req, undefined);

      this.redirect(authorizeUrl.href);
    })
    .catch(err => {
      errorDebug(err);
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
