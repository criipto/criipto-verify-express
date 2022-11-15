import { JWTPayload } from "jose";

declare global {
  namespace Express {
    // These open interfaces may be extended in an application-specific manner via declaration merging.
    // See for example method-override.d.ts (https://github.com/DefinitelyTyped/DefinitelyTyped/blob/master/types/method-override/index.d.ts)
    interface Request {
        claims?: JWTPayload
    }
  }
}

declare module 'express-session' {
  interface SessionData {
    verifyClaims?: string
    verifyRedirectUri?: string
  }
}