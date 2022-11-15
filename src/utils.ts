import { Request } from 'express';
import {readFileSync} from 'fs';

export function extractBearerToken(req: Request) {
  if (!req.headers['authorization']) return null;
  const authorization = req.headers['authorization'];

  if (!authorization.startsWith('Bearer ')) return null;

  return authorization.split('Bearer ')[1] || null;
}

export const VERSION = JSON.parse(readFileSync(__dirname + '/../package.json').toString()).version;
export const CRIIPTO_SDK = `@criipto/verify-express@${VERSION}`;

export const memoryStorage = (() => {
  let cache : {[key: string]: string} = {};

  const storage = {
    get length() {
      return Object.keys(cache).length;
    },
    clear() {
      cache = {};
    },
    getItem(key: string) {
      return cache[key];
    },
    setItem(key: string, value: string) {
      cache[key] = value;
    },
    removeItem(key: string) {
      delete cache[key];
    },
    key(index: number) {
      return Object.keys(cache)[index] ?? null;
    },
  };
  
  return storage;
})();