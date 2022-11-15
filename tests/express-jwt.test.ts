import { describe, it, expect } from '@jest/globals';
import supertest from 'supertest';
import express from 'express';
import { CriiptoVerifyExpressJwt } from '../src';

const authenticator = new CriiptoVerifyExpressJwt({
  domain: 'samples.criipto.id',
  clientID: 'urn:my:application:identifier:9134'
});
const app = express();
app.get('/protected', authenticator.middleware(), (req, res) => {
  res.json({});
});
const request = supertest(app);

describe('CriiptoVerifyExpressJwt', () => {
  it('responds with 401 if no jwt', async () => {
    const actual = await request.get('/protected');
    expect(actual.statusCode).toBe(401);
  });

  it('responds with 401 if jwt is malformed', async () => {
    const jwt = 'asd.asd.asd';
    const actual = await (request.get('/protected').set('Authorization', `Bearer ${jwt}`));
    expect(actual.statusCode).toBe(401);
  });

  it('responds with 401 if jwt is for wrong issuer', async () => {
    const jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IkIxMTQ5QkM4MEMyNUY4MTZEODVCMjdFMTMwNUYzRkQ1NTMwNkUzRUYifQ.eyJpc3MiOiJodHRwczovL3NhbXBsZXMuY3JpaXB0by5pZCIsImF1ZCI6InVybjpjcmlpcHRvOnNhbXBsZXM6Y3JpaXB0by1hdXRoIiwibm9uY2UiOiJlY25vbi01M2NhMWQ0OS00ZWYxLTRlMzEtYWEwMy1iYjdiYzIyNWI4MDIiLCJpZGVudGl0eXNjaGVtZSI6InNlYmFua2lkIiwiYXV0aGVudGljYXRpb250eXBlIjoidXJuOmdybjphdXRobjpzZTpiYW5raWQ6c2FtZS1kZXZpY2UiLCJhdXRoZW50aWNhdGlvbm1ldGhvZCI6InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlNvZnR3YXJlUEtJIiwiYXV0aGVudGljYXRpb25pbnN0YW50IjoiMjAyMi0xMS0xNVQxNTowMToyNC41MzNaIiwibmFtZWlkZW50aWZpZXIiOiI0YTUyZDg2ZGNjZTU0NGM5OTk5MWZhNGZmNzlmM2VhNyIsInN1YiI6Ins0YTUyZDg2ZC1jY2U1LTQ0YzktOTk5MS1mYTRmZjc5ZjNlYTd9Iiwic2Vzc2lvbmluZGV4IjoiYjM1NTQzYWEtYjMzMS00MDkxLWE0MWEtNDc1NmU2NDkxMTNjIiwic3NuIjoiMTk4MjA4MjczNTg0IiwibmFtZSI6IkxpbGx5IEJlcmdxdmlzdCIsImdpdmVubmFtZSI6IkxpbGx5IiwiZ2l2ZW5fbmFtZSI6IkxpbGx5Iiwic3VybmFtZSI6IkJlcmdxdmlzdCIsImZhbWlseV9uYW1lIjoiQmVyZ3F2aXN0IiwiaXBhZGRyZXNzIjoiODAuNzEuMTQyLjk5IiwiY291bnRyeSI6IlNFIiwiaWF0IjoxNjY4NTI0NDg0LCJuYmYiOjE2Njg1MjQ0ODQsImV4cCI6MTY2ODUyNTY4NH0.Lg1zApzxyR9cxJsT-cD-ZgJ3soFotIJPZWpT-a47Nl9FaRFDyDX8DzFf-PxEL2UIy9RtTp9PenvvS7TVzDgB_EVjnY75nqRllsTw4qJqEGXlHW7KTiWbvOPhYN8ZNlsVyK7OJAAKfTHqjA1B2nKiKgq6KGgvHY1udPeuLHMzyh1R2X7PMKEVfrralIZgozqXWyCPMWhTxl6oxEGAaxdcNFS1DYd-r9ApYcA0oMVQxzVUHYk6ppv19TQCiSFmVEXwu8pqq-FNmSKonb_w3a7-RQZTH4bd_GQ2W2TJvmmgDllBerub7c30hxaJAGRAvaMGJCV7zQ4btmeVUhKM8diZ7g';
    const actual = await (request.get('/protected').set('Authorization', `Bearer ${jwt}`));
    expect(actual.statusCode).toBe(401);
  });
});