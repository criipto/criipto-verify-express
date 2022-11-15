import fetch, {
  Headers,
  Request,
  Response,
} from 'node-fetch'

if (!(globalThis as any).fetch) {
  (globalThis as any).fetch = fetch as any;
  (globalThis as any).Headers = Headers as any;
  (globalThis as any).Request = Request as any;
  (globalThis as any).Response = Response as any;
}