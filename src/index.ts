import * as didJWT from "did-jwt";
import KeyDIDResolver from "key-did-resolver";
import { Resolver } from "did-resolver";

import * as ed25519 from "@stablelib/ed25519";
import { concat } from "uint8arrays/concat";
import { toString } from "uint8arrays/to-string";
import { fromString } from "uint8arrays/from-string";
import { safeJsonParse, safeJsonStringify } from "@walletconnect/safe-json";

// ---------- Interfaces ----------------------------------------------- //

interface IridiumJWTHeader {
  alg: "EdDSA";
  typ: "JWT";
}

interface IridiumJWTPayload {
  iss: string;
  sub: string;
}

interface IridiumJWTData {
  header: IridiumJWTHeader;
  payload: IridiumJWTPayload;
}

interface IridiumJWTSigned extends IridiumJWTData {
  signature: Uint8Array;
}

// ---------- Constants ----------------------------------------------- //

const JWT_IRIDIUM_ALG: IridiumJWTHeader["alg"] = "EdDSA";

const JWT_IRIDIUM_TYP: IridiumJWTHeader["typ"] = "JWT";

const JWT_DELIMITER = ".";

const JWT_ENCODING = "base64url";

const JSON_ENCODING = "utf8";

const DID_DELIMITER = ":";

const DID_PREFIX = "did";

const DID_METHOD = "key";

const MULTICODEC_ED25519_ENCODING = "base58btc";

const MULTICODEC_ED25519_BASE = "z";

const MULTICODEC_ED25519_HEADER = "K36";

const MULTICODEC_ED25519_LENGTH = 32;

// ---------- Utilities ----------------------------------------------- //

export function decodeJSON(str: string): any {
  return safeJsonParse(toString(fromString(str, JWT_ENCODING), JSON_ENCODING));
}

export function encodeJSON(val: any): string {
  return toString(
    fromString(safeJsonStringify(val), JSON_ENCODING),
    JWT_ENCODING
  );
}

export function encodeIss(publicKey: Uint8Array): string {
  const header = fromString(
    MULTICODEC_ED25519_HEADER,
    MULTICODEC_ED25519_ENCODING
  );
  const multicodec =
    MULTICODEC_ED25519_BASE +
    toString(concat([header, publicKey]), MULTICODEC_ED25519_ENCODING);
  return [DID_PREFIX, DID_METHOD, multicodec].join(DID_DELIMITER);
}

export function decodeIss(issuer: string): Uint8Array {
  const [prefix, method, multicodec] = issuer.split(DID_DELIMITER);
  if (prefix !== DID_PREFIX || method !== DID_METHOD) {
    throw new Error(`Issuer must be a DID with method "key"`);
  }
  const base = multicodec.slice(0, 1);
  if (base !== MULTICODEC_ED25519_BASE) {
    throw new Error(`Issuer must be a key in mulicodec format`);
  }
  const bytes = fromString(multicodec.slice(1), MULTICODEC_ED25519_ENCODING);
  const type = toString(bytes.slice(0, 2), MULTICODEC_ED25519_ENCODING);
  if (type !== MULTICODEC_ED25519_HEADER) {
    throw new Error(`Issuer must be a public key with type "Ed25519"`);
  }
  const publicKey = bytes.slice(2);
  if (publicKey.length !== MULTICODEC_ED25519_LENGTH) {
    throw new Error(`Issuer must be a public key with length 32 bytes`);
  }
  return publicKey;
}

export function encodeSig(bytes: Uint8Array): string {
  return toString(bytes, JWT_ENCODING);
}

export function decodeSig(encoded: string): Uint8Array {
  return fromString(encoded, JWT_ENCODING);
}

export function encodeData(params: IridiumJWTData): string {
  return [encodeJSON(params.header), encodeJSON(params.payload)].join(
    JWT_DELIMITER
  );
}

export function decodeData(jwt: string): IridiumJWTData {
  const params = jwt.split(JWT_DELIMITER);
  const header = decodeJSON(params[0]);
  const payload = decodeJSON(params[1]);
  return { header, payload };
}

export function encodeJWT(params: IridiumJWTSigned): string {
  return [
    encodeJSON(params.header),
    encodeJSON(params.payload),
    encodeSig(params.signature),
  ].join(JWT_DELIMITER);
}

export function decodeJWT(jwt: string): IridiumJWTSigned {
  const params = jwt.split(JWT_DELIMITER);
  const header = decodeJSON(params[0]);
  const payload = decodeJSON(params[1]);
  const signature = decodeSig(params[2]);
  return { header, payload, signature };
}

// ---------- API ----------------------------------------------- //

export async function signJWT(subject: string, keyPair: ed25519.KeyPair) {
  const header = { alg: JWT_IRIDIUM_ALG, typ: JWT_IRIDIUM_TYP };
  const issuer = encodeIss(keyPair.publicKey);
  const payload = { iss: issuer, sub: subject };
  const data = fromString(encodeData({ header, payload }), "utf8");
  const signature = ed25519.sign(keyPair.secretKey, data);
  return encodeJWT({ header, payload, signature });
}

export async function verifyJWT(jwt: string) {
  const { header, payload, signature } = decodeJWT(jwt);
  if (header.alg !== JWT_IRIDIUM_ALG || header.typ !== JWT_IRIDIUM_TYP) {
    throw new Error("JWT must use EdDSA algorithm");
  }
  const publicKey = decodeIss(payload.iss);
  const data = fromString(encodeData({ header, payload }), "utf8");
  return ed25519.verify(publicKey, data, signature);
}

// ---------- Test Cases ----------------------------------------------- //

// Client will sign the Server assigned socketId as a nonce
const nonce =
  "c479fe5dc464e771e78b193d239a65b58d278cad1c34bfb0b5716e5bb514928e";

// Fixed seed to generate the same key pair
const seed = fromString(
  "58e0254c211b858ef7896b00e3f36beeb13d568d47c6031c4218b87718061295",
  "base16"
);

// Generate key pair from seed
const keyPair = ed25519.generateKeyPairFromSeed(seed);

// Expected JWT for given nonce
const expected =
  "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJkaWQ6a2V5Ono2TWtvZEhad25lVlJTaHRhTGY4SktZa3hwREdwMXZHWm5wR21kQnBYOE0yZXh4SCIsInN1YiI6ImM0NzlmZTVkYzQ2NGU3NzFlNzhiMTkzZDIzOWE2NWI1OGQyNzhjYWQxYzM0YmZiMGI1NzE2ZTViYjUxNDkyOGUifQ.0JkxOM-FV21U7Hk-xycargj_qNRaYV2H5HYtE4GzAeVQYiKWj7YySY5AdSqtCgGzX4Gt98XWXn2kSr9rE1qvCA";

async function test() {
  const jwt = await signJWT(nonce, keyPair);
  console.log("jwt", jwt);
  console.log("matches", jwt === expected);
  const verified = await verifyJWT(jwt);
  console.log("verified", verified);
  const decoded = didJWT.decodeJWT(jwt);
  console.log("decoded", decoded);
  const keyDidResolver = KeyDIDResolver.getResolver();
  const resolver = new Resolver(keyDidResolver);
  const response = await didJWT.verifyJWT(jwt, { resolver });
  console.log("response", response);
}

test();
