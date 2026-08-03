import bigInt from 'big-integer';

import {
  generateRandomBytes,
  modExp,
  readBigIntFromBuffer,
  readBufferFromBigInt,
  sha1,
} from '../Helpers';

export const SERVER_KEYS = [
    {
        fingerprint: bigInt("-4189175511134604188"),
        n: bigInt(
            "c288b69fbc967ce1a393220005beff534bc9949340adeeac66240236c4d7ad06e0df6de1a6bd7c6ff709a1d0aa96f479b1dc5315c88089be47d2861abf796dd0d41ed87990a093565788683e753b43480efea9f9d211c451b0aedb0c8bd48c643f6d90bfdd9f50a3bd03b8b8b0d8ca8a8e5fcbc4330a6d59cdba80886de2337dea51513624d3516daf78622bda6a9a7ac195b8759ddfc22542b600df92c6734aa3c53cc247dcb506523b838fe537590edbc9c14dbdaada2b691935c3b4985f33f9e59af8bbdb43efc8b4657094f29654c32c6090a57f7ae10cc7cd33c0238fb2ff8f8b5887458b19890effeffb3120f730be8f91c48a93ecb2fab644b56e0bef",
            16
        ),
        e: 65537
    }
].reduce((acc, { fingerprint, ...keyInfo }) => {
  acc.set(fingerprint.toString(), keyInfo);
  return acc;
}, new Map<string, { n: bigInt.BigInteger; e: number }>());

/**
 * Encrypts the given data known the fingerprint to be used
 * in the way Telegram requires us to do so (sha1(data) + data + padding)

 * @param fingerprint the fingerprint of the RSA key.
 * @param data the data to be encrypted.
 * @returns {Buffer|*|undefined} the cipher text, or undefined if no key matching this fingerprint is found.
 */
export async function encrypt(fingerprint: bigInt.BigInteger, data: Buffer) {
  const key = SERVER_KEYS.get(fingerprint.toString());
  if (!key) {
    return undefined;
  }

  // len(sha1.digest) is always 20, so we're left with 255 - 20 - x padding
  const rand = generateRandomBytes(235 - data.length);

  const toEncrypt = Buffer.concat([await sha1(data), data, rand]);

  // rsa module rsa.encrypt adds 11 bits for padding which we don't want
  // rsa module uses rsa.transform.bytes2int(to_encrypt), easier way:
  const payload = readBigIntFromBuffer(toEncrypt, false);
  const encrypted = modExp(payload, bigInt(key.e), key.n);
  // rsa module uses transform.int2bytes(encrypted, keylength), easier:
  return readBufferFromBigInt(encrypted, 256, false);
}
