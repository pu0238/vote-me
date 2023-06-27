import { encodeBase58, ethers } from "ethers";
import * as secp256k1 from "secp256k1";
import { bech32 } from "bech32";

export enum Network {
  Testnet,
  Regtest,
  Mainnet,
}

function networkToPrefix(network: Network): number {
  switch (network) {
    case Network.Testnet:
      return 0x6f;
    case Network.Regtest:
      return 0x6f;
    case Network.Mainnet:
      return 0x00;
  }
}

export function publicKeyToBitcoinAddress(
  network: Network,
  publicKey: Uint8Array
): string {
  const sha256 = ethers.sha256(publicKey).slice(2);
  const result = ethers.ripemd160(Buffer.from(sha256, "hex")).slice(2);

  const prefix = networkToPrefix(network);
  const dataWithPrefix = Buffer.concat([
    Buffer.from([prefix]),
    Buffer.from(result, "hex"),
  ]);

  const checksum = Buffer.from(
    ethers
      .sha256(Buffer.from(ethers.sha256(dataWithPrefix).slice(2), "hex"))
      .slice(2),
    "hex"
  ).slice(0, 4);

  const fullAddress = Buffer.concat([dataWithPrefix, Buffer.from(checksum)]);

  return encodeBase58(fullAddress);
}

export function publicKeyToEvmAddress(publicKey: Uint8Array): string {
  const extendedKey = secp256k1.publicKeyConvert(publicKey, false);

  return "0x" + ethers.keccak256(extendedKey.slice(1)).slice(-40);
}

export function privateKeyToCosmosAddress(
  prefix: string,
  publicKey: Uint8Array
): string {
  const sha256 = ethers.sha256(publicKey).slice(2);
  const ripemd160 = ethers.ripemd160(Buffer.from(sha256, "hex")).slice(2);
  const words = bech32.toWords(Buffer.from(ripemd160, "hex"));

  return bech32.encode(prefix, words);
}

export function hashUserData(
  username: string,
  password: string,
  selectedImage: String,
  salt: string
): string {
  const saltUserPasswd = ethers.keccak256(
    Buffer.from(salt + username + password)
  );

  return ethers.ripemd160(Buffer.from(saltUserPasswd + selectedImage));
}
