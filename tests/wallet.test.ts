import { expect } from "chai";
import { Secp256k1KeyIdentity } from "@dfinity/identity-secp256k1";
// @ts-ignore
import icblast from "@infu/icblast";
import * as fs from "fs";
import * as dotenv from "dotenv";
import {
  hashUserData,
} from "../utils";
import { ethers } from "ethers";
import chaiAsPromised from "chai-as-promised";
import * as chai from "chai";

chai.use(chaiAsPromised);
dotenv.config();

describe("Wallet", () => {
  const CANISTER_ID_vote_me_backend = process.env.CANISTER_ID_vote_me_backend;
  const DFX_NETWOR = process.env.DFX_NETWORK
    ? "http://localhost:4943"
    : `https://${CANISTER_ID_vote_me_backend}.ic0.app`;
  const bitnati_did = fs.readFileSync(
    "src/vote_me_backend/vote_me_backend.did",
    "utf8"
  );

  const randomIdentity = Secp256k1KeyIdentity.generate();
  const devicesPublicKey = Secp256k1KeyIdentity.generate();

  const username = "test";

  const setUpCan = async (identity?: Secp256k1KeyIdentity) => {
    const ic = icblast({ local: true, local_host: DFX_NETWOR, identity });
    return await ic(CANISTER_ID_vote_me_backend, bitnati_did);
  };

  it("First user can sign in and will be admin", async () => {
    const password = "test";
    const selectedImage = "banana";
    const randBytes = ethers.randomBytes(4);
    const salt = Buffer.from(randBytes).toString("hex");

    const saltUserPasswd = hashUserData(username, password, selectedImage, salt)
      .slice(2)
      .slice(0, 32);

    const userIdentity = Secp256k1KeyIdentity.generate(
      Buffer.from(saltUserPasswd)
    );
    const can = await setUpCan(userIdentity);

    console.table({
      username,
      saltUserPasswd,
      selectedImage,
      salt,
    });

    const res = await can.sign_in(username, salt);
    console.log({ res });
    const tokenData = JSON.parse(
      Buffer.from(res.split(".")[0], "hex").toString()
    );

    console.log("---tokenData---");

    console.table(tokenData);
    expect(res).to.be.a("string");
    expect(tokenData.username).to.be.equal(username);
    expect(tokenData.rank).to.be.equal("Admin");
  });

  it("Second user can sign in and will be user", async () => {
    const username = "secondUser"
    const password = "test";
    const selectedImage = "banana";
    const randBytes = ethers.randomBytes(4);
    const salt = Buffer.from(randBytes).toString("hex");

    const saltUserPasswd = hashUserData(username, password, selectedImage, salt)
      .slice(2)
      .slice(0, 32);

    const userIdentity = Secp256k1KeyIdentity.generate(
      Buffer.from(saltUserPasswd)
    );
    const can = await setUpCan(userIdentity);

    console.table({
      username,
      saltUserPasswd,
      selectedImage,
      salt,
    });

    const res = await can.sign_in(username, salt);
    console.log({ res });
    const tokenData = JSON.parse(
      Buffer.from(res.split(".")[0], "hex").toString()
    );

    console.log("---tokenData---");

    console.table(tokenData);
    expect(res).to.be.a("string");
    expect(tokenData.username).to.be.equal(username);
    expect(tokenData.rank).to.be.equal("User");
  });

  it("Can get user salt", async () => {
    const can = await setUpCan();

    console.table({
      username,
    });

    const res = await can.get_user_salt(username);
    expect(res).to.be.a("string");
  });

  it("Can not get user salt", async () => {
    const can = await setUpCan();
    const username = "dsfdf";

    console.table({
      username,
    });

    const res = can.get_user_salt(username);
    await expect(res).to.be.rejected;
  });

  it("User can log in", async () => {
    const password = "test";
    const selectedImage = "banana";

    const query = await setUpCan();
    const salt = await query.get_user_salt(username);

    const saltUserPasswd = hashUserData(username, password, selectedImage, salt)
      .slice(2)
      .slice(0, 32);

    const userIdentity = Secp256k1KeyIdentity.generate(
      Buffer.from(saltUserPasswd)
    );
    const can = await setUpCan(userIdentity);

    console.table({
      username,
      saltUserPasswd,
      selectedImage,
      salt,
    });

    const res = await can.log_in(username);
    expect(res).to.be.a("string");
  });

  it("Not valid user is rejected", async () => {
    const password = "123";
    const selectedImage = "banana";

    const query = await setUpCan();
    const salt = await query.get_user_salt(username);

    const saltUserPasswd = hashUserData(username, password, selectedImage, salt)
      .slice(2)
      .slice(0, 32);

    const userIdentity = Secp256k1KeyIdentity.generate(
      Buffer.from(saltUserPasswd)
    );
    const can = await setUpCan(userIdentity);

    console.table({
      username,
      saltUserPasswd,
      selectedImage,
      salt,
    });

    const res = can.log_in(username);
    await expect(res).to.be.rejected;
  });

  it("Admin can create vote", async () => {
    const password = "test";
    const selectedImage = "banana";

    const query = await setUpCan();
    const salt = await query.get_user_salt(username);

    const saltUserPasswd = hashUserData(username, password, selectedImage, salt)
      .slice(2)
      .slice(0, 32);

    const userIdentity = Secp256k1KeyIdentity.generate(
      Buffer.from(saltUserPasswd)
    );
    const can = await setUpCan(userIdentity);

    console.table({
      username,
      saltUserPasswd,
      selectedImage,
      salt,
    });

    const auth_token = await can.log_in(username);
    console.log({ auth_token });
    expect(auth_token).to.be.a("string");

    const voteName = "testVote";
    const voteDescription = "testDescription";

    const res = await can.create_vote(auth_token, voteName, voteDescription);
  });

  it("Anyone can list votes", async () => {
    const can = await setUpCan();

    const res = await can.get_votings();
    console.log( res );
  });

  it("Registered user can vote", async () => {
    const password = "test";
    const selectedImage = "banana";

    const query = await setUpCan();
    const salt = await query.get_user_salt(username);

    const saltUserPasswd = hashUserData(username, password, selectedImage, salt)
      .slice(2)
      .slice(0, 32);

    const userIdentity = Secp256k1KeyIdentity.generate(
      Buffer.from(saltUserPasswd)
    );
    const can = await setUpCan(userIdentity);

    console.table({
      username,
      saltUserPasswd,
      selectedImage,
      salt,
    });

    const token = await can.log_in(username);
    const votings = await can.get_votings();

    const res = await can.vote_at(token, votings[0][0], {"Pro": null});
    console.log( res );
    expect(res.pro).to.be.eql(1n);
  });
});
