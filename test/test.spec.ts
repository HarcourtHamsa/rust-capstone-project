import { readFileSync } from "fs";

describe("Evaluate submission", () => {
  let txid: string;
  let minerInputAddress: string;
  let minerInputAmount: number;
  let traderInputAddress: string;
  let traderInputAmount: number;
  let minerChangeAddress: string;
  let minerChangeAmount: number;
  let fee: number;
  let blockHeight: number;
  let blockHash: string;
  let tx: any;

  it("should read data from out.txt and perform sanity checks", () => {
    // read txid from out.txt
    const data = readFileSync("out.txt", "utf8").trim().split("\n");

    console.log({
      data,
    });

    expect(data.length).toBe(10);

    txid = data[0].trim();
    expect(txid).toBeDefined();
    expect(txid).toHaveLength(64);

    minerInputAddress = data[1].trim();
    expect(minerInputAddress).toBeDefined();

    minerInputAmount = parseFloat(data[2].trim());
    expect(minerInputAmount).toBeDefined();
    expect(minerInputAmount).toBeGreaterThan(0);

    traderInputAddress = data[3].trim();
    expect(traderInputAddress).toBeDefined();

    traderInputAmount = parseFloat(data[4].trim());
    expect(traderInputAmount).toBeDefined();
    expect(traderInputAmount).toBeGreaterThan(0);

    minerChangeAddress = data[5].trim();
    expect(minerChangeAddress).toBeDefined();

    minerChangeAmount = parseFloat(data[6].trim());
    expect(minerChangeAmount).toBeDefined();
    expect(minerChangeAmount).toBeGreaterThan(0);

    fee = parseFloat(data[7].trim());
    expect(fee).toBeDefined();
    if (fee < 0) fee = -fee;
    expect(fee).toBeGreaterThan(0);

    blockHeight = parseInt(data[8].trim());
    expect(blockHeight).toBeDefined();
    expect(blockHeight).toBeGreaterThan(0);

    blockHash = data[9].trim();
    expect(blockHash).toBeDefined();
    expect(blockHash).toHaveLength(64);
  });

  it("should get transaction details from node", async () => {
    const RPC_USER = "alice";
    const RPC_PASSWORD = "password";
    const RPC_HOST = "http://127.0.0.1:18443/wallet/Miner";

    const response = await fetch(RPC_HOST, {
      method: "post",
      body: JSON.stringify({
        jsonrpc: "1.0",
        id: "curltest",
        method: "gettransaction",
        params: [txid, null, true],
      }),
      headers: {
        "Content-Type": "text/plain",
        Authorization:
          "Basic " +
          Buffer.from(`${RPC_USER}:${RPC_PASSWORD}`).toString("base64"),
      },
    });
    const result = (await response.json()).result as any;
    expect(result).not.toBeNull();
    expect(result.txid).toBe(txid);

    tx = result;
  });

  it("should have the correct block height", () => {
    expect(tx.blockheight).toBe(blockHeight);
  });

  it("should have the correct block hash", () => {
    expect(tx.blockhash).toBe(blockHash);
  });

  it("should have the correct number of vins", () => {
    expect(tx.decoded.vin.length).toBe(1);
  });

  it("should have the correct number of vouts", () => {
    expect(tx.decoded.vout.length).toBe(2);
  });

  it("should have the correct miner output", () => {
    const minerOutput = tx.decoded.vout.find((o: any) =>
      o.scriptPubKey.address.includes(minerChangeAddress)
    );
    expect(minerOutput).toBeDefined();
    expect(minerOutput.value).toBe(minerChangeAmount);
  });

  it("should have the correct trader output", () => {
    const traderOutput = tx.decoded.vout.find((o: any) =>
      o.scriptPubKey.address.includes(traderInputAddress)
    );
    expect(traderOutput).toBeDefined();
    expect(traderOutput.value).toBe(traderInputAmount);
  });

  it("should have the correct fee", () => {
    expect(Math.abs(tx.fee)).toBe(fee);
  });
});
