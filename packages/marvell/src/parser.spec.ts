import { describe, expect, it } from "vitest";
import { gunzipSync } from "node:zlib";
import { MarvellAttestationParser } from "./parser";
import { base64CompressedData } from "../test/fixtures";

// ECC
const eccData = `H4sIAAAAAAAAAGNgAANmBgYOBwYGdgUIl/0ZhFZaxsAIlONgngIVUwYqbYDIMTAyATGYwcwAYYFEGECYEchjZIExWGHSbDARdpgIB4zBBZNKhjHghiZBRUCOZGhILCiIz06tZBg4APZlQ4qBWXKyhYFhmnlKWlpKUkqKeaKlkYlBUkqyQWKqYWKKoZGJhZmRpYVBcqK5sVFyqqmJiVmaYXKKQZI5SG1iknGqsWFKkpGlqYVRokFSkoVJcpJhirlFiqF5khnQaLOkVDMj08RU41RzkxRjSzPLNMMU41QDC3NjC/Nk86QUoDsSge4ABbIjkF0MCp/GjcsZGARAwaTgULr46UI7Y84Qg2lae3adfm90vbjIpK299ZITx2RN+xNZQHUgv3BA/cTUwMBYAtJHwO//gepKiVRXRqS6ciLVVRCprpJIdQ3EqAMGLUiNI4uHUWDm4rJ2i9nf7um/Xi86I5Y5qKB7H5O29hyfvN8Vd+qv+vEqLF6Vx/YueCOrfqIUr9M2gUbP3u2dB6aH7WDkulUANEiRARxfjPOBdBsDJHUzCUAZjDwwRiqY0QDNSSAGPCukQBnAfImWF5mJyIsMsLzICMuLDLC8yAjLi4ywvMiAkRcZYXkRZM9oXsSeF7tG8yKyumGRF0Guw5EXGRtLNh6VepC1cUnAzPfnr3rYnfKe9/Dzyeb6y99ebEyz/XdD+WXTf/6G9m1P/wgq9nwRnbt1mu36kzMTS644NlXKR//pnSC7zMNKbhWDz7KJHNGbddqu8ksuuusdwyPmfzD9WMKXwq1Skx8a9jaeTec/Xte8eqftROmVG58+LQv73ainq7wzp/naxEdOYc/annt/jHryjO+M9puZXKn/lFNyJX7rLrkWUff2+BsZpltmDziT+E49UtRVOpqpy7Cve6qesGrgh+6P5xlaFz4v/p3d6ChbWr9z3XnZmgXXnuw8IpTELXA+4Wn7lgnSgf0/DKx7JofqTbc8U3mw/HnZSdc1GzZNf63s8l3lTrrG/wcAkcwjK0AIAAA=`;

// RSA
const rsaData = `H4sIAAAAAAAAAGNgAANmBga2JgYG1iwIV56LgREoxgFlMzCoAuXCIHIMjEDFjGAGjGBkAhIgzAjkMbLARFlhImwwEXaYCAeMwQWTSoYxmGFSSTArQCINiQUF8dmplQwDB8C-bDA2SDY0NUg2Nk8zME1JM0ixSDMxT00zSTQzNjdITkxKTE4xMU02NrQ0NkiyBALDZAOjJBNjExNzQ_PEZJMk8ySjVMtEE4MUMwNjk8Rk07Q0Q9MkS1OggKG5mYVpMtAwAxNTA6O0JMNks7REA1NjoMpkQzNTkyRTi6Q0Y2OgOxKB7gAGMqcHkF0MCp_wq6kMDAKgYFKoePjiiecp5W_yVixuzd2X1xS9suZ872vEoHpFp7K99rIyUB3ILxxQPzE1MDCWgPQR8Pt_oLpSItWVEamunEh1FUSqqyRSXQMx6oBBqwBK04_8_17ZuYzhX09mxcvFs77Umll73XzD8rRuvaiqzD2j6m21d7iUrl_dNadPOLTltJvusrQqmYPnW3g-8luX89-41ryidYrsycmzy459PXox-qau-55zRw7-7i1c-s9z8dFp67oevXopNPHF0llxy70e7VDK2aB0f9n_-fvttl-duOjgBC739pN3_rwOWmzr0mt8euP6pNt7hTmPSHpM6zZ0ZXRvWfTpYJBSfE577euzC9oOvJN4vX3iuplObyXScv5Nadz_YGrkmzLNkNKXKvUVu36F7Cyzi0greNJZ0qc6uTZTQetGeaPhU9e_ZhzbrxfxXJSqu2L6uCH5nrvBj8meey64lU1Iat8W8Kh2vqBNtj_z1shjHYUzpCzEfgqtCDFglThyk49b9cHrR_sMCpftsX7LevTH47AIjp9LXZu2LhRdXz7tccQuV82wSlbnlUoNtbz_GZYb79k9cQJv-5xpy_JZHF6c_NkX_uXjmcrd5640Lamu6J0Q-sPSzU3t_m-DxueBc7c_dD23UPrPg2-3Y5KcXj5I4qtoVnAvexCVr2i5XsXjg4X4tXLbVRP9JN_3Nrxqilq8-Mhyz12vV8_408P7svz1zUk3s67_qDa2Zd62QnTij9U2a9w-v3JrXRd0QWnlp4tyU8TXvn4hcPdYdW7y7Zqe0y-fvl0tcuf1rNvTSj56JYdqc9wQ2HU6eK6pqvPVv9N3hVi0TIotSwemA0UGcHYTAFKMSkCCmRGShiDCoEKOoY0BUlQxCUAZjDwwRiqY0QAtH0EMZphUCkTEqne7S4vik9vzD7-70HlHkYs_uslS_H6wo35kzebJagt35N35-itxftG55ZLBwmmGAWwbD8gdZLmduPa0wtW6WF-H95tE1B6pcc_92Pv5a8zqwC8bzaMPVV59Ed-aU3rsxqmCh8vedz_4tPT66puMGv_5PWL0K6Y9WM9ZPE35gdLdffUH8x59k0_6fGviPMdlAW3vLKdzfdol_9eds--pgcRb348XnHK7LE9WMNccYWLr_mswxeJ57zd3a83Idc8PHLar3zPPyDbhu8Nm1xxHmZ8z3G990w_bpxr1sdDlZKXlBj2_9tUmkZ_-iKnyOL8NEuw7YKHjxqI7RffXjs_LTzDk_lt5rPYQy_XfQjMAUrOFtoIGAAA`;

describe("Marvell:Parser", () => {
  it("should correctly parse ECC data", async () => {
    const parser = new MarvellAttestationParser();
    const result = parser.parse(Buffer.from(eccData, "base64"));
    expect(result.attestationData.firstKey.attributes.OBJ_ATTR_KEY_TYPE).toBe("CKK_EC");
  });

  it("should correctly parse RSA data", () => {
    const parser = new MarvellAttestationParser();
    const result = parser.parse(Buffer.from(rsaData, "base64"));
    expect(result.attestationData.firstKey.attributes.OBJ_ATTR_KEY_TYPE).toBe("CKK_RSA");
    expect(result.attestationData.secondKey).toBeFalsy();
  });
});

/** Copies data into a larger buffer and returns a view of it at a non-zero byte offset. */
function embed(data: Uint8Array, offset: number): Uint8Array<ArrayBuffer> {
  const buffer = new Uint8Array(offset + data.length + 7).fill(0xa5);
  buffer.set(data, offset);
  return buffer.subarray(offset, offset + data.length);
}

function shared(data: Uint8Array): SharedArrayBuffer {
  const buffer = new SharedArrayBuffer(data.length);
  new Uint8Array(buffer).set(data);
  return buffer;
}

describe("Marvell:Parser byte inputs", () => {
  const compressed = Buffer.from(base64CompressedData, "base64");
  const raw = gunzipSync(compressed);
  const expected = new MarvellAttestationParser().parse(Uint8Array.from(raw));

  it.each([
    ["raw", raw],
    ["gzipped", compressed],
  ])("parses a %s view with a non-zero byte offset", (_, data) => {
    const result = new MarvellAttestationParser().parse(embed(data, 13));
    expect(result.attestationData).toEqual(expected.attestationData);
    expect(Buffer.from(result.signedData).equals(Buffer.from(expected.signedData))).toBe(true);
    expect(Buffer.from(result.signature).equals(Buffer.from(expected.signature))).toBe(true);
  });

  it("parses a DataView with a non-zero byte offset", () => {
    const view = embed(raw, 5);
    const result = new MarvellAttestationParser().parse(new DataView(view.buffer, view.byteOffset, view.byteLength));
    expect(result.attestationData).toEqual(expected.attestationData);
  });

  it.each([
    ["raw", raw],
    ["gzipped", compressed],
  ])("parses %s bytes in a SharedArrayBuffer", (_, data) => {
    const result = new MarvellAttestationParser().parse(shared(data) as unknown as ArrayBuffer);
    expect(result.attestationData).toEqual(expected.attestationData);
  });

  it("decodes invalid UTF-8 in text attributes with replacement characters", () => {
    const label = expected.attestationData.firstKey.attributes.OBJ_ATTR_LABEL;
    expect(label).toBe("app_key");
    const corrupted = Uint8Array.from(raw);
    const offset = Buffer.from(corrupted).indexOf("app_key");
    corrupted[offset + 3] = 0xff;
    const result = new MarvellAttestationParser().parse(corrupted);
    expect(result.attestationData.firstKey.attributes.OBJ_ATTR_LABEL).toBe("app�key");
  });
});
