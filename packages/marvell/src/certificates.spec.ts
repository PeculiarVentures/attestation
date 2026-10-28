import { describe, expect, it } from "vitest";
import * as x509 from "@peculiar/x509";
import { certificateId } from "./certificates";
import { certChain } from "../test/fixtures";

describe("Marvell:certificateId", () => {
  it("returns the DER as lowercase hex", () => {
    for (const cert of x509.PemConverter.decode(certChain).map((der) => new x509.X509Certificate(der))) {
      const id = certificateId(cert);
      expect(id).toMatch(/^[0-9a-f]+$/);
      expect(id).toBe(Buffer.from(cert.rawData).toString("hex"));
    }
  });
});
