import type { X509Certificate } from "@peculiar/x509";
import { Convert } from "pvtsutils";

export class CertificateLimitError extends Error {}

export function certificateId(cert: X509Certificate): string {
  return Convert.ToHex(cert.rawData);
}

/** Bounds preparation before allocating DER identities; both profiles use the same input limits. */
export function prepareCertificates(certs: readonly X509Certificate[], anchors: readonly X509Certificate[]): X509Certificate[] {
  if (certs.length + anchors.length > 64) {
    throw new CertificateLimitError("Too many certificates. At most 64 input certificates and trust anchors are supported in total.");
  }
  const unique = new Map<string, X509Certificate>();
  let bytes = 0;
  for (const cert of [...certs, ...anchors]) {
    bytes += cert.rawData.byteLength;
    if (bytes > 1024 * 1024) {
      throw new CertificateLimitError("Certificate data exceeds the 1048576-byte limit.");
    }
    const id = certificateId(cert);
    if (!unique.has(id)) unique.set(id, cert);
  }
  return [...unique].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([, cert]) => cert);
}
