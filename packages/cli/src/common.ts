import { PublicKey, X509Certificate } from '@peculiar/x509';

export const TAB = '  ';

export async function printPublicKey(publicKey: PublicKey, tab = '') {
  console.log(`${tab}Public Key:`);
  let alg = 'unknown';
  switch (publicKey.algorithm.name) {
    case 'RSASSA-PKCS1-v1_5': {
      alg = 'RSA';
      const key = await publicKey.export();
      const rsaAlg = key.algorithm as RsaKeyAlgorithm;
      alg += ` (${rsaAlg.modulusLength})`;
      break;
    }
    case 'ECDSA': {
      alg = 'EC';
      const ecAlg = publicKey.algorithm as EcKeyAlgorithm;
      alg += ` (${ecAlg.namedCurve})`;
      break;
    }
  }

  console.log(`${tab}${TAB}Algorithm: ${alg}`);
  const keyIdSha1 = await publicKey.getKeyIdentifier();
  const keyIdSha256 = await publicKey.getKeyIdentifier('SHA-256');
  console.log(`${tab}${TAB}Key ID:`);
  console.log(
    `${tab}${TAB}${TAB}SHA-1:   ${Buffer.from(keyIdSha1).toString('hex')}`,
  );
  console.log(
    `${tab}${TAB}${TAB}SHA-256: ${Buffer.from(keyIdSha256).toString('hex')}`,
  );
}

function formatDate(date: Date): string {
  return date.toISOString().replace(/T.*/, '');
}

/**
 * Prints the common details of a certificate.
 *
 * @param cert - The X509Certificate object.
 * @param tab - The tab string for indentation.
 */
async function printCommonCertificateDetails(
  cert: X509Certificate,
  tab: string,
) {
  const sha1 = await cert.getThumbprint('SHA-1');
  const sha256 = await cert.getThumbprint('SHA-256');
  console.log(`${tab}${TAB}SHA-1:   ${Buffer.from(sha1).toString('hex')}`);
  console.log(`${tab}${TAB}SHA-256: ${Buffer.from(sha256).toString('hex')}`);
}

/**
 * Prints a short summary of the certificate.
 *
 * @param cert - The X509Certificate object.
 * @param label - The label for the certificate.
 * @param tab - The tab string for indentation.
 */
export async function printCertificateShort(
  cert: X509Certificate,
  label = 'Certificate',
  tab = '',
) {
  if (label) {
    console.log(`${tab}${label}:`);
  }
  console.log(`${tab}${TAB}Subject: ${cert.subject}`);
  console.log(`${tab}${TAB}Issuer:  ${cert.issuer}`);
  console.log(`${tab}${TAB}Serial:  ${cert.serialNumber}`);
  console.log(`${tab}${TAB}Expires: ${formatDate(cert.notAfter)}`);

  await printCommonCertificateDetails(cert, tab);
}

/**
 * Prints the full details of the certificate.
 *
 * @param cert - The X509Certificate object.
 * @param label - The label for the certificate.
 * @param tab - The tab string for indentation.
 */
export async function printCertificate(
  cert: X509Certificate,
  label = 'Certificate',
  tab = '',
) {
  const details = cert.toString('text').split('\n');

  if (!label) {
    // Remove the first line which is the certificate header
    details.shift();
    // Remove tabs from the beginning of each line
    details.map((line) => line.replace(new RegExp(`^${TAB}`), ''));
  } else {
    details[0] = `${tab}${label}:`;
    details.map((line) => `${tab}${line}`);
  }

  console.log(details.join('\n'));

  await printCommonCertificateDetails(cert, tab);
}
