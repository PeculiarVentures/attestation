import assert from 'node:assert';
import * as zlib from 'node:zlib';
import { AttestationVerificationFailure } from '@peculiar/attestation-common';
import * as x509 from '@peculiar/x509';
import { MarvellAttestationValidator } from './validator';
import { OWNER_ROOT_CERT } from './certs';

const base64CompressedData =
  'H4sIAAAAAAAAAGNgAANmBgYOBwYGdgUIl/0ZhFZaxsAIlONgngIVUwYqbYDIMTAyATGYwcwAYYFEGECYEchjZIExWGHSbDARdpgIB4zBBZNKhjHghiZBRUCOZGhILCiIz06tZBg4APZlQ4qBWXKyhYFhmnlKWlpKUkqKeaKlkYlBUkqyQWKqYWKKoZGJhZmRpYVBcqK5sVFyqqmJiVmaYXKKQZI5SG1iknGqsWFKkpGlqYVRokFSkoVJcpJhirlFiqF5khnQaLOkVDMj08RU41RzkxRjSzPLNMMU41QDC3NjC/Nk86QUoDsSge4ABbIjkF0MCp/GjcsZGARAwaTgULr46UI7Y84Qg2lae3adfm90vbjIpK299ZITx2RN+xNZQHUgv3BA/cTUwMBYAtJHwO//gepKiVRXRqS6ciLVVRCprpJIdQ3EqAMGLUiNI4uHUWDm4rJ2i9nf7um/Xi86I5Y5qKB7H5O29hyfvN8Vd+qv+vEqLF6Vx/YueCOrfqIUr9M2gUbP3u2dB6aH7WDkulUANEiRARxfjPOBdBsDJHUzCUAZjDwwRiqY0QDNSSAGPCukQBnAfImWF5mJyIsMsLzICMuLDLC8yAjLi4ywvMiAkRcZYXkRZM9oXsSeF7tG8yKyumGRF0Guw5EXGRtLNh6VepC1cUnAzPfnr3rYnfKe9/Dzyeb6y99ebEyz/XdD+WXTf/6G9m1P/wgq9nwRnbt1mu36kzMTS644NlXKR//pnSC7zMNKbhWDz7KJHNGbddqu8ksuuusdwyPmfzD9WMKXwq1Skx8a9jaeTec/Xte8eqftROmVG58+LQv73ainq7wzp/naxEdOYc/annt/jHryjO+M9puZXKn/lFNyJX7rLrkWUff2+BsZpltmDziT+E49UtRVOpqpy7Cve6qesGrgh+6P5xlaFz4v/p3d6ChbWr9z3XnZmgXXnuw8IpTELXA+4Wn7lgnSgf0/DKx7JofqTbc8U3mw/HnZSdc1GzZNf63s8l3lTrrG/wcAkcwjK0AIAAA=';
const certChain = [
  '-----BEGIN CERTIFICATE-----',
  'MIIDbTCCAlWgAwIBAgIBATANBgkqhkiG9w0BAQsFADB2MUQwCQYDVQQGEwJVUzAJ',
  'BgNVBAgMAkNBMA0GA1UECgwGQ2F2aXVtMA0GA1UECwwGTjNGSVBTMA4GA1UEBwwH',
  'U2FuSm9zZTEuMCwGA1UEAwwlSFNNOjUuM0cxOTUzLUlDTTAwMTIyNSwgZm9yIEZJ',
  'UFMgbW9kZTAeFw0yNDA0MTUxODE5MTVaFw0zNDA0MTMxODE5MTVaMH4xRDAJBgNV',
  'BAYTAlVTMAkGA1UECAwCQ0EwDQYDVQQKDAZDYXZpdW0wDQYDVQQLDAZOM0ZJUFMw',
  'DgYDVQQHDAdTYW5Kb3NlMTYwNAYDVQQDDC1IU006NS4zRzE5NTMtSUNNMDAxMjI1',
  'OlBBUlROOjEsIGZvciBGSVBTIG1vZGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw',
  'ggEKAoIBAQD1PSdIEujySEmKoLHT85w73xR9HOn4Bf1rRWoI8mD3WX9wrV2zZ3xA',
  'i4PeTERvNe4AKPNhaoriCxbMdw3igPsJUGxJvit1610pi4bxM72L/BqtGGNJLcWo',
  'qSKjyLS5ezwcoLAcP0+LwObtpJ9HMOsWXv6s3yKDLVclHzygTkB6Mon85yrzk4D3',
  'X/mDUtsOLvbCMLEXoo1jSyb2cMYTqo6hBTPkLzO6svZfn8su0r1qvASUg/+zUCfw',
  'og1LPRaSqZRpzFoQ84aIiBeKfqFM5to0s1r2vhqf2lg6J5Ik+I2PMxOD52/OttJv',
  'dg5oRnJgywj10Xt3gI0CKZjJM2fDEFEJAgMBAAEwDQYJKoZIhvcNAQELBQADggEB',
  'AGgMK5LlGYQxg5T5LeW3/3nxHhIlHyi8R8Vd5tG+o+SufVFm8Ti8YMf+Yemfrt8g',
  'wUgo1HGcrE/QKhRoj+46qHwJ1MRnFr4W4kKk7LSro9cnFuhxTun0hUtEEfn96D3/',
  '8FArSHsI5qHhxz1l6Gu+UCVkgTNXIetq2vmbScVt0RPbrh737CNhupQMlQzhv8j0',
  'jR2/GZHVFKo3uaAJ7nb+KHhKW6kygU2kmGPOtr6vQrh+86uCI912eiySRRhMBQAx',
  'Nvl/NMlPEg91Mthv5Ibmtt0CFgHma4bh7yt2h6YTcDuoMo6b4n1fRtQE3fWJPtAJ',
  'K/MmRd+7MYpzn1fyUcAEcIY=',
  '-----END CERTIFICATE-----',
  '-----BEGIN CERTIFICATE-----',
  'MIIDfDCCAmQCAQEwDQYJKoZIhvcNAQELBQAwgZExCzAJBgNVBAYTAlVTMRMwEQYD',
  'VQQIDApDYWxpZm9ybmlhMREwDwYDVQQHDAhTYW4gSm9zZTEVMBMGA1UECgwMQ2F2',
  'aXVtLCBJbmMuMRcwFQYDVQQLDA5MaXF1aWRTZWN1cml0eTEqMCgGA1UEAwwhbG9j',
  'YWxjYS5saXF1aWRzZWN1cml0eS5jYXZpdW0uY29tMB4XDTIwMDYwNTE2MTcyNloX',
  'DTMwMDYwMzE2MTcyNlowdjFEMAkGA1UEBhMCVVMwCQYDVQQIDAJDQTANBgNVBAoM',
  'BkNhdml1bTANBgNVBAsMBk4zRklQUzAOBgNVBAcMB1Nhbkpvc2UxLjAsBgNVBAMM',
  'JUhTTTo1LjNHMTk1My1JQ00wMDEyMjUsIGZvciBGSVBTIG1vZGUwggEiMA0GCSqG',
  'SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCw8HewzUImNdhT3i0DIqAYGZ4Rg0IgfqSI',
  'RFL65x4H7a19fFT/V75s6J1sajDXAO9CuPRYCniMytTBEBs0eTfkqPvwXVpGpLfT',
  'GNHDH4H2rfVFwQw2YriAnNj+dLKS3Gljy7JQrzwYhQTvaQScfWG6lpfm5VZshyuF',
  'sST0Xvkt5DT2NJO3E0ok6ViBDnozNc1FCsG22tXekLOHk4cUJcLwi5vAWdEm9rU0',
  '2GJ+igEUnbQvzXteMBjGE+vaRHEyfePf0N7GMYr0rUlaDSr074oDbxWE5bka2W22',
  'kanpZLx2RhDy67+63kkQTttcWhTHPxDiXTPTLkCi3a8cVo4U05wpAgMBAAEwDQYJ',
  'KoZIhvcNAQELBQADggEBAC1oSr+Gv45ADbfGIpMzYfmmeJ+kP4vVTFR9TWMYMQPM',
  'ZNQO55TbKhYaozqA9TxqHmWTRRPu5sC6zYSJ1IyWsPp2ZtUoeqZwlBghhcilC85d',
  'SBG3nNof0/To4UrCzWvmw+WVZfJrQqyBXIH9X1C63KE9HYwoMNkUIT5nKUYlQWy0',
  'is4Tgj8hZo4h2o/giDZtIEHrBPp9M4s2ZPOfig/PpDcXAKJwwRKiYrvUw+2rKygk',
  'NM92QcsHyUBVCSZsUe1WIgPuaatG6tou5Jcd7kFyujd6K5A+ZxRF1JD7cX/1JZTg',
  'rPZ+t4ZyR41E1SuO6Bv3MC4nPfUuminIu2sw2Za+PXE=',
  '-----END CERTIFICATE-----',
  '-----BEGIN CERTIFICATE-----',
  'MIID0TCCArmgAwIBAgIUDPPxhVEiVTS9cggqCLhJ5YMYxsEwDQYJKoZIhvcNAQEL',
  'BQAwaDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1Nb3VudGFp',
  'biBWaWV3MRMwEQYDVQQKDApHb29nbGUgSW5jMR8wHQYDVQQDDBZIYXdrc2JpbGwg',
  'Um9vdCB2MSBwcm9kMB4XDTI0MDQxNTE4MjA0NVoXDTMwMDEwMTAwMDAwMFowfjFE',
  'MAkGA1UEBhMCVVMwCQYDVQQIDAJDQTANBgNVBAoMBkNhdml1bTANBgNVBAsMBk4z',
  'RklQUzAOBgNVBAcMB1Nhbkpvc2UxNjA0BgNVBAMMLUhTTTo1LjNHMTk1My1JQ00w',
  'MDEyMjU6UEFSVE46MSwgZm9yIEZJUFMgbW9kZTCCASIwDQYJKoZIhvcNAQEBBQAD',
  'ggEPADCCAQoCggEBAPU9J0gS6PJISYqgsdPznDvfFH0c6fgF/WtFagjyYPdZf3Ct',
  'XbNnfECLg95MRG817gAo82FqiuILFsx3DeKA+wlQbEm+K3XrXSmLhvEzvYv8Gq0Y',
  'Y0ktxaipIqPItLl7PBygsBw/T4vA5u2kn0cw6xZe/qzfIoMtVyUfPKBOQHoyifzn',
  'KvOTgPdf+YNS2w4u9sIwsReijWNLJvZwxhOqjqEFM+QvM7qy9l+fyy7SvWq8BJSD',
  '/7NQJ/CiDUs9FpKplGnMWhDzhoiIF4p+oUzm2jSzWva+Gp/aWDonkiT4jY8zE4Pn',
  'b8620m92DmhGcmDLCPXRe3eAjQIpmMkzZ8MQUQkCAwEAAaNdMFswCQYDVR0TBAIw',
  'ADAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0OBBYEFDM5ST3birLQgwqR4mhM2OO/nBUk',
  'MB8GA1UdIwQYMBaAFDHoUt/hSfgSe3xu506Repd1vKiuMA0GCSqGSIb3DQEBCwUA',
  'A4IBAQBaeci2u9m3/kyIteCAkiTpKK5CXfuqLOLEblGJIE0xDT18mfFfxe334JjO',
  'EI6noB0xfFzcmoS7zoEG/92p2U4kz8fpP4Hdqq4gYrdWMVhnsZ9ON7ljn0H1kv33',
  'puQLK4E9fZqHZnWxi3kkTErsN/rOZb525Tzw/0kBaLZ5WJWVKLViErIEB59DGync',
  'JaUILrGCB6ryHatNNMrJAha/GvRGHAk1xXn+GsepGU8b/P8AXI/SFiQtHyJg81Q0',
  'e8PUxCduOhfKBMXX6Vvg+w1Hmm9+50xWp1RJQB4bvTahsQHvOhwcuSxPZ+xAVNWQ',
  'nhhURGiP9oBHS4DSd1gzvXqJfdQy',
  '-----END CERTIFICATE-----',
  '-----BEGIN CERTIFICATE-----',
  'MIIDyTCCArGgAwIBAgIUIkfneEvERiM2iwsq9OuFlh7b00gwDQYJKoZIhvcNAQEL',
  'BQAwaDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1Nb3VudGFp',
  'biBWaWV3MRMwEQYDVQQKDApHb29nbGUgSW5jMR8wHQYDVQQDDBZIYXdrc2JpbGwg',
  'Um9vdCB2MSBwcm9kMB4XDTI0MDQxNTE4MTkwOVoXDTMwMDEwMTAwMDAwMFowdjFE',
  'MAkGA1UEBhMCVVMwCQYDVQQIDAJDQTANBgNVBAoMBkNhdml1bTANBgNVBAsMBk4z',
  'RklQUzAOBgNVBAcMB1Nhbkpvc2UxLjAsBgNVBAMMJUhTTTo1LjNHMTk1My1JQ00w',
  'MDEyMjUsIGZvciBGSVBTIG1vZGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK',
  'AoIBAQCw8HewzUImNdhT3i0DIqAYGZ4Rg0IgfqSIRFL65x4H7a19fFT/V75s6J1s',
  'ajDXAO9CuPRYCniMytTBEBs0eTfkqPvwXVpGpLfTGNHDH4H2rfVFwQw2YriAnNj+',
  'dLKS3Gljy7JQrzwYhQTvaQScfWG6lpfm5VZshyuFsST0Xvkt5DT2NJO3E0ok6ViB',
  'DnozNc1FCsG22tXekLOHk4cUJcLwi5vAWdEm9rU02GJ+igEUnbQvzXteMBjGE+va',
  'RHEyfePf0N7GMYr0rUlaDSr074oDbxWE5bka2W22kanpZLx2RhDy67+63kkQTttc',
  'WhTHPxDiXTPTLkCi3a8cVo4U05wpAgMBAAGjXTBbMAkGA1UdEwQCMAAwDgYDVR0P',
  'AQH/BAQDAgWgMB0GA1UdDgQWBBSVk83KWA3bMxEdHl3eEfwQ7bMI7TAfBgNVHSME',
  'GDAWgBQx6FLf4Un4Ent8budOkXqXdbyorjANBgkqhkiG9w0BAQsFAAOCAQEAJ9O9',
  '37CpUNhwBWLDB1kXckmbAF58IIjHhLCElaUCwv4SR7ZggeCYJoCyjMTclymKfwlh',
  'vs7qYqSLbb3Jll6VrWixpB/MML7QhRp7Lnz+C4H8y+qIXm4gYRrl7kel2+bfn8Gn',
  '6nUhELWXNRTnb5ex7hT7Cw/Jxxm+ftO5gLftuzMLAOvD4hYMNeaaafDGQ9TbMbUe',
  '8CAo9XJNndSqWLdDTprNAlg8BGpwQKxZDqt4teVWeAwlU7aGXaVmlU9QYqvLkLC8',
  'hAOBZ8zSXcRds6HvpNLCObE590LrXI47yYMW7xe8JPLWgWcIX7oCmHShNR9HesTS',
  'mxHK9nKyJ1txoluMqg==',
  '-----END CERTIFICATE-----  ',
].join('\n');

describe('Marvell:Validator', () => {
  it('should correctly validate the attestation data', async () => {
    const validator = new MarvellAttestationValidator();
    const data = Buffer.from(base64CompressedData, 'base64');
    const pemChain = x509.PemConverter.decode(certChain);
    const certs = pemChain.map((cert) => {
      return new x509.X509Certificate(cert);
    });
    const result = await validator.validate(data, certs);
    assert.strictEqual(
      result.status,
      true,
      (result as AttestationVerificationFailure).error?.message,
    );
    assert.strictEqual(
      result.signer.subjectName.getField('CN')[0],
      'HSM:5.3G1953-ICM001225:PARTN:1, for FIPS mode',
    );
    assert.strictEqual(result.chain.length, 3);
  });

  it('should fail validation with corrupted signature', async () => {
    const validator = new MarvellAttestationValidator();
    const data = Buffer.from(base64CompressedData, 'base64');
    const unpackedData = zlib.gunzipSync(data);

    // Corrupt the data by modifying a byte
    const corruptedData = unpackedData;
    corruptedData[corruptedData.length - 1] ^= 0xff; // Flip the last byte

    const pemChain = x509.PemConverter.decode(certChain);
    const certs = pemChain.map((cert) => {
      return new x509.X509Certificate(cert);
    });
    const result = await validator.validate(corruptedData, certs);
    assert.strictEqual(result.status, false);
  });

  it('should throw an error if initialized with a single trusted certificate', () => {
    assert.throws(() => {
      new MarvellAttestationValidator({
        trustedCerts: [OWNER_ROOT_CERT],
      });
    });
  });
});
