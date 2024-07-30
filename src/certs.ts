import * as x509 from '@peculiar/x509';

const OWNER_ROOT_CERT_PEM = [
  '-----BEGIN CERTIFICATE-----',
  'MIIDjTCCAnWgAwIBAgIBAzANBgkqhkiG9w0BAQsFADBoMQswCQYDVQQGEwJVUzEL',
  'MAkGA1UECAwCQ0ExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxEzARBgNVBAoMCkdv',
  'b2dsZSBJbmMxHzAdBgNVBAMMFkhhd2tzYmlsbCBSb290IHYxIHByb2QwHhcNMTcw',
  'NzAxMDAwMDAwWhcNMzAwMTAxMDAwMDAwWjBoMQswCQYDVQQGEwJVUzELMAkGA1UE',
  'CAwCQ0ExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxEzARBgNVBAoMCkdvb2dsZSBJ',
  'bmMxHzAdBgNVBAMMFkhhd2tzYmlsbCBSb290IHYxIHByb2QwggEiMA0GCSqGSIb3',
  'DQEBAQUAA4IBDwAwggEKAoIBAQCsLqhiiSGgcJLfsI7Dk00mONulol9rHm2obCyD',
  '1lua+AKg+LAW+1zauZu5i028FSbgDk8vtSBDHDF+XsFnqTbIGV7Ctai2lnaQe1UV',
  'TVMWEPBi1diYGceeDrJpJqPz2aXTcIghrGISeyq+IC4z25uQp7G/D8AResKYqYxN',
  'NqcfZlMIk0s6Eh4aPyvCXYtLl9QXD0GDJ6nz4NmC+Fw31B5d5Kg9WXxDZOYC1zU5',
  '9JXbdxxzeC/EJo1k1AHghto/J8edvTIl5NQ0ahOHKoUZzhhDRsVBioFmymVuwaHO',
  'cXTUsHe3NTkNyeLIfoFpsQQ4XcH9kjO67YXTkdCWeNYw/FYZAgMBAAGjQjBAMA8G',
  'A1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBQx6FLf4Un4',
  'Ent8budOkXqXdbyorjANBgkqhkiG9w0BAQsFAAOCAQEAjxKOjnr7WYKoD+a+uAld',
  'F8iOwTrHpFLUDS6sqFyx9FLut8Qlmioy/JE9uima7cjeH3U5VBbRcnTglaDiQTac',
  '+JXCIRApEl9N0bDhoVvFeTzRI8nJdMJCWPobNXV3MHpYsgfgzewh4lFUWQghvscF',
  '325VgSEN0a1hgXcnPr05gd+9kTI9zF3r3vyncyYvzYincGX0NQaz1gJW4brm1W+w',
  'TbWVy8Y0o6c1eZm7v8sHoNSg3vIs6JsnQ8bAXK5i2qO/AXZQu25wH1aPQct8QdGw',
  'x2JBsjEjmWpHuBDAXPCesD5cu9UzzDgcpdwmi7Xidl74kj3f/HgrOeimRdOb8lG5',
  '/A==',
  '-----END CERTIFICATE-----',
].join('\n');
export const OWNER_ROOT_CERT = new x509.X509Certificate(OWNER_ROOT_CERT_PEM);

const MANUFACTURER_ROOT_CERT_PEM = [
  '-----BEGIN CERTIFICATE-----',
  'MIIDoDCCAogCCQDA6q30NN7cFzANBgkqhkiG9w0BAQsFADCBkTELMAkGA1UEBhMC',
  'VVMxEzARBgNVBAgMCkNhbGlmb3JuaWExETAPBgNVBAcMCFNhbiBKb3NlMRUwEwYD',
  'VQQKDAxDYXZpdW0sIEluYy4xFzAVBgNVBAsMDkxpcXVpZFNlY3VyaXR5MSowKAYD',
  'VQQDDCFsb2NhbGNhLmxpcXVpZHNlY3VyaXR5LmNhdml1bS5jb20wHhcNMTUxMTE5',
  'MTM1NTI1WhcNMjUxMTE2MTM1NTI1WjCBkTELMAkGA1UEBhMCVVMxEzARBgNVBAgM',
  'CkNhbGlmb3JuaWExETAPBgNVBAcMCFNhbiBKb3NlMRUwEwYDVQQKDAxDYXZpdW0s',
  'IEluYy4xFzAVBgNVBAsMDkxpcXVpZFNlY3VyaXR5MSowKAYDVQQDDCFsb2NhbGNh',
  'LmxpcXVpZHNlY3VyaXR5LmNhdml1bS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IB',
  'DwAwggEKAoIBAQDckvqQM4cvZjdyqOLGMTjKJwvfxJOhVqw6pojgUMz10VU7z3Ct',
  'JrwHcESwEDUxUkMxzof55kForURLaVVCjedYauEisnZwwSWkAemp9GREm8iX6BXt',
  'oZ8VDWoO2H0AJiHCM62qJeZVXhm8A/zWG0PyLrCINH0yz9ah6BcwdsZGLvQvkpUN',
  'JhwVMrb9nI9BlRmTWhoot1YSTf7jfibEkc/pN+0Ez30RFaL3MhyIaNJS22+10tny',
  '4sOUTsPEtXKah5mPlHpnrGcB18z5Yxgr0vDNYx+FCPGo95XGrq9NYfNMlwsSeFSr',
  '8D1VQ7HZmipeTB1hQTUQw/K/Rmtw5NiljkYTAgMBAAEwDQYJKoZIhvcNAQELBQAD',
  'ggEBAJjqbFaa3FOXEXcXPX2lCHdcyl8TwOR9f3Rq87MEfb3oeK9FarNkUCdvuGs3',
  'OkAWoFib/9l2F7ZgaNlJqVrwBaOvYuGguQoUpDybqttYUJVLcu9vA9eZA+UCJdhd',
  'P7fCyGMO+G96cnG3GTS1/SrIDU+YCnVElQ0P/73/de+ImoeMkwcqiUi2lsf3vGGR',
  'YXMt/DxUwjXwjIpWCs+37cwbNHAv0VKDOR/jmNf5EZf+sy4x2rJZ1NS6eDZ9RBug',
  'CLaN6ntybV4YlE7jDI9XIOm/tPJULZGLpLolngWVB6qtzn1RjBw1HIqpoXg+9s1g',
  'pLFFinSrEL1fkQR0YZQrJckktPs=',
  '-----END CERTIFICATE-----',
].join('\n');
export const MANUFACTURER_ROOT_CERT = new x509.X509Certificate(
  MANUFACTURER_ROOT_CERT_PEM,
);
