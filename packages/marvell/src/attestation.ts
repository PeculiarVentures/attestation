export enum MarvellAttestationFlags {
  /**
   * Fetches the attributes as part of the response.
   */
  KEY_GEN_FLAG_GET_ATTR = 0x0001,
  /**
   * Gets RSA sign of the data as part of the response. This sign is obtained by signing the response header along with attributes (if fetched).
   */
  KEY_GEN_FLAG_GET_ATTEST = 0x0002,
  /**
   * Excludes the response header and gets only the sign of the attributes. This flag is valid only if KEY_GEN_FLAG_GET_ATTEST is set. If attribute flag (KEY_GEN_FLAG_GET_ATTR) is not specified and KEY_GEN_FLAG_EXCLUDE_HEADER flag is set, attestation will fail as there is no data to sign.
   */
  KEY_GEN_FLAG_EXCLUDE_HEADER = 0x0004,
}

/**
 * Enum representing various attribute types for keys.
 */
export enum MarvellAttributeType {
  /**
   * Class type of the key.
   */
  OBJ_ATTR_CLASS = 0x0000,

  /**
   * Identifies the key as a token key.
   */
  OBJ_ATTR_TOKEN = 0x0001,

  /**
   * Indicates if this is a shared key or a private key (for symmetric or asymmetric keys).
   */
  OBJ_ATTR_PRIVATE = 0x0002,

  /**
   * Key description.
   */
  OBJ_ATTR_LABEL = 0x0003,

  /**
   * The key can be trusted for the application that it was created.
   */
  OBJ_ATTR_TRUSTED = 0x0086,

  /**
   * Subclass type of the key.
   */
  OBJ_ATTR_KEY_TYPE = 0x0100,

  /**
   * Key identifier.
   */
  OBJ_ATTR_ID = 0x0102,

  /**
   * Always true for keys generated on HSM.
   */
  OBJ_ATTR_SENSITIVE = 0x0103,

  /**
   * Indicates if key can be used to encrypt data for operations like RSA_Encrypt. Not applicable to EC keys.
   */
  OBJ_ATTR_ENCRYPT = 0x0104,

  /**
   * Indicates if key can be used to decrypt data for operations like RSA_Decrypt. Not applicable to EC keys.
   */
  OBJ_ATTR_DECRYPT = 0x0105,

  /**
   * Indicates if key can be used to wrap other keys.
   */
  OBJ_ATTR_WRAP = 0x0106,

  /**
   * Indicates if key can be used to unwrap other keys.
   */
  OBJ_ATTR_UNWRAP = 0x0107,

  /**
   * Indicates if key can be used for signing operations.
   */
  OBJ_ATTR_SIGN = 0x0108,

  /**
   * Indicates if key can be used for verifying operations.
   */
  OBJ_ATTR_VERIFY = 0x010a,

  /**
   * Indicates if key supports key derivation (i.e. if other keys can be derived from this one).
   */
  OBJ_ATTR_DERIVE = 0x010c,

  /**
   * RSA key modulus value.
   */
  OBJ_ATTR_MODULUS = 0x0120,

  /**
   * RSA key size in bits.
   */
  OBJ_ATTR_MODULUS_BITS = 0x0121,

  /**
   * RSA key public exponent value.
   */
  OBJ_ATTR_PUBLIC_EXPONENT = 0x0122,

  /**
   * Length in bytes of any value.
   */
  OBJ_ATTR_VALUE_LEN = 0x0161,

  /**
   * Indicates if key can be extracted.
   */
  OBJ_ATTR_EXTRACTABLE = 0x0162,

  /**
   * Indicates if key was generated locally.
   */
  OBJ_ATTR_LOCAL = 0x0163,

  /**
   * Indicates if key can never be extracted.
   */
  OBJ_ATTR_NEVER_EXTRACTABLE = 0x0164,

  /**
   * Indicates if key has always had the OBJ_ATTR_SENSITIVE attribute set.
   */
  OBJ_ATTR_ALWAYS_SENSITIVE = 0x0165,

  /**
   * Key Check Value.
   */
  OBJ_ATTR_KCV = 0x0173,

  /**
   * Extended Attribute #1.
   */
  OBJ_EXT_ATTR1 = 0x1000,

  /**
   * Extended Key Check Value.
   */
  OBJ_ATTR_EKCV = 0x1003,

  /**
   * Indicates if key can only be wrapped with a wrapping key that has OBJ_ATTR_TRUSTED set.
   */
  OBJ_ATTR_WRAP_WITH_TRUSTED = 0x0210,

  /**
   * Indicates if key can be split into multiple parts.
   */
  OBJ_ATTR_SPLITTABLE = 0x80000002,

  /**
   * Indicate if it is part of the key split.
   */
  OBJ_ATTR_IS_SPLIT = 0x80000003,

  /**
   * Indicate if key supports encryption.
   */
  OBJ_ATTR_ENCRYPT_KEY_MECHANISMS = 0x80000174,

  /**
   * Indicate if key supports decryption.
   */
  OBJ_ATTR_DECRYPT_KEY_MECHANISMS = 0x80000175,

  /**
   * Indicate if key supports signing.
   */
  OBJ_ATTR_SIGN_KEY_MECHANISMS = 0x80000176,

  /**
   * Indicate if key supports signature verification.
   */
  OBJ_ATTR_VERIFY_KEY_MECHANISMS = 0x80000177,

  /**
   * Indicate if key supports key wrapping.
   */
  OBJ_ATTR_WRAP_KEY_MECHANISMS = 0x80000178,

  /**
   * Indicate if key supports key unwrapping.
   */
  OBJ_ATTR_UNWAP_KEY_MECHANISMS = 0x80000179,

  /**
   * Indicate if key supports key derivation.
   */
  OBJ_ATTR_DERIVE_KEY_MECHANISMS = 0x80000180,
}

export interface MarvellAttestationData {
  info: InfoHeader;
  firstKey: ObjectAttributes;
  secondKey?: ObjectAttributes;
}

export interface MarvellAttestation {
  compressed: boolean;
  responseHeader: ResponseHeader;
  attestationData: MarvellAttestationData;
  signedData: Uint8Array;
  signature: Uint8Array;
}

export type AttributeMap = Partial<Record<MarvellAttributeType, Attribute>>;

export interface ObjectAttributes {
  handle: number;
  attributeCount: number;
  objectSize: number;
  attributes: Attributes;
}

export interface Attribute {
  tag: MarvellAttributeType;
  length: number;
  value: Uint8Array;
}

export interface ResponseHeader {
  responseCode: number;
  requestFlags: MarvellAttestationFlags;
  totalSize: number;
  bufferSize: number;
}

export interface InfoHeader {
  objectVersion: number;
  requestFlags: number;
  offsetFirstKey: number;
  offsetSecondKey: number;
}

export enum CryptokiObjectClass {
  CKO_DATA = 0x00,
  CKO_CERTIFICATE = 0x01,
  CKO_PUBLIC_KEY = 0x02,
  CKO_PRIVATE_KEY = 0x03,
  CKO_SECRET_KEY = 0x04,
  CKO_HW_FEATURE = 0x05,
  CKO_DOMAIN_PARAMETERS = 0x06,
  CKO_MECHANISM = 0x07,
  CKO_OTP_KEY = 0x08,
}

export enum CryptokiKeyType {
  CKK_RSA = 0x00,
  CKK_DSA = 0x01,
  CKK_DH = 0x02,
  CKK_EC = 0x03,
  CKK_X9_42_DH = 0x04,
  CKK_KEA = 0x05,
  CKK_GENERIC_SECRET = 0x10,
  CKK_RC2 = 0x11,
  CKK_RC4 = 0x12,
  CKK_DES = 0x13,
  CKK_DES2 = 0x14,
  CKK_DES3 = 0x15,
  CKK_CAST = 0x16,
  CKK_CAST3 = 0x17,
  CKK_CAST128 = 0x18,
  CKK_RC5 = 0x19,
  CKK_IDEA = 0x1a,
  CKK_SKIPJACK = 0x1b,
  CKK_BATON = 0x1c,
  CKK_JUNIPER = 0x1d,
  CKK_CDMF = 0x1e,
  CKK_AES = 0x1f,
  CKK_BLOWFISH = 0x20,
  CKK_TWOFISH = 0x21,
  CKK_SECURID = 0x22,
  CKK_HOTP = 0x23,
  CKK_ACTI = 0x24,
  CKK_CAMELLIA = 0x25,
  CKK_ARIA = 0x26,
}

export type AttributeValue = boolean | number | string | Uint8Array;

/**
 * Interface representing various attributes for cryptographic objects.
 */
export interface Attributes {
  /**
   * Class type of the key.
   */
  ['OBJ_ATTR_CLASS']: keyof typeof CryptokiObjectClass;

  /**
   * Identifies the key as a token key.
   */
  ['OBJ_ATTR_TOKEN']: boolean;

  /**
   * Indicates if this is a shared key or a private key (for symmetric or asymmetric keys).
   */
  ['OBJ_ATTR_PRIVATE']: boolean;

  /**
   * The key can be trusted for the application that it was created.
   */
  ['OBJ_ATTR_TRUSTED']: boolean;

  /**
   * Always true for keys generated on HSM.
   */
  ['OBJ_ATTR_SENSITIVE']: boolean;

  /**
   * Indicates if key can be used to encrypt data for operations like RSA_Encrypt. Not applicable to EC keys.
   */
  ['OBJ_ATTR_ENCRYPT']: boolean;

  /**
   * Indicates if key can be used to decrypt data for operations like RSA_Decrypt. Not applicable to EC keys.
   */
  ['OBJ_ATTR_DECRYPT']: boolean;

  /**
   * Indicates if key can be used to wrap other keys.
   */
  ['OBJ_ATTR_WRAP']: boolean;

  /**
   * Indicates if key can be used to unwrap other keys.
   */
  ['OBJ_ATTR_UNWRAP']: boolean;

  /**
   * Indicates if key can be used for signing operations.
   */
  ['OBJ_ATTR_SIGN']: boolean;

  /**
   * Indicates if key can be used for verifying operations.
   */
  ['OBJ_ATTR_VERIFY']: boolean;

  /**
   * Indicates if key supports key derivation (i.e. if other keys can be derived from this one).
   */
  ['OBJ_ATTR_DERIVE']: boolean;

  /**
   * Indicates if key can be extracted.
   */
  ['OBJ_ATTR_EXTRACTABLE']: boolean;

  /**
   * Indicates if key was generated locally.
   */
  ['OBJ_ATTR_LOCAL']: boolean;

  /**
   * Indicates if key can never be extracted.
   */
  ['OBJ_ATTR_NEVER_EXTRACTABLE']: boolean;

  /**
   * Indicates if key has always had the OBJ_ATTR_SENSITIVE attribute set.
   */
  ['OBJ_ATTR_ALWAYS_SENSITIVE']: boolean;

  /**
   * Indicates if key can only be wrapped with a wrapping key that has OBJ_ATTR_TRUSTED set.
   */
  ['OBJ_ATTR_WRAP_WITH_TRUSTED']: boolean;

  /**
   * Indicates if key can be split into multiple parts.
   */
  ['OBJ_ATTR_SPLITTABLE']: boolean;

  /**
   * Indicate if it is part of the key split.
   */
  ['OBJ_ATTR_IS_SPLIT']: boolean;

  /**
   * Key description.
   */
  ['OBJ_ATTR_LABEL']: string;

  /**
   * Subclass type of the key.
   */
  ['OBJ_ATTR_KEY_TYPE']: keyof typeof CryptokiKeyType;

  /**
   * Key identifier.
   */
  ['OBJ_ATTR_ID']: string;

  /**
   * RSA key size in bits.
   */
  ['OBJ_ATTR_MODULUS_BITS']: number;

  /**
   * Length in bytes of any value.
   */
  ['OBJ_ATTR_VALUE_LEN']: number;

  /**
   * Key Check Value.
   */
  ['OBJ_ATTR_KCV']: Uint8Array;

  /**
   * RSA key modulus value.
   */
  ['OBJ_ATTR_MODULUS']: Uint8Array;

  /**
   * Extended Attribute #1.
   */
  ['OBJ_EXT_ATTR1']: Uint8Array;

  /**
   * Indicate if key supports encryption.
   */
  ['OBJ_ATTR_ENCRYPT_KEY_MECHANISMS']: Uint8Array;

  /**
   * Indicate if key supports decryption.
   */
  ['OBJ_ATTR_DECRYPT_KEY_MECHANISMS']: Uint8Array;

  /**
   * Indicate if key supports signing.
   */
  ['OBJ_ATTR_SIGN_KEY_MECHANISMS']: Uint8Array;

  /**
   * Indicate if key supports signature verification.
   */
  ['OBJ_ATTR_VERIFY_KEY_MECHANISMS']: Uint8Array;

  /**
   * Indicate if key supports key wrapping.
   */
  ['OBJ_ATTR_WRAP_KEY_MECHANISMS']: Uint8Array;

  /**
   * Indicate if key supports key unwrapping.
   */
  ['OBJ_ATTR_UNWAP_KEY_MECHANISMS']: Uint8Array;

  /**
   * Indicate if key supports key derivation.
   */
  ['OBJ_ATTR_DERIVE_KEY_MECHANISMS']: Uint8Array;

  /**
   * RSA key public exponent value.
   */
  ['OBJ_ATTR_PUBLIC_EXPONENT']: Uint8Array;

  /**
   * Extended Key Check Value.
   */
  ['OBJ_ATTR_EKCV']: Uint8Array;
}
