export enum AttestationFlags {
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

export enum AttributeType {
  OBJ_ATTR_CLASS = 0x0000,
  OBJ_ATTR_TOKEN = 0x0001,
  OBJ_ATTR_PRIVATE = 0x0002,
  OBJ_ATTR_LABEL = 0x0003,
  OBJ_ATTR_TRUSTED = 0x0086,
  OBJ_ATTR_KEY_TYPE = 0x0100,
  OBJ_ATTR_ID = 0x0102,
  OBJ_ATTR_SENSITIVE = 0x0103,
  OBJ_ATTR_ENCRYPT = 0x0104,
  OBJ_ATTR_DECRYPT = 0x0105,
  OBJ_ATTR_WRAP = 0x0106,
  OBJ_ATTR_UNWRAP = 0x0107,
  OBJ_ATTR_SIGN = 0x0108,
  OBJ_ATTR_VERIFY = 0x010a,
  OBJ_ATTR_DERIVE = 0x010c,
  OBJ_ATTR_MODULUS = 0x0120,
  OBJ_ATTR_MODULUS_BITS = 0x0121,
  OBJ_ATTR_PUBLIC_EXPONENT = 0x0122,
  OBJ_ATTR_VALUE_LEN = 0x0161,
  OBJ_ATTR_EXTRACTABLE = 0x0162,
  OBJ_ATTR_LOCAL = 0x0163,
  OBJ_ATTR_NEVER_EXTRACTABLE = 0x0164,
  OBJ_ATTR_ALWAYS_SENSITIVE = 0x0165,
  OBJ_ATTR_KCV = 0x0173,
  OBJ_EXT_ATTR1 = 0x1000,
  OBJ_ATTR_EKCV = 0x1003,
  OBJ_ATTR_WRAP_WITH_TRUSTED = 0x0210,
  OBJ_ATTR_SPLITTABLE = 0x80000002,
  OBJ_ATTR_IS_SPLIT = 0x80000003,
  OBJ_ATTR_ENCRYPT_KEY_MECHANISMS = 0x80000174,
  OBJ_ATTR_DECRYPT_KEY_MECHANISMS = 0x80000175,
  OBJ_ATTR_SIGN_KEY_MECHANISMS = 0x80000176,
  OBJ_ATTR_VERIFY_KEY_MECHANISMS = 0x80000177,
  OBJ_ATTR_WRAP_KEY_MECHANISMS = 0x80000178,
  OBJ_ATTR_UNWAP_KEY_MECHANISMS = 0x80000179,
  OBJ_ATTR_DERIVE_KEY_MECHANISMS = 0x80000180,
}

export interface KmsAttestationData {
  raw: Uint8Array;
  info: InfoHeader;
  firstKey: ObjectAttributes;
  secondKey: ObjectAttributes;
}

export interface KmsAttestation {
  compressed: boolean;
  responseHeader: ResponseHeader;
  attestationData: KmsAttestationData;
  signedData: Uint8Array;
  signature: Uint8Array;
}

export type AttributeMap = Partial<Record<AttributeType, Attribute>>;

export interface ObjectAttributes {
  handle: number;
  attributeCount: number;
  objectSize: number;
  attributes: AttributeMap;
}

export interface Attribute {
  tag: AttributeType;
  length: number;
  value: Uint8Array;
}

export interface ResponseHeader {
  responseCode: number;
  requestFlags: AttestationFlags;
  totalSize: number;
  bufferSize: number;
}

export interface InfoHeader {
  objectVersion: number;
  requestFlags: number;
  offsetFirstKey: number;
  offsetSecondKey: number;
}
