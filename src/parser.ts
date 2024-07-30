import * as pako from 'pako';
import { BufferSourceConverter, Convert } from 'pvtsutils';
import { DataViewReader } from './view_reader';
import {
  AttributeMap,
  AttributeType,
  CryptokiKeyType,
  CryptokiObjectClass,
  InfoHeader,
  ObjectAttributes,
  ResponseHeader,
  Attributes,
  KmsAttestation,
  AttributeValue,
} from './attestation';

function isGZIP(data: Uint8Array): boolean {
  return data[0] === 0x1f && data[1] === 0x8b;
}

function parseAttribute(tag: AttributeType, value: Uint8Array): AttributeValue {
  const parseFunction = attributeTypeMap[tag];
  if (parseFunction) {
    return parseFunction(value);
  }
  return value;
}

function parseAttributeBoolean(value: Uint8Array): boolean {
  return value[0] !== 0;
}

function parseAttributeText(value: Uint8Array): string {
  const nullIndex = value.findIndex((byte) => byte === 0);
  return Convert.ToUtf8String(value.slice(0, nullIndex));
}

function parseAttributeNumber(value: Uint8Array): number {
  return new DataView(
    value.buffer,
    value.byteOffset,
    value.byteLength,
  ).getUint32(0, false);
}

function parseAttributeEnum(value: Uint8Array, enumType: any): any {
  const enumValue = value[0];
  return enumType[enumValue];
}

function parseAttributeDefault(value: Uint8Array): Uint8Array {
  return value;
}

const attributeTypeMap: Record<AttributeType, (value: Uint8Array) => any> = {
  [AttributeType.OBJ_ATTR_CLASS]: (value) =>
    parseAttributeEnum(value, CryptokiObjectClass),
  [AttributeType.OBJ_ATTR_TOKEN]: parseAttributeBoolean,
  [AttributeType.OBJ_ATTR_PRIVATE]: parseAttributeBoolean,
  [AttributeType.OBJ_ATTR_TRUSTED]: parseAttributeBoolean,
  [AttributeType.OBJ_ATTR_SENSITIVE]: parseAttributeBoolean,
  [AttributeType.OBJ_ATTR_ENCRYPT]: parseAttributeBoolean,
  [AttributeType.OBJ_ATTR_DECRYPT]: parseAttributeBoolean,
  [AttributeType.OBJ_ATTR_WRAP]: parseAttributeBoolean,
  [AttributeType.OBJ_ATTR_UNWRAP]: parseAttributeBoolean,
  [AttributeType.OBJ_ATTR_SIGN]: parseAttributeBoolean,
  [AttributeType.OBJ_ATTR_VERIFY]: parseAttributeBoolean,
  [AttributeType.OBJ_ATTR_DERIVE]: parseAttributeBoolean,
  [AttributeType.OBJ_ATTR_EXTRACTABLE]: parseAttributeBoolean,
  [AttributeType.OBJ_ATTR_LOCAL]: parseAttributeBoolean,
  [AttributeType.OBJ_ATTR_NEVER_EXTRACTABLE]: parseAttributeBoolean,
  [AttributeType.OBJ_ATTR_ALWAYS_SENSITIVE]: parseAttributeBoolean,
  [AttributeType.OBJ_ATTR_WRAP_WITH_TRUSTED]: parseAttributeBoolean,
  [AttributeType.OBJ_ATTR_SPLITTABLE]: parseAttributeBoolean,
  [AttributeType.OBJ_ATTR_IS_SPLIT]: parseAttributeBoolean,
  [AttributeType.OBJ_ATTR_LABEL]: parseAttributeText,
  [AttributeType.OBJ_ATTR_KEY_TYPE]: (value) =>
    parseAttributeEnum(value, CryptokiKeyType),
  [AttributeType.OBJ_ATTR_ID]: parseAttributeText,
  [AttributeType.OBJ_ATTR_MODULUS_BITS]: parseAttributeNumber,
  [AttributeType.OBJ_ATTR_VALUE_LEN]: parseAttributeNumber,
  [AttributeType.OBJ_ATTR_KCV]: parseAttributeDefault,
  [AttributeType.OBJ_ATTR_MODULUS]: parseAttributeDefault,
  [AttributeType.OBJ_EXT_ATTR1]: parseAttributeDefault,
  [AttributeType.OBJ_ATTR_ENCRYPT_KEY_MECHANISMS]: parseAttributeDefault,
  [AttributeType.OBJ_ATTR_DECRYPT_KEY_MECHANISMS]: parseAttributeDefault,
  [AttributeType.OBJ_ATTR_SIGN_KEY_MECHANISMS]: parseAttributeDefault,
  [AttributeType.OBJ_ATTR_VERIFY_KEY_MECHANISMS]: parseAttributeDefault,
  [AttributeType.OBJ_ATTR_WRAP_KEY_MECHANISMS]: parseAttributeDefault,
  [AttributeType.OBJ_ATTR_UNWAP_KEY_MECHANISMS]: parseAttributeDefault,
  [AttributeType.OBJ_ATTR_DERIVE_KEY_MECHANISMS]: parseAttributeDefault,
  [AttributeType.OBJ_ATTR_PUBLIC_EXPONENT]: parseAttributeDefault,
  [AttributeType.OBJ_ATTR_EKCV]: parseAttributeDefault,
};

export class KmsAttestationParser {
  public static SIGNATURE_SIZE = 256;

  private view!: DataView;
  private reader!: DataViewReader;

  private readResponseHeader(): ResponseHeader {
    return {
      responseCode: this.reader.readUint32(),
      requestFlags: this.reader.readUint32(),
      totalSize: this.reader.readUint32(),
      bufferSize: this.reader.readUint32(),
    };
  }

  private readInfoHeader(): InfoHeader {
    return {
      objectVersion: this.reader.readUint16(),
      requestFlags: this.reader.readUint16(),
      offsetFirstKey: this.reader.readUint16(),
      offsetSecondKey: this.reader.readUint16(),
    };
  }

  private readAttributes(offset: number, length: number): ObjectAttributes {
    this.reader.setPosition(offset);
    const handle = this.reader.readUint32();
    const attributeCount = this.reader.readUint32();
    const objectSize = this.reader.readUint32();
    const attributes: AttributeMap = {};

    for (let i = 0; i < attributeCount; i++) {
      const tag = this.reader.readUint32() as AttributeType;
      const attrLength = this.reader.readUint32();
      const value = this.reader.readBytes(attrLength);
      attributes[tag] = { tag, length: attrLength, value };
    }

    const simpleAttributes: Attributes = this.simplifyAttributes(attributes);

    return { handle, attributeCount, objectSize, attributes: simpleAttributes };
  }

  private readSignature(): Uint8Array {
    return this.reader.readBytes(KmsAttestationParser.SIGNATURE_SIZE);
  }

  public parse(data: Uint8Array): KmsAttestation {
    let compressed = false;
    if (isGZIP(data)) {
      data = pako.inflate(data);
      compressed = true;
    }

    this.view = new DataView(BufferSourceConverter.toArrayBuffer(data));
    this.reader = new DataViewReader(this.view);

    const responseHeader = this.readResponseHeader();

    const attestDataPosition =
      data.byteLength -
      (responseHeader.bufferSize + KmsAttestationParser.SIGNATURE_SIZE);
    this.reader.setPosition(attestDataPosition);

    const infoHeader = this.readInfoHeader();
    const firstKey = this.readAttributes(
      attestDataPosition + infoHeader.offsetFirstKey,
      infoHeader.offsetSecondKey - infoHeader.offsetFirstKey,
    );
    const secondKey = this.readAttributes(
      attestDataPosition + infoHeader.offsetSecondKey,
      responseHeader.bufferSize - infoHeader.offsetSecondKey,
    );

    this.reader.setPosition(
      data.byteLength - KmsAttestationParser.SIGNATURE_SIZE,
    );
    const signature = this.readSignature();

    return {
      compressed,
      responseHeader,
      attestationData: { info: infoHeader, firstKey, secondKey },
      signedData: data.subarray(
        0,
        data.byteLength - KmsAttestationParser.SIGNATURE_SIZE,
      ),
      signature,
    };
  }

  private simplifyAttributes(attributes: AttributeMap): Attributes {
    const simplified: Record<string, any> = {};
    for (const [, attr] of Object.entries(attributes)) {
      simplified[AttributeType[attr.tag]] = parseAttribute(
        attr.tag,
        attr.value,
      );
    }
    return simplified as Attributes;
  }
}
