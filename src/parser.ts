import * as pako from 'pako';
import { BufferSourceConverter, Convert } from 'pvtsutils';
import { DataViewReader } from './view_reader';
import {
  AttributeMap,
  AttributeType,
  InfoHeader,
  KmsAttestation,
  ObjectAttributes,
  ResponseHeader,
} from './attestation';

function isGZIP(data: Uint8Array): boolean {
  return data[0] === 0x1f && data[1] === 0x8b;
}

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

    return { handle, attributeCount, objectSize, attributes };
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
      attestationData: {
        raw: data,
        info: infoHeader,
        firstKey,
        secondKey,
      },
      signedData: data.subarray(
        0,
        data.byteLength - KmsAttestationParser.SIGNATURE_SIZE,
      ),
      signature,
    };
  }
}
