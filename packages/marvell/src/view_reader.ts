export class DataViewReader {
  private position = 0;

  constructor(private view: DataView) {}

  readUint16(): number {
    const value = this.view.getUint16(this.position, false);
    this.position += 2;
    return value;
  }

  readUint32(): number {
    const value = this.view.getUint32(this.position, false);
    this.position += 4;
    return value;
  }

  setPosition(position: number) {
    this.position = position;
  }

  readBytes(length: number): Uint8Array {
    const value = new Uint8Array(this.view.buffer, this.position, length);
    this.position += length;
    return value;
  }
}
