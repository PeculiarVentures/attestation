import assert from 'node:assert';
import { KmsAttestationParser } from './parser';

const base64CompressedData =
  'H4sIAAAAAAAAAGNgAANmBgYOBwYGdgUIl/0ZhFZaxsAIlONgngIVUwYqbYDIMTAyATGYwcwAYYFEGECYEchjZIExWGHSbDARdpgIB4zBBZNKhjHghiZBRUCOZGhILCiIz06tZBg4APZlQ4qBWXKyhYFhmnlKWlpKUkqKeaKlkYlBUkqyQWKqYWKKoZGJhZmRpYVBcqK5sVFyqqmJiVmaYXKKQZI5SG1iknGqsWFKkpGlqYVRokFSkoVJcpJhirlFiqF5khnQaLOkVDMj08RU41RzkxRjSzPLNMMU41QDC3NjC/Nk86QUoDsSge4ABbIjkF0MCp/GjcsZGARAwaTgULr46UI7Y84Qg2lae3adfm90vbjIpK299ZITx2RN+xNZQHUgv3BA/cTUwMBYAtJHwO//gepKiVRXRqS6ciLVVRCprpJIdQ3EqAMGLUiNI4uHUWDm4rJ2i9nf7um/Xi86I5Y5qKB7H5O29hyfvN8Vd+qv+vEqLF6Vx/YueCOrfqIUr9M2gUbP3u2dB6aH7WDkulUANEiRARxfjPOBdBsDJHUzCUAZjDwwRiqY0QDNSSAGPCukQBnAfImWF5mJyIsMsLzICMuLDLC8yAjLi4ywvMiAkRcZYXkRZM9oXsSeF7tG8yKyumGRF0Guw5EXGRtLNh6VepC1cUnAzPfnr3rYnfKe9/Dzyeb6y99ebEyz/XdD+WXTf/6G9m1P/wgq9nwRnbt1mu36kzMTS644NlXKR//pnSC7zMNKbhWDz7KJHNGbddqu8ksuuusdwyPmfzD9WMKXwq1Skx8a9jaeTec/Xte8eqftROmVG58+LQv73ainq7wzp/naxEdOYc/annt/jHryjO+M9puZXKn/lFNyJX7rLrkWUff2+BsZpltmDziT+E49UtRVOpqpy7Cve6qesGrgh+6P5xlaFz4v/p3d6ChbWr9z3XnZmgXXnuw8IpTELXA+4Wn7lgnSgf0/DKx7JofqTbc8U3mw/HnZSdc1GzZNf63s8l3lTrrG/wcAkcwjK0AIAAA=';

describe('Parser', () => {
  let parser: KmsAttestationParser;

  beforeEach(() => {
    parser = new KmsAttestationParser();
  });

  it('should correctly parse compressed data', () => {
    const compressedData = Uint8Array.from(atob(base64CompressedData), (c) =>
      c.charCodeAt(0),
    );
    const result = parser.parse(compressedData);
    assert.strictEqual(result.compressed, true);
  });
});
