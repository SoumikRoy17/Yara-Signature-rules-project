// MD5 hash implementation
function md5(array: Uint8Array): string {
  const rotateLeft = (x: number, n: number) => (x << n) | (x >>> (32 - n));
  const toHexString = (num: number) => {
    const s = '0123456789abcdef';
    let str = '';
    for (let i = 0; i < 4; i++) {
      str += s.charAt((num >> ((3 - i) * 8 + 4)) & 0x0F) + 
             s.charAt((num >> ((3 - i) * 8)) & 0x0F);
    }
    return str;
  };

  // Initialize variables
  let a = 0x67452301;
  let b = 0xEFCDAB89;
  let c = 0x98BADCFE;
  let d = 0x10325476;

  // Pre-computed table
  const S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
  ];

  const K = new Uint32Array(64);
  for (let i = 0; i < 64; i++) {
    K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000);
  }

  // Padding
  const paddedLength = (((array.length + 8) >> 6) + 1) << 6;
  const padded = new Uint8Array(paddedLength);
  padded.set(array);
  padded[array.length] = 0x80;
  const bits = array.length * 8;
  padded[paddedLength - 8] = bits & 0xFF;
  padded[paddedLength - 7] = (bits >> 8) & 0xFF;
  padded[paddedLength - 6] = (bits >> 16) & 0xFF;
  padded[paddedLength - 5] = (bits >> 24) & 0xFF;

  // Process blocks
  for (let i = 0; i < paddedLength; i += 64) {
    const chunk = new Uint32Array(16);
    for (let j = 0; j < 16; j++) {
      chunk[j] = padded[i + j * 4] |
                (padded[i + j * 4 + 1] << 8) |
                (padded[i + j * 4 + 2] << 16) |
                (padded[i + j * 4 + 3] << 24);
    }

    let aa = a, bb = b, cc = c, dd = d;

    for (let j = 0; j < 64; j++) {
      let f, g;
      if (j < 16) {
        f = (b & c) | ((~b) & d);
        g = j;
      } else if (j < 32) {
        f = (d & b) | ((~d) & c);
        g = (5 * j + 1) % 16;
      } else if (j < 48) {
        f = b ^ c ^ d;
        g = (3 * j + 5) % 16;
      } else {
        f = c ^ (b | (~d));
        g = (7 * j) % 16;
      }

      const temp = d;
      d = c;
      c = b;
      b = b + rotateLeft((a + f + K[j] + chunk[g]) | 0, S[j]);
      a = temp;
    }

    a = (a + aa) | 0;
    b = (b + bb) | 0;
    c = (c + cc) | 0;
    d = (d + dd) | 0;
  }

  return toHexString(a) + toHexString(b) + toHexString(c) + toHexString(d);
}

export function generateMD5Hash(buffer: Uint8Array): string {
  return md5(buffer);
}