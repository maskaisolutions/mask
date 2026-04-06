import * as crypto from 'crypto';

export class FF1 {
  private key: Buffer;
  private tweak: Buffer;
  private radix: number;
  private chars: string = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

  constructor(key: Buffer, tweak: Buffer, radix: number) {
    this.key = key;
    this.tweak = tweak;
    this.radix = radix;
    if (radix > this.chars.length) {
      throw new Error(`Radix ${radix} not supported`);
    }
  }

  private _prf(x: Buffer): Buffer {
    const cipher = crypto.createCipheriv('aes-256-cbc', this.key, Buffer.alloc(16, 0));
    cipher.setAutoPadding(false);
    return Buffer.concat([cipher.update(x), cipher.final()]).subarray(-16);
  }

  private _ciph(x: Buffer): Buffer {
    const cipher = crypto.createCipheriv('aes-256-ecb', this.key, null);
    cipher.setAutoPadding(false);
    return Buffer.concat([cipher.update(x), cipher.final()]);
  }

  private _strToInt(s: string): bigint {
    let n = 0n;
    const r = BigInt(this.radix);
    for (let i = 0; i < s.length; i++) {
        n = n * r + BigInt(this.chars.indexOf(s[i]));
    }
    return n;
  }

  private _intToStr(num: bigint, length: number): string {
    if (num === 0n) {
      return this.chars[0].repeat(length);
    }
    let digits: string[] = [];
    let n = num;
    const r = BigInt(this.radix);
    while (n > 0n) {
      digits.push(this.chars[Number(n % r)]);
      n /= r;
    }
    let s = digits.reverse().join('');
    while (s.length < length) s = this.chars[0] + s;
    return s;
  }

  private _bigintToBuffer(num: bigint, bytes: number): Buffer {
    const buf = Buffer.alloc(bytes);
    let n = num;
    for (let i = bytes - 1; i >= 0; i--) {
      buf[i] = Number(n & 0xFFn);
      n >>= 8n;
    }
    return buf;
  }

  encrypt(X: string): string {
    const n = X.length;
    const t = this.tweak.length;
    if (n < 2) return X;
    const u = Math.floor(n / 2);
    const v = n - u;
    
    let A = X.substring(0, u);
    let B = X.substring(u);
    
    const b = Math.ceil(Math.ceil(v * Math.log2(this.radix)) / 8);
    const d = 4 * Math.ceil(b / 4) + 4;

    const P = Buffer.alloc(16);
    P[0] = 1; P[1] = 2; P[2] = 1;
    P.writeUIntBE(this.radix, 3, 3);
    P[6] = 10; P[7] = u % 256;
    P.writeUInt32BE(n, 8);
    P.writeUInt32BE(t, 12);

    for (let i = 0; i < 10; i++) {
      const m = i % 2 === 0 ? u : v;
      // padding length calculates correctly using JS modulo for negative numbers
      const padLen = ((-t - b - 1) % 16 + 16) % 16;
      
      const Q = Buffer.alloc(t + padLen + 1 + b);
      this.tweak.copy(Q, 0);
      Q[t + padLen] = i;
      this._bigintToBuffer(this._strToInt(B), b).copy(Q, t + padLen + 1);

      const R = this._prf(Buffer.concat([P, Q]));
      let S = Buffer.from(R);
      let j = 1;
      
      while (S.length < d) {
        const xorBlock = Buffer.alloc(16);
        const jBuf = Buffer.alloc(16);
        jBuf.writeUInt32BE(j, 12); // j fits in 32 bits natively
        for (let k = 0; k < 16; k++) xorBlock[k] = R[k] ^ jBuf[k];
        S = Buffer.concat([S, this._ciph(xorBlock)]);
        j++;
      }
      
      S = S.subarray(0, d);
      
      // Convert S to bigint
      let y = 0n;
      for (let k = 0; k < S.length; k++) {
        y = (y << 8n) + BigInt(S[k]);
      }
      
      const modulo = BigInt(this.radix) ** BigInt(m);
      const c = (this._strToInt(A) + y) % modulo;
      const C = this._intToStr(c, m);
      
      A = B;
      B = C;
    }
    
    return A + B;
  }

  decrypt(X: string): string {
    const n = X.length;
    const t = this.tweak.length;
    if (n < 2) return X;
    const u = Math.floor(n / 2);
    const v = n - u;
    
    let A = X.substring(0, u);
    let B = X.substring(u);
    
    if (n % 2 !== 0) {
      const temp = A; A = B; B = temp;
    }
    
    const b = Math.ceil(Math.ceil(v * Math.log2(this.radix)) / 8);
    const d = 4 * Math.ceil(b / 4) + 4;

    const P = Buffer.alloc(16);
    P[0] = 1; P[1] = 2; P[2] = 1;
    P.writeUIntBE(this.radix, 3, 3);
    P[6] = 10; P[7] = u % 256;
    P.writeUInt32BE(n, 8);
    P.writeUInt32BE(t, 12);

    for (let i = 9; i >= 0; i--) {
      const m = i % 2 === 0 ? u : v;
      const padLen = ((-t - b - 1) % 16 + 16) % 16;
      
      const Q = Buffer.alloc(t + padLen + 1 + b);
      this.tweak.copy(Q, 0);
      Q[t + padLen] = i;
      this._bigintToBuffer(this._strToInt(A), b).copy(Q, t + padLen + 1);

      const R = this._prf(Buffer.concat([P, Q]));
      let S = Buffer.from(R);
      let j = 1;
      
      while (S.length < d) {
        const xorBlock = Buffer.alloc(16);
        const jBuf = Buffer.alloc(16);
        jBuf.writeUInt32BE(j, 12);
        for (let k = 0; k < 16; k++) xorBlock[k] = R[k] ^ jBuf[k];
        S = Buffer.concat([S, this._ciph(xorBlock)]);
        j++;
      }
      
      S = S.subarray(0, d);
      
      let y = 0n;
      for (let k = 0; k < S.length; k++) {
        y = (y << 8n) + BigInt(S[k]);
      }
      
      const modulo = BigInt(this.radix) ** BigInt(m);
      let c = (this._strToInt(B) - y) % modulo;
      if (c < 0n) c += modulo;
      
      const C = this._intToStr(c, m);
      
      B = A;
      A = C;
    }
    
    if (n % 2 !== 0) {
      const temp = A; A = B; B = temp;
    }
    
    return A + B;
  }
}
