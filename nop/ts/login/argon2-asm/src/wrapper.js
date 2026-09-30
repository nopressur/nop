// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

var ready = function () {
  var root = getRoot();
  var argon2BufferPointer = _Argon2_GetBuffer();
  var blakeBufferPointer = _Blake2b_GetBuffer();

  function getRoot() {
    if (typeof window !== 'undefined') {
      return window;
    }
    if (typeof self !== 'undefined') {
      return self;
    }
    if (typeof global !== 'undefined') {
      return global;
    }
    return {};
  }

  function isTypedArray(value) {
    return value && typeof value === 'object' && value.buffer instanceof ArrayBuffer && typeof value.byteLength === 'number';
  }

  function utf8Bytes(input) {
    var str = String(input);
    var length = 0;
    var i;
    var code;
    var next;

    for (i = 0; i < str.length; i++) {
      code = str.charCodeAt(i);
      if (code >= 0xd800 && code <= 0xdbff && i + 1 < str.length) {
        next = str.charCodeAt(i + 1);
        if (next >= 0xdc00 && next <= 0xdfff) {
          code = 0x10000 + ((code - 0xd800) << 10) + (next - 0xdc00);
          i++;
        }
      }
      if (code < 0x80) {
        length++;
      } else if (code < 0x800) {
        length += 2;
      } else if (code < 0x10000) {
        length += 3;
      } else {
        length += 4;
      }
    }

    var out = new Uint8Array(length);
    var p = 0;
    for (i = 0; i < str.length; i++) {
      code = str.charCodeAt(i);
      if (code >= 0xd800 && code <= 0xdbff && i + 1 < str.length) {
        next = str.charCodeAt(i + 1);
        if (next >= 0xdc00 && next <= 0xdfff) {
          code = 0x10000 + ((code - 0xd800) << 10) + (next - 0xdc00);
          i++;
        }
      }
      if (code < 0x80) {
        out[p++] = code;
      } else if (code < 0x800) {
        out[p++] = 0xc0 | (code >> 6);
        out[p++] = 0x80 | (code & 0x3f);
      } else if (code < 0x10000) {
        out[p++] = 0xe0 | (code >> 12);
        out[p++] = 0x80 | ((code >> 6) & 0x3f);
        out[p++] = 0x80 | (code & 0x3f);
      } else {
        out[p++] = 0xf0 | (code >> 18);
        out[p++] = 0x80 | ((code >> 12) & 0x3f);
        out[p++] = 0x80 | ((code >> 6) & 0x3f);
        out[p++] = 0x80 | (code & 0x3f);
      }
    }
    return out;
  }

  function copyBytes(input) {
    var out;
    var i;
    if (typeof input === 'string') {
      return utf8Bytes(input);
    }
    if (!isTypedArray(input)) {
      throw new Error('Expected a string or typed array.');
    }
    out = new Uint8Array(input.byteLength);
    input = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
    for (i = 0; i < input.length; i++) {
      out[i] = input[i];
    }
    return out;
  }

  function hexToBytes(hex) {
    if (typeof hex !== 'string' || hex.length % 2 !== 0) {
      throw new Error('Salt hex must contain an even number of characters.');
    }
    var out = new Uint8Array(hex.length / 2);
    var i;
    var value;
    for (i = 0; i < out.length; i++) {
      value = parseInt(hex.charAt(i * 2) + hex.charAt(i * 2 + 1), 16);
      if (value !== value) {
        throw new Error('Salt hex contains invalid characters.');
      }
      out[i] = value;
    }
    return out;
  }

  function saltBytes(input) {
    if (typeof input === 'string') {
      return hexToBytes(input);
    }
    return copyBytes(input);
  }

  function int32LE(value) {
    var out = new Uint8Array(4);
    out[0] = value & 255;
    out[1] = (value >>> 8) & 255;
    out[2] = (value >>> 16) & 255;
    out[3] = (value >>> 24) & 255;
    return out;
  }

  function bytesToHex(bytes) {
    var hex = '0123456789abcdef';
    var chars = new Array(bytes.length * 2);
    var i;
    var value;
    for (i = 0; i < bytes.length; i++) {
      value = bytes[i];
      chars[i * 2] = hex.charAt(value >>> 4);
      chars[i * 2 + 1] = hex.charAt(value & 15);
    }
    return chars.join('');
  }

  function copyRange(source, offset, length) {
    var out = new Uint8Array(length);
    var i;
    for (i = 0; i < length; i++) {
      out[i] = source[offset + i];
    }
    return out;
  }

  function setBytes(target, source, offset) {
    var i;
    for (i = 0; i < source.length; i++) {
      target[offset + i] = source[i];
    }
  }

  function zeroBytes(target, offset, length) {
    var i;
    for (i = 0; i < length; i++) {
      target[offset + i] = 0;
    }
  }

  function blake2bDigest(parts, outputLength) {
    var i;
    var part;
    var read;
    var chunk;
    if (outputLength < 1 || outputLength > 64) {
      throw new Error('BLAKE2b output length must be between 1 and 64 bytes.');
    }
    _Blake2b_Init(outputLength * 8);
    for (i = 0; i < parts.length; i++) {
      part = parts[i];
      read = 0;
      while (read < part.length) {
        chunk = part.length - read;
        if (chunk > 16384) {
          chunk = 16384;
        }
        HEAPU8.set(part.subarray(read, read + chunk), blakeBufferPointer);
        _Blake2b_Update(chunk);
        read += chunk;
      }
    }
    _Blake2b_Final();
    return copyRange(HEAPU8, blakeBufferPointer, outputLength);
  }

  function hashFunc(blake512, buf, length) {
    var r;
    var ret;
    var vp;
    var i;
    var partialBytesNeeded;

    if (length <= 64) {
      return blake2bDigest([int32LE(length), buf], length);
    }

    r = Math.ceil(length / 32) - 2;
    ret = new Uint8Array(length);
    vp = blake2bDigest([int32LE(length), buf], 64);
    setBytes(ret, copyRange(vp, 0, 32), 0);

    for (i = 1; i < r; i++) {
      vp = blake2bDigest([vp], 64);
      setBytes(ret, copyRange(vp, 0, 32), i * 32);
    }

    partialBytesNeeded = length - 32 * r;
    vp = blake2bDigest([vp], partialBytesNeeded);
    setBytes(ret, copyRange(vp, 0, partialBytesNeeded), r * 32);
    return ret;
  }

  function validateParams(params) {
    if (!params || typeof params !== 'object') {
      throw new Error('Argon2id parameters are required.');
    }
    if (params.memoryKib !== (params.memoryKib | 0) || params.memoryKib < 8 * params.parallelism) {
      throw new Error('memoryKib must be an integer at least 8 * parallelism.');
    }
    if (params.iterations !== (params.iterations | 0) || params.iterations < 1) {
      throw new Error('iterations must be a positive integer.');
    }
    if (params.parallelism !== (params.parallelism | 0) || params.parallelism < 1) {
      throw new Error('parallelism must be a positive integer.');
    }
    if (params.outputLen !== (params.outputLen | 0) || params.outputLen < 4) {
      throw new Error('outputLen must be an integer at least 4.');
    }
  }

  function writeInt32LE(target, offset, value) {
    target[offset] = value & 255;
    target[offset + 1] = (value >>> 8) & 255;
    target[offset + 2] = (value >>> 16) & 255;
    target[offset + 3] = (value >>> 24) & 255;
  }

  function ensureArgon2Memory(totalBytes) {
    var result;
    argon2BufferPointer = _Argon2_GetBuffer();
    result = _Argon2_SetMemorySize(totalBytes);
    if (result !== 0) {
      throw new Error('Unable to allocate Argon2 memory.');
    }
    updateMemoryViews();
    argon2BufferPointer = _Argon2_GetBuffer();
  }

  function deriveArgon2id(passwordInput, saltInput, params) {
    validateParams(params);

    var password = copyBytes(passwordInput);
    var salt = saltBytes(saltInput);
    if (password.length < 1) {
      throw new Error('Password must be specified.');
    }
    if (salt.length < 8) {
      throw new Error('Salt should be at least 8 bytes long.');
    }

    var version = 0x13;
    var hashType = 2;
    var memoryKib = params.memoryKib;
    var totalBytes = memoryKib * 1024 + 1024;
    var initVector = new Uint8Array(24);
    var segments = Math.floor(memoryKib / (params.parallelism * 4));
    var lanes = segments * 4;
    var h0;
    var param;
    var lane;
    var position;
    var chunk;
    var c;
    var result;

    writeInt32LE(initVector, 0, params.parallelism);
    writeInt32LE(initVector, 4, params.outputLen);
    writeInt32LE(initVector, 8, memoryKib);
    writeInt32LE(initVector, 12, params.iterations);
    writeInt32LE(initVector, 16, version);
    writeInt32LE(initVector, 20, hashType);

    ensureArgon2Memory(totalBytes);
    zeroBytes(HEAPU8, argon2BufferPointer, totalBytes);
    HEAPU8.set(initVector, argon2BufferPointer + memoryKib * 1024);

    h0 = blake2bDigest([
      initVector,
      int32LE(password.length),
      password,
      int32LE(salt.length),
      salt,
      int32LE(0),
      int32LE(0)
    ], 64);

    param = new Uint8Array(72);
    setBytes(param, h0, 0);

    for (lane = 0; lane < params.parallelism; lane++) {
      writeInt32LE(param, 64, 0);
      writeInt32LE(param, 68, lane);
      position = lane * lanes;
      chunk = hashFunc(null, param, 1024);
      HEAPU8.set(chunk, argon2BufferPointer + position * 1024);

      writeInt32LE(param, 64, 1);
      position += 1;
      chunk = hashFunc(null, param, 1024);
      HEAPU8.set(chunk, argon2BufferPointer + position * 1024);
    }

    _Argon2_Calculate(0, memoryKib);
    c = copyRange(HEAPU8, argon2BufferPointer, 1024);
    result = hashFunc(null, c, params.outputLen);
    return bytesToHex(result);
  }

  root.NoPressureArgon2id = {
    deriveArgon2id: deriveArgon2id
  };

  if (typeof module !== 'undefined' && module && module.exports) {
    module.exports = root.NoPressureArgon2id;
  }
};
