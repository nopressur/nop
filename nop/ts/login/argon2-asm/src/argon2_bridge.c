/*
 * This file is part of the product NoPressure.
 * SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
 */

#include <stdint.h>
#include <stdalign.h>

#define ARGON2_ASM_MAX_MEMORY_BYTES (96u * 1024u * 1024u)

#define P Argon2_P
#define Hash_GetBuffer Argon2_Original_GetBuffer
#define Hash_SetMemorySize Argon2_Original_SetMemorySize
#define Hash_Calculate Argon2_Calculate
#define __builtin_wasm_memory_grow(index, blocks) (-1)
#define __builtin_wasm_memory_size(index) (0)
#include "argon2.c"
#undef __builtin_wasm_memory_size
#undef __builtin_wasm_memory_grow
#undef Hash_Calculate
#undef Hash_SetMemorySize
#undef Hash_GetBuffer
#undef P

alignas(128) static uint8_t argon2_asm_buffer[ARGON2_ASM_MAX_MEMORY_BYTES];

WASM_EXPORT
int8_t Argon2_SetMemorySize(uint32_t total_bytes) {
  if (total_bytes > ARGON2_ASM_MAX_MEMORY_BYTES) {
    return -1;
  }
  B = argon2_asm_buffer;
  B_size = ARGON2_ASM_MAX_MEMORY_BYTES;
  return 0;
}

WASM_EXPORT
uint8_t *Argon2_GetBuffer() {
  B = argon2_asm_buffer;
  B_size = ARGON2_ASM_MAX_MEMORY_BYTES;
  return B;
}
