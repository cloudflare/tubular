#pragma once

typedef char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;
_Static_assert(sizeof(__s32) == 4, "__s32 must be 4 bytes");
_Static_assert(sizeof(__s64) == 8, "__s64 must be 8 bytes");

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
_Static_assert(sizeof(__u32) == 4, "__u32 must be 4 bytes");
_Static_assert(sizeof(__u64) == 8, "__u64 must be 8 bytes");

typedef __u16 __be16;
typedef __u16 __le16;
typedef __u16 __be32;
typedef __u32 __le32;
typedef __u64 __be64;
typedef __u64 __le64;

typedef __u32 __wsum;

typedef __u64 __attribute__((aligned(8))) __aligned_u64;
