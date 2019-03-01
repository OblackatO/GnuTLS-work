#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <math.h>

#include "eina_types.h"
#include "eina_fp.h"

#define MAX_PREC 1025
static const Eina_F32p32 eina_trigo[MAX_PREC] = {
	0x0000000100000000, 0x00000000ffffec43, 0x00000000ffffb10b,
	0x00000000ffff4e5a, 0x00000000fffec42e, 0x00000000fffe1287,
	0x00000000fffd3967, 0x00000000fffc38cd, 0x00000000fffb10b9,
	0x00000000fff9c12c,
	0x00000000fff84a25, 0x00000000fff6aba5, 0x00000000fff4e5ac,
	0x00000000fff2f83b, 0x00000000fff0e351, 0x00000000ffeea6ef,
	0x00000000ffec4316, 0x00000000ffe9b7c5, 0x00000000ffe704fe,
	0x00000000ffe42ac0,
	0x00000000ffe1290b, 0x00000000ffddffe2, 0x00000000ffdaaf43,
	0x00000000ffd7372f, 0x00000000ffd397a8, 0x00000000ffcfd0ad,
	0x00000000ffcbe23f, 0x00000000ffc7cc5f, 0x00000000ffc38f0d,
	0x00000000ffbf2a4b,
	0x00000000ffba9e17, 0x00000000ffb5ea75, 0x00000000ffb10f63,
	0x00000000ffac0ce3, 0x00000000ffa6e2f6, 0x00000000ffa1919c,
	0x00000000ff9c18d6, 0x00000000ff9678a6, 0x00000000ff90b10b,
	0x00000000ff8ac208,
	0x00000000ff84ab9c, 0x00000000ff7e6dc8, 0x00000000ff78088f,
	0x00000000ff717bf0, 0x00000000ff6ac7ec, 0x00000000ff63ec85,
	0x00000000ff5ce9bc, 0x00000000ff55bf92, 0x00000000ff4e6e08,
	0x00000000ff46f51f,
	0x00000000ff3f54d8, 0x00000000ff378d34, 0x00000000ff2f9e35,
	0x00000000ff2787dc, 0x00000000ff1f4a2a, 0x00000000ff16e520,
	0x00000000ff0e58c0, 0x00000000ff05a50a, 0x00000000fefcca01,
	0x00000000fef3c7a6,
	0x00000000feea9df9, 0x00000000fee14cfe, 0x00000000fed7d4b3,
	0x00000000fece351d, 0x00000000fec46e3b, 0x00000000feba800f,
	0x00000000feb06a9c, 0x00000000fea62de1, 0x00000000fe9bc9e2,
	0x00000000fe913e9f,
	0x00000000fe868c1b, 0x00000000fe7bb256, 0x00000000fe70b153,
	0x00000000fe658913, 0x00000000fe5a3998, 0x00000000fe4ec2e4,
	0x00000000fe4324f9, 0x00000000fe375fd7, 0x00000000fe2b7382,
	0x00000000fe1f5ffa,
	0x00000000fe132543, 0x00000000fe06c35d, 0x00000000fdfa3a4b,
	0x00000000fded8a0e, 0x00000000fde0b2a8, 0x00000000fdd3b41c,
	0x00000000fdc68e6c, 0x00000000fdb94199, 0x00000000fdabcda5,
	0x00000000fd9e3294,
	0x00000000fd907065, 0x00000000fd82871d, 0x00000000fd7476bd,
	0x00000000fd663f46, 0x00000000fd57e0bd, 0x00000000fd495b21,
	0x00000000fd3aae77, 0x00000000fd2bdabf, 0x00000000fd1cdffd,
	0x00000000fd0dbe32,
	0x00000000fcfe7562, 0x00000000fcef058e, 0x00000000fcdf6eb8,
	0x00000000fccfb0e4, 0x00000000fcbfcc13, 0x00000000fcafc048,
	0x00000000fc9f8d86, 0x00000000fc8f33ce, 0x00000000fc7eb325,
	0x00000000fc6e0b8b,
	0x00000000fc5d3d03, 0x00000000fc4c4791, 0x00000000fc3b2b37,
	0x00000000fc29e7f7, 0x00000000fc187dd5, 0x00000000fc06ecd2,
	0x00000000fbf534f2, 0x00000000fbe35637, 0x00000000fbd150a3,
	0x00000000fbbf243b,
	0x00000000fbacd100, 0x00000000fb9a56f6, 0x00000000fb87b61f,
	0x00000000fb74ee7e, 0x00000000fb620016, 0x00000000fb4eeaea,
	0x00000000fb3baefd, 0x00000000fb284c52, 0x00000000fb14c2eb,
	0x00000000fb0112cd,
	0x00000000faed3bf9, 0x00000000fad93e73, 0x00000000fac51a3f,
	0x00000000fab0cf5e, 0x00000000fa9c5dd5, 0x00000000fa87c5a6,
	0x00000000fa7306d5, 0x00000000fa5e2164, 0x00000000fa491558,
	0x00000000fa33e2b3,
	0x00000000fa1e8978, 0x00000000fa0909ab, 0x00000000f9f36350,
	0x00000000f9dd9668, 0x00000000f9c7a2f9, 0x00000000f9b18905,
	0x00000000f99b488f, 0x00000000f984e19c, 0x00000000f96e542e,
	0x00000000f957a049,
	0x00000000f940c5f1, 0x00000000f929c528, 0x00000000f9129df3,
	0x00000000f8fb5056, 0x00000000f8e3dc53, 0x00000000f8cc41ee,
	0x00000000f8b4812b, 0x00000000f89c9a0e, 0x00000000f8848c9b,
	0x00000000f86c58d4,
	0x00000000f853febe, 0x00000000f83b7e5d, 0x00000000f822d7b4,
	0x00000000f80a0ac7, 0x00000000f7f1179a, 0x00000000f7d7fe31,
	0x00000000f7bebe90, 0x00000000f7a558ba, 0x00000000f78bccb3,
	0x00000000f7721a80,
	0x00000000f7584225, 0x00000000f73e43a5, 0x00000000f7241f04,
	0x00000000f709d446, 0x00000000f6ef6370, 0x00000000f6d4cc85,
	0x00000000f6ba0f8a, 0x00000000f69f2c83, 0x00000000f6842374,
	0x00000000f668f461,
	0x00000000f64d9f4e, 0x00000000f632243f, 0x00000000f616833a,
	0x00000000f5fabc41, 0x00000000f5decf59, 0x00000000f5c2bc87,
	0x00000000f5a683cf, 0x00000000f58a2535, 0x00000000f56da0be,
	0x00000000f550f66e,
	0x00000000f5342649, 0x00000000f5173054, 0x00000000f4fa1494,
	0x00000000f4dcd30c, 0x00000000f4bf6bc2, 0x00000000f4a1deb9,
	0x00000000f4842bf7, 0x00000000f4665380, 0x00000000f4485559,
	0x00000000f42a3186,
	0x00000000f40be80c, 0x00000000f3ed78ef, 0x00000000f3cee434,
	0x00000000f3b029e1, 0x00000000f39149f9, 0x00000000f3724482,
	0x00000000f3531980, 0x00000000f333c8f8, 0x00000000f31452ef,
	0x00000000f2f4b76a,
	0x00000000f2d4f66d, 0x00000000f2b50ffe, 0x00000000f2950421,
	0x00000000f274d2dc, 0x00000000f2547c33, 0x00000000f234002b,
	0x00000000f2135eca, 0x00000000f1f29814, 0x00000000f1d1ac0e,
	0x00000000f1b09abe,
	0x00000000f18f6429, 0x00000000f16e0853, 0x00000000f14c8742,
	0x00000000f12ae0fb, 0x00000000f1091583, 0x00000000f0e724e0,
	0x00000000f0c50f17, 0x00000000f0a2d42c, 0x00000000f0807426,
	0x00000000f05def09,
	0x00000000f03b44db, 0x00000000f01875a1, 0x00000000eff58161,
	0x00000000efd2681f, 0x00000000efaf29e2, 0x00000000ef8bc6af,
	0x00000000ef683e8b, 0x00000000ef44917b, 0x00000000ef20bf86,
	0x00000000eefcc8b1,
	0x00000000eed8ad01, 0x00000000eeb46c7b, 0x00000000ee900727,
	0x00000000ee6b7d08, 0x00000000ee46ce25, 0x00000000ee21fa83,
	0x00000000edfd0228, 0x00000000edd7e51a, 0x00000000edb2a35f,
	0x00000000ed8d3cfc,
	0x00000000ed67b1f6, 0x00000000ed420255, 0x00000000ed1c2e1d,
	0x00000000ecf63554, 0x00000000ecd01801, 0x00000000eca9d628,
	0x00000000ec836fd1, 0x00000000ec5ce501, 0x00000000ec3635bd,
	0x00000000ec0f620d,
	0x00000000ebe869f5, 0x00000000ebc14d7d, 0x00000000eb9a0ca9,
	0x00000000eb72a780, 0x00000000eb4b1e08, 0x00000000eb237047,
	0x00000000eafb9e43, 0x00000000ead3a803, 0x00000000eaab8d8d,
	0x00000000ea834ee6,
	0x00000000ea5aec15, 0x00000000ea326520, 0x00000000ea09ba0d,
	0x00000000e9e0eae4, 0x00000000e9b7f7a9, 0x00000000e98ee063,
	0x00000000e965a51a, 0x00000000e93c45d2, 0x00000000e912c292,
	0x00000000e8e91b61,
	0x00000000e8bf5046, 0x00000000e8956146, 0x00000000e86b4e68,
	0x00000000e84117b3, 0x00000000e816bd2d, 0x00000000e7ec3edc,
	0x00000000e7c19cc8, 0x00000000e796d6f6, 0x00000000e76bed6e,
	0x00000000e740e036,
	0x00000000e715af54, 0x00000000e6ea5ad0, 0x00000000e6bee2af,
	0x00000000e69346f9, 0x00000000e66787b5, 0x00000000e63ba4e9,
	0x00000000e60f9e9b, 0x00000000e5e374d4, 0x00000000e5b72798,
	0x00000000e58ab6f1,
	0x00000000e55e22e3, 0x00000000e5316b76, 0x00000000e50490b1,
	0x00000000e4d7929c, 0x00000000e4aa713c, 0x00000000e47d2c98,
	0x00000000e44fc4b9, 0x00000000e42239a4, 0x00000000e3f48b61,
	0x00000000e3c6b9f7,
	0x00000000e398c56c, 0x00000000e36aadc9, 0x00000000e33c7314,
	0x00000000e30e1554, 0x00000000e2df9490, 0x00000000e2b0f0d0,
	0x00000000e2822a1a, 0x00000000e2534077, 0x00000000e22433ec,
	0x00000000e1f50482,
	0x00000000e1c5b240, 0x00000000e1963d2d, 0x00000000e166a550,
	0x00000000e136eab0, 0x00000000e1070d56, 0x00000000e0d70d48,
	0x00000000e0a6ea8e, 0x00000000e076a52f, 0x00000000e0463d33,
	0x00000000e015b2a1,
	0x00000000dfe50580, 0x00000000dfb435d9, 0x00000000df8343b2,
	0x00000000df522f13, 0x00000000df20f804, 0x00000000deef9e8d,
	0x00000000debe22b5, 0x00000000de8c8483, 0x00000000de5ac3ff,
	0x00000000de28e131,
	0x00000000ddf6dc21, 0x00000000ddc4b4d6, 0x00000000dd926b59,
	0x00000000dd5fffb0, 0x00000000dd2d71e3, 0x00000000dcfac1fb,
	0x00000000dcc7f000, 0x00000000dc94fbf8, 0x00000000dc61e5ec,
	0x00000000dc2eade4,
	0x00000000dbfb53e8, 0x00000000dbc7d7ff, 0x00000000db943a31,
	0x00000000db607a88, 0x00000000db2c9909, 0x00000000daf895bf,
	0x00000000dac470af, 0x00000000da9029e3, 0x00000000da5bc163,
	0x00000000da273737,
	0x00000000d9f28b66, 0x00000000d9bdbdf9, 0x00000000d988cef8,
	0x00000000d953be6b, 0x00000000d91e8c5b, 0x00000000d8e938d0,
	0x00000000d8b3c3d1, 0x00000000d87e2d67, 0x00000000d848759b,
	0x00000000d8129c74,
	0x00000000d7dca1fb, 0x00000000d7a68638, 0x00000000d7704934,
	0x00000000d739eaf7, 0x00000000d7036b89, 0x00000000d6cccaf3,
	0x00000000d696093d, 0x00000000d65f266f, 0x00000000d6282293,
	0x00000000d5f0fdb0,
	0x00000000d5b9b7d0, 0x00000000d58250fa, 0x00000000d54ac937,
	0x00000000d513208f, 0x00000000d4db570c, 0x00000000d4a36cb6,
	0x00000000d46b6195, 0x00000000d43335b3, 0x00000000d3fae917,
	0x00000000d3c27bcb,
	0x00000000d389edd7, 0x00000000d3513f43, 0x00000000d318701a,
	0x00000000d2df8063, 0x00000000d2a67027, 0x00000000d26d3f6f,
	0x00000000d233ee43, 0x00000000d1fa7cae, 0x00000000d1c0eab7,
	0x00000000d1873867,
	0x00000000d14d65c8, 0x00000000d11372e1, 0x00000000d0d95fbd,
	0x00000000d09f2c64, 0x00000000d064d8df, 0x00000000d02a6537,
	0x00000000cfefd176, 0x00000000cfb51da3, 0x00000000cf7a49c8,
	0x00000000cf3f55ef,
	0x00000000cf044220, 0x00000000cec90e64, 0x00000000ce8dbac5,
	0x00000000ce52474c, 0x00000000ce16b401, 0x00000000cddb00ef,
	0x00000000cd9f2e1e, 0x00000000cd633b97, 0x00000000cd272964,
	0x00000000cceaf78e,
	0x00000000ccaea61e, 0x00000000cc72351e, 0x00000000cc35a497,
	0x00000000cbf8f492, 0x00000000cbbc2519, 0x00000000cb7f3634,
	0x00000000cb4227ee, 0x00000000cb04fa50, 0x00000000cac7ad63,
	0x00000000ca8a4131,
	0x00000000ca4cb5c3, 0x00000000ca0f0b22, 0x00000000c9d14159,
	0x00000000c9935870, 0x00000000c9555072, 0x00000000c9172967,
	0x00000000c8d8e35a, 0x00000000c89a7e53, 0x00000000c85bfa5e,
	0x00000000c81d5782,
	0x00000000c7de95cb, 0x00000000c79fb541, 0x00000000c760b5ee,
	0x00000000c72197dc, 0x00000000c6e25b15, 0x00000000c6a2ffa3,
	0x00000000c663858f, 0x00000000c623ece2, 0x00000000c5e435a8,
	0x00000000c5a45fe9,
	0x00000000c5646bb0, 0x00000000c5245906, 0x00000000c4e427f6,
	0x00000000c4a3d888, 0x00000000c4636ac8, 0x00000000c422debf,
	0x00000000c3e23476, 0x00000000c3a16bf9, 0x00000000c3608550,
	0x00000000c31f8087,
	0x00000000c2de5da6, 0x00000000c29d1cb8, 0x00000000c25bbdc8,
	0x00000000c21a40de, 0x00000000c1d8a606, 0x00000000c196ed49,
	0x00000000c15516b2, 0x00000000c113224a, 0x00000000c0d1101d,
	0x00000000c08ee033,
	0x00000000c04c9297, 0x00000000c00a2754, 0x00000000bfc79e73,
	0x00000000bf84f800, 0x00000000bf423404, 0x00000000beff5289,
	0x00000000bebc539a, 0x00000000be793741, 0x00000000be35fd89,
	0x00000000bdf2a67b,
	0x00000000bdaf3223, 0x00000000bd6ba08b, 0x00000000bd27f1bc,
	0x00000000bce425c2, 0x00000000bca03ca7, 0x00000000bc5c3676,
	0x00000000bc181338, 0x00000000bbd3d2f9, 0x00000000bb8f75c3,
	0x00000000bb4afba1,
	0x00000000bb06649c, 0x00000000bac1b0c0, 0x00000000ba7ce018,
	0x00000000ba37f2ad, 0x00000000b9f2e88b, 0x00000000b9adc1bc,
	0x00000000b9687e4a, 0x00000000b9231e41, 0x00000000b8dda1ac,
	0x00000000b8980894,
	0x00000000b8525305, 0x00000000b80c8109, 0x00000000b7c692ac,
	0x00000000b78087f7, 0x00000000b73a60f6, 0x00000000b6f41db4,
	0x00000000b6adbe3a, 0x00000000b6674296, 0x00000000b620aad0,
	0x00000000b5d9f6f4,
	0x00000000b593270e, 0x00000000b54c3b27, 0x00000000b505334a,
	0x00000000b4be0f84, 0x00000000b476cfde, 0x00000000b42f7464,
	0x00000000b3e7fd20, 0x00000000b3a06a1e, 0x00000000b358bb69,
	0x00000000b310f10c,
	0x00000000b2c90b11, 0x00000000b2810985, 0x00000000b238ec71,
	0x00000000b1f0b3e2, 0x00000000b1a85fe2, 0x00000000b15ff07c,
	0x00000000b11765bc, 0x00000000b0cebfad, 0x00000000b085fe5a,
	0x00000000b03d21ce,
	0x00000000aff42a15, 0x00000000afab1739, 0x00000000af61e946,
	0x00000000af18a048, 0x00000000aecf3c49, 0x00000000ae85bd55,
	0x00000000ae3c2377, 0x00000000adf26ebb, 0x00000000ada89f2c,
	0x00000000ad5eb4d5,
	0x00000000ad14afc2, 0x00000000acca8ffd, 0x00000000ac805594,
	0x00000000ac360090, 0x00000000abeb90fe, 0x00000000aba106e9,
	0x00000000ab56625d, 0x00000000ab0ba364, 0x00000000aac0ca0b,
	0x00000000aa75d65d,
	0x00000000aa2ac865, 0x00000000a9dfa030, 0x00000000a9945dc9,
	0x00000000a949013a, 0x00000000a8fd8a91, 0x00000000a8b1f9d8,
	0x00000000a8664f1c, 0x00000000a81a8a68, 0x00000000a7ceabc7,
	0x00000000a782b345,
	0x00000000a736a0ef, 0x00000000a6ea74cf, 0x00000000a69e2ef2,
	0x00000000a651cf63, 0x00000000a605562f, 0x00000000a5b8c360,
	0x00000000a56c1702, 0x00000000a51f5123, 0x00000000a4d271cc,
	0x00000000a485790b,
	0x00000000a43866eb, 0x00000000a3eb3b77, 0x00000000a39df6bd,
	0x00000000a35098c7, 0x00000000a30321a2, 0x00000000a2b5915a,
	0x00000000a267e7fa, 0x00000000a21a258e, 0x00000000a1cc4a24,
	0x00000000a17e55c5,
	0x00000000a1304880, 0x00000000a0e2225f, 0x00000000a093e36f,
	0x00000000a0458bbb, 0x000000009ff71b50, 0x000000009fa8923a,
	0x000000009f59f086, 0x000000009f0b363e, 0x000000009ebc6370,
	0x000000009e6d7827,
	0x000000009e1e746f, 0x000000009dcf5856, 0x000000009d8023e6,
	0x000000009d30d72d, 0x000000009ce17236, 0x000000009c91f50e,
	0x000000009c425fc1, 0x000000009bf2b25b, 0x000000009ba2ece8,
	0x000000009b530f76,
	0x000000009b031a0f, 0x000000009ab30cc1, 0x000000009a62e797,
	0x000000009a12aa9f, 0x0000000099c255e5, 0x000000009971e974,
	0x000000009921655a, 0x0000000098d0c9a2, 0x0000000098801659,
	0x00000000982f4b8d,
	0x0000000097de6948, 0x00000000978d6f97, 0x00000000973c5e88,
	0x0000000096eb3626, 0x000000009699f67f, 0x0000000096489f9e,
	0x0000000095f73190, 0x0000000095a5ac61, 0x000000009554101f,
	0x0000000095025cd6,
	0x0000000094b09292, 0x00000000945eb161, 0x00000000940cb94e,
	0x0000000093baaa66, 0x00000000936884b6, 0x000000009316484b,
	0x0000000092c3f531, 0x0000000092718b75, 0x00000000921f0b24,
	0x0000000091cc744b,
	0x000000009179c6f5, 0x0000000091270331, 0x0000000090d4290a,
	0x000000009081388e, 0x00000000902e31c8, 0x000000008fdb14c7,
	0x000000008f87e197, 0x000000008f349845, 0x000000008ee138dd,
	0x000000008e8dc36c,
	0x000000008e3a3800, 0x000000008de696a5, 0x000000008d92df68,
	0x000000008d3f1256, 0x000000008ceb2f7c, 0x000000008c9736e7,
	0x000000008c4328a3, 0x000000008bef04bf, 0x000000008b9acb46,
	0x000000008b467c45,
	0x000000008af217cb, 0x000000008a9d9de3, 0x000000008a490e9b,
	0x0000000089f469ff, 0x00000000899fb01e, 0x00000000894ae103,
	0x0000000088f5fcbc, 0x0000000088a10357, 0x00000000884bf4df,
	0x0000000087f6d163,
	0x0000000087a198f0, 0x00000000874c4b92, 0x0000000086f6e956,
	0x0000000086a1724b, 0x00000000864be67c, 0x0000000085f645f8,
	0x0000000085a090cc, 0x00000000854ac704, 0x0000000084f4e8ad,
	0x00000000849ef5d7,
	0x000000008448ee8c, 0x0000000083f2d2db, 0x00000000839ca2d1,
	0x0000000083465e7c, 0x0000000082f005e8, 0x0000000082999922,
	0x0000000082431839, 0x0000000081ec833a, 0x000000008195da31,
	0x00000000813f1d2d,
	0x0000000080e84c3a, 0x0000000080916766, 0x00000000803a6ebf,
	0x000000007fe36251, 0x000000007f8c422b, 0x000000007f350e59,
	0x000000007eddc6ea, 0x000000007e866bea, 0x000000007e2efd67,
	0x000000007dd77b6f,
	0x000000007d7fe60f, 0x000000007d283d54, 0x000000007cd0814c,
	0x000000007c78b205, 0x000000007c20cf8c, 0x000000007bc8d9ef,
	0x000000007b70d13b, 0x000000007b18b57e, 0x000000007ac086c5,
	0x000000007a68451f,
	0x000000007a0ff098, 0x0000000079b7893e, 0x00000000795f0f1f,
	0x0000000079068248, 0x0000000078ade2c8, 0x00000000785530ab,
	0x0000000077fc6c01, 0x0000000077a394d5, 0x00000000774aab36,
	0x0000000076f1af32,
	0x000000007698a0d6, 0x00000000763f8030, 0x0000000075e64d4e,
	0x00000000758d083e, 0x000000007533b10d, 0x0000000074da47c9,
	0x000000007480cc80, 0x0000000074273f3f, 0x0000000073cda016,
	0x000000007373ef10,
	0x00000000731a2c3d, 0x0000000072c057aa, 0x0000000072667164,
	0x00000000720c797a, 0x0000000071b26ffa, 0x00000000715854f2,
	0x0000000070fe286e, 0x0000000070a3ea7e, 0x0000000070499b30,
	0x000000006fef3a90,
	0x000000006f94c8ae, 0x000000006f3a4596, 0x000000006edfb157,
	0x000000006e850c00, 0x000000006e2a559d, 0x000000006dcf8e3d,
	0x000000006d74b5ee, 0x000000006d19ccbe, 0x000000006cbed2bb,
	0x000000006c63c7f3,
	0x000000006c08ac74, 0x000000006bad804c, 0x000000006b524389,
	0x000000006af6f639, 0x000000006a9b986b, 0x000000006a402a2c,
	0x0000000069e4ab8a, 0x0000000069891c94, 0x00000000692d7d57,
	0x0000000068d1cde3,
	0x0000000068760e44, 0x00000000681a3e89, 0x0000000067be5ec1,
	0x0000000067626ef9, 0x0000000067066f40, 0x0000000066aa5fa3,
	0x00000000664e4032, 0x0000000065f210f9, 0x000000006595d209,
	0x000000006539836d,
	0x0000000064dd2536, 0x000000006480b770, 0x0000000064243a2b,
	0x0000000063c7ad75, 0x00000000636b115c, 0x00000000630e65ed,
	0x0000000062b1ab39, 0x000000006254e14c, 0x0000000061f80835,
	0x00000000619b2002,
	0x00000000613e28c2, 0x0000000060e12283, 0x0000000060840d54,
	0x000000006026e943, 0x000000005fc9b65d, 0x000000005f6c74b2,
	0x000000005f0f2450, 0x000000005eb1c545, 0x000000005e5457a0,
	0x000000005df6db6f,
	0x000000005d9950c0, 0x000000005d3bb7a3, 0x000000005cde1024,
	0x000000005c805a54, 0x000000005c22963f, 0x000000005bc4c3f6,
	0x000000005b66e385, 0x000000005b08f4fd, 0x000000005aaaf86a,
	0x000000005a4ceddc,
	0x0000000059eed561, 0x000000005990af08, 0x0000000059327adf,
	0x0000000058d438f4, 0x000000005875e957, 0x0000000058178c16,
	0x0000000057b9213f, 0x00000000575aa8e0, 0x0000000056fc230a,
	0x00000000569d8fc9,
	0x00000000563eef2d, 0x0000000055e04144, 0x000000005581861d,
	0x000000005522bdc6, 0x0000000054c3e84e, 0x00000000546505c4,
	0x0000000054061636, 0x0000000053a719b3, 0x000000005348104a,
	0x0000000052e8fa09,
	0x000000005289d6ff, 0x00000000522aa73a, 0x0000000051cb6aca,
	0x00000000516c21bc, 0x00000000510ccc20, 0x0000000050ad6a05,
	0x00000000504dfb78, 0x000000004fee808a, 0x000000004f8ef947,
	0x000000004f2f65c0,
	0x000000004ecfc603, 0x000000004e701a1f, 0x000000004e106222,
	0x000000004db09e1b, 0x000000004d50ce19, 0x000000004cf0f22b,
	0x000000004c910a5f, 0x000000004c3116c5, 0x000000004bd1176b,
	0x000000004b710c5f,
	0x000000004b10f5b2, 0x000000004ab0d371, 0x000000004a50a5ab,
	0x0000000049f06c70, 0x00000000499027cd, 0x00000000492fd7d3,
	0x0000000048cf7c8f, 0x00000000486f1611, 0x00000000480ea467,
	0x0000000047ae27a1,
	0x00000000474d9fcd, 0x0000000046ed0cfa, 0x00000000468c6f37,
	0x00000000462bc693, 0x0000000045cb131c, 0x00000000456a54e3,
	0x0000000045098bf5, 0x0000000044a8b861, 0x000000004447da37,
	0x0000000043e6f186,
	0x000000004385fe5c, 0x00000000432500c8, 0x0000000042c3f8d9,
	0x000000004262e69f, 0x000000004201ca28, 0x0000000041a0a383,
	0x00000000413f72bf, 0x0000000040de37eb, 0x00000000407cf317,
	0x00000000401ba450,
	0x000000003fba4ba7, 0x000000003f58e92a, 0x000000003ef77ce8,
	0x000000003e9606f1, 0x000000003e348752, 0x000000003dd2fe1c,
	0x000000003d716b5e, 0x000000003d0fcf25, 0x000000003cae2982,
	0x000000003c4c7a83,
	0x000000003beac238, 0x000000003b8900b0, 0x000000003b2735f9,
	0x000000003ac56223, 0x000000003a63853d, 0x000000003a019f56,
	0x00000000399fb07d, 0x00000000393db8c1, 0x0000000038dbb831,
	0x000000003879aedd,
	0x0000000038179cd3, 0x0000000037b58222, 0x0000000037535edb,
	0x0000000036f1330b, 0x00000000368efec2, 0x00000000362cc20f,
	0x0000000035ca7d02, 0x0000000035682fa9, 0x000000003505da14,
	0x0000000034a37c51,
	0x0000000034411671, 0x0000000033dea881, 0x00000000337c3292,
	0x000000003319b4b3, 0x0000000032b72ef2, 0x000000003254a15e,
	0x0000000031f20c08, 0x00000000318f6efe, 0x00000000312cca50,
	0x0000000030ca1e0c,
	0x0000000030676a43, 0x000000003004af02, 0x000000002fa1ec5a,
	0x000000002f3f2259, 0x000000002edc510f, 0x000000002e79788b,
	0x000000002e1698dc, 0x000000002db3b212, 0x000000002d50c43c,
	0x000000002cedcf68,
	0x000000002c8ad3a7, 0x000000002c27d108, 0x000000002bc4c799,
	0x000000002b61b76b, 0x000000002afea08c, 0x000000002a9b830b,
	0x000000002a385ef9, 0x0000000029d53464, 0x000000002972035b,
	0x00000000290ecbee,
	0x0000000028ab8e2c, 0x0000000028484a25, 0x0000000027e4ffe7,
	0x000000002781af83, 0x00000000271e5906, 0x0000000026bafc82,
	0x0000000026579a04, 0x0000000025f4319d, 0x000000002590c35c,
	0x00000000252d4f4f,
	0x0000000024c9d587, 0x0000000024665613, 0x000000002402d101,
	0x00000000239f4662, 0x00000000233bb644, 0x0000000022d820b8,
	0x00000000227485cc, 0x000000002210e590, 0x0000000021ad4013,
	0x0000000021499565,
	0x0000000020e5e594, 0x00000000208230b1, 0x00000000201e76ca,
	0x000000001fbab7ef, 0x000000001f56f430, 0x000000001ef32b9b,
	0x000000001e8f5e41, 0x000000001e2b8c30, 0x000000001dc7b578,
	0x000000001d63da29,
	0x000000001cfffa51, 0x000000001c9c1600, 0x000000001c382d46,
	0x000000001bd44032, 0x000000001b704ed3, 0x000000001b0c5939,
	0x000000001aa85f74, 0x000000001a446191, 0x0000000019e05fa2,
	0x00000000197c59b5,
	0x0000000019184fdb, 0x0000000018b44221, 0x0000000018503098,
	0x0000000017ec1b50, 0x0000000017880257, 0x000000001723e5bd,
	0x0000000016bfc591, 0x00000000165ba1e4, 0x0000000015f77ac3,
	0x0000000015935040,
	0x00000000152f2269, 0x0000000014caf14d, 0x000000001466bcfd,
	0x0000000014028587, 0x00000000139e4afb, 0x00000000133a0d69,
	0x0000000012d5cce0, 0x000000001271896f, 0x00000000120d4326,
	0x0000000011a8fa15,
	0x000000001144ae4a, 0x0000000010e05fd6, 0x00000000107c0ec7,
	0x000000001017bb2d, 0x000000000fb36519, 0x000000000f4f0c98,
	0x000000000eeab1bb, 0x000000000e865491, 0x000000000e21f52a,
	0x000000000dbd9395,
	0x000000000d592fe1, 0x000000000cf4ca1f, 0x000000000c90625c,
	0x000000000c2bf8aa, 0x000000000bc78d18, 0x000000000b631fb4,
	0x000000000afeb08f, 0x000000000a9a3fb8, 0x000000000a35cd3e,
	0x0000000009d15931,
	0x00000000096ce3a1, 0x0000000009086c9c, 0x0000000008a3f433,
	0x00000000083f7a75, 0x0000000007daff71, 0x0000000007768337,
	0x00000000071205d6, 0x0000000006ad875f, 0x00000000064907df,
	0x0000000005e48768,
	0x0000000005800608, 0x00000000051b83cf, 0x0000000004b700cc,
	0x0000000004527d0f, 0x0000000003edf8a7, 0x00000000038973a4,
	0x000000000324ee16, 0x0000000002c0680b, 0x00000000025be194,
	0x0000000001f75ac0,
	0x000000000192d39e, 0x00000000012e4c3e, 0x0000000000c9c4af,
	0x0000000000653d02, 0x0000000000000000
};

EAPI Eina_F32p32 eina_f32p32_cos(Eina_F32p32 a)
{
	Eina_F32p32 F32P32_2PI;
	Eina_F32p32 F32P32_PI2;
	Eina_F32p32 F32P32_3PI2;
	Eina_F32p32 remainder_2PI;
	Eina_F32p32 remainder_PI;
	Eina_F32p32 interpol;
	Eina_F32p32 result;
	int idx;
	int index2;

	F32P32_2PI = EINA_F32P32_PI << 1;
	F32P32_PI2 = EINA_F32P32_PI >> 1;
	F32P32_3PI2 = EINA_F32P32_PI + F32P32_PI2;

	/* Take advantage of cosinus symetrie. */
	a = eina_fp32p32_llabs(a);

	/* Find table entry in 0 to PI / 2 */
	remainder_PI = a - (a / EINA_F32P32_PI) * EINA_F32P32_PI;

	/* Find which case from 0 to 2 * PI */
	remainder_2PI = a - (a / F32P32_2PI) * F32P32_2PI;

	interpol =
	    eina_f32p32_div(eina_f32p32_scale(remainder_PI, MAX_PREC * 2),
			    EINA_F32P32_PI);
	idx = eina_f32p32_int_to(interpol);
	if (idx >= MAX_PREC)
		idx = 2 * MAX_PREC - (idx - 1);

	index2 = idx + 1;
	if (index2 == MAX_PREC)
		index2 = idx - 1;

	result = eina_f32p32_add(eina_trigo[idx],
				 eina_f32p32_mul(eina_f32p32_sub
						 (eina_trigo[idx],
						  eina_trigo[index2]),
						 (Eina_F32p32)
						 eina_f32p32_fracc_get
						 (interpol)));

	if (0 <= remainder_2PI && remainder_2PI < F32P32_PI2)
		return result;
	else if (F32P32_PI2 <= remainder_2PI
		 && remainder_2PI < EINA_F32P32_PI)
		return -result;
	else if (EINA_F32P32_PI <= remainder_2PI
		 && remainder_2PI < F32P32_3PI2)
		return -result;
	else			/*  if (F32P32_3PI2 <= remainder_2PI) */
		return result;
}

EAPI Eina_F32p32 eina_f32p32_sin(Eina_F32p32 a)
{
	Eina_F32p32 F32P32_2PI;
	Eina_F32p32 F32P32_PI2;
	Eina_F32p32 F32P32_3PI2;
	Eina_F32p32 remainder_2PI;
	Eina_F32p32 remainder_PI;
	Eina_F32p32 interpol;
	Eina_F32p32 result;
	int idx;
	int index2;

	F32P32_2PI = EINA_F32P32_PI << 1;
	F32P32_PI2 = EINA_F32P32_PI >> 1;
	F32P32_3PI2 = EINA_F32P32_PI + F32P32_PI2;

	/* We only have a table for cosinus, but sin(a) = cos(pi / 2 - a) */
	a = eina_f32p32_sub(F32P32_PI2, a);

	/* Take advantage of cosinus symetrie. */
	a = eina_fp32p32_llabs(a);

	/* Find table entry in 0 to PI / 2 */
	remainder_PI = a - (a / EINA_F32P32_PI) * EINA_F32P32_PI;

	/* Find which case from 0 to 2 * PI */
	remainder_2PI = a - (a / F32P32_2PI) * F32P32_2PI;

	interpol =
	    eina_f32p32_div(eina_f32p32_scale(remainder_PI, MAX_PREC * 2),
			    EINA_F32P32_PI);
	idx = eina_f32p32_int_to(interpol);
	if (idx >= MAX_PREC)
		idx = 2 * MAX_PREC - (idx + 1);

	index2 = idx + 1;
	if (index2 == MAX_PREC)
		index2 = idx - 1;

	result = eina_f32p32_add(eina_trigo[idx],
				 eina_f32p32_mul(eina_f32p32_sub
						 (eina_trigo[idx],
						  eina_trigo[index2]),
						 (Eina_F32p32)
						 eina_f32p32_fracc_get
						 (interpol)));

	if (0 <= remainder_2PI && remainder_2PI < F32P32_PI2)
		return result;
	else if (F32P32_PI2 <= remainder_2PI
		 && remainder_2PI < EINA_F32P32_PI)
		return -result;
	else if (EINA_F32P32_PI <= remainder_2PI
		 && remainder_2PI < F32P32_3PI2)
		return -result;
	else			/* if (F32P32_3PI2 <= remainder_2PI) */
		return result;
}
