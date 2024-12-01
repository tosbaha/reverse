def checkpoint_0(flag):
    accumulated_value = flag[4] * 0xef7a8c
    accumulated_value += 0x9d865d8d #0x637aa373
    assert(0x100af1b85 == accumulated_value)
    accumulated_value += flag[24] * -0x45b53c
    accumulated_value += 0x18baee57 #0xe84612a9
    assert(0x10c125960 == accumulated_value)
    accumulated_value += flag[0] * -0xe4cf8b
    accumulated_value -= 0x913fbbde #0x913fbbde
    assert(0x241ff9d7 == accumulated_value)
    accumulated_value += flag[8] * -0xf5c990
    accumulated_value += 0x6bfaa656 #0x95065aaa
    assert(0x434ba32d == accumulated_value)
    accumulated_value ^= flag[18] * 0x733178
    accumulated_value ^= 0x61e3db3b #0x9f1d25c5
    assert(0x37313e96 == accumulated_value)
    accumulated_value ^= flag[4] * 0x9a17b8
    accumulated_value -= 0xca2804b1 #0xca2804b1
    assert(0xffffffff3ed4e7f5 == accumulated_value)
    accumulated_value ^= flag[0] * 0x773850
    accumulated_value ^= 0x5a6f68be #0xa6919842
    assert(0xffffffff4997d91b == accumulated_value)
    accumulated_value ^= flag[28] * 0xe21d3d
    accumulated_value ^= 0x5c911d23 #0xa46fe3dd
    assert(0xffffffff7cfb70a0 == accumulated_value)
    accumulated_value -= 0x81647a79 #0xa46fe3dd
    assert(0xfffffffefb96f627 == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_1(flag):
    accumulated_value = flag[17] * 0x99aa81
    accumulated_value -= 0x74edea51 #0x74edea51
    assert(0xffffffffad490c68 == accumulated_value)
    accumulated_value ^= flag[0] * 0x4aba22
    accumulated_value += 0x598015bf #0xa780eb41
    assert(0xa99a049 == accumulated_value)
    accumulated_value ^= flag[3] * 0x91a68a
    accumulated_value ^= 0x6df18e52 #0x930f72ae
    assert(0x5a1a6c23 == accumulated_value)
    accumulated_value ^= flag[1] * 0x942fde
    accumulated_value += 0x15c825ee #0xeb38db12
    assert(0x2e541287 == accumulated_value)
    accumulated_value += flag[1] * -0xfe2fbe
    accumulated_value += 0xd5682b64 #0x2b98d59c
    assert(0x918ccb91 == accumulated_value)
    accumulated_value += flag[29] * -0xd7e52f
    accumulated_value += 0x798bd018 #0x877530e8
    assert(0xbf320923 == accumulated_value)
    accumulated_value ^= flag[25] * 0xe44f6a
    accumulated_value -= 0xe66d523e #0xe66d523e
    assert(0xffffffffabdc88ff == accumulated_value)
    accumulated_value += flag[9] * 0xaf71d6
    accumulated_value += 0x921122d3 #0x6eefde2d
    assert(0x6a799328 == accumulated_value)
    accumulated_value -= 0xe1148bae #0x6eefde2d
    assert(0xffffffff8965077a == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_2(flag):
    accumulated_value = flag[10] * 0x48c500
    accumulated_value -= 0x8fdaa1bc #0x8fdaa1bc
    assert(0xffffffff87bd3d44 == accumulated_value)
    accumulated_value += flag[30] * -0x152887
    accumulated_value += 0x65f04e48 #0x9b10b2b8
    assert(0xffffffffe3983b36 == accumulated_value)
    accumulated_value += flag[2] * -0xaa4247
    accumulated_value += 0x3d63ec69 #0xc39d1497
    assert(0xffffffff9c75bb13 == accumulated_value)
    accumulated_value ^= flag[22] * 0x38d82d
    accumulated_value ^= 0x872eca8f #0x79d23671
    assert(0xffffffff0bfc24b3 == accumulated_value)
    accumulated_value ^= flag[26] * 0xf120ac
    accumulated_value += 0x803dbdcf #0x80c34331
    assert(0xffffffffec9deb2a == accumulated_value)
    accumulated_value += flag[2] * 0x254def
    accumulated_value += 0xee3813b3 #0x12c8ed4d
    assert(0xffffffff15084f35 == accumulated_value)
    accumulated_value ^= flag[18] * 0x9ef3e7
    accumulated_value -= 0x6deaa90b #0x6deaa90b
    assert(0xfffffffe9adb4b5a == accumulated_value)
    accumulated_value -= flag[1] * 0x69c573
    accumulated_value -= 0xc9ac5c5d #0xc9ac5c5d
    assert(0xfffffffe00b2a1a6 == accumulated_value)
    accumulated_value -= 0x0d46c1f3 #0xc9ac5c5d
    assert(0xfffffffd0cf86299 == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_3(flag):
    accumulated_value = flag[11] * 0x67dda4
    accumulated_value += 0xf4753afc #0x0c8bc604
    assert(0x11fdede88 == accumulated_value)
    accumulated_value += flag[31] * 0x5bb860
    accumulated_value += 0xc1d47fc9 #0x3f2c8137
    assert(0x1f87ec641 == accumulated_value)
    accumulated_value ^= flag[23] * 0xab0ce5
    accumulated_value += 0x544ff977 #0xacb10789
    assert(0x22d663c72 == accumulated_value)
    accumulated_value -= flag[2] * 0x148e94
    accumulated_value -= 0x9cb3e419 #0x9cb3e419
    assert(0x198ba0a29 == accumulated_value)
    accumulated_value += flag[3] * -0x9e06ae
    accumulated_value -= 0xadc62064 #0xadc62064
    assert(0xa849185d == accumulated_value)
    accumulated_value ^= flag[3] * 0xfb9de1
    accumulated_value ^= 0x4e3633f7 #0xb2cacd09
    assert(0x8c59b146 == accumulated_value)
    accumulated_value += flag[27] * -0xa8a511
    accumulated_value += 0xa61f9208 #0x5ae16ef8
    assert(0xc6c0b0ec == accumulated_value)
    accumulated_value += flag[19] * 0xd3468d
    accumulated_value += 0x4a5d7b48 #0xb6a385b8
    assert(0x13f559b0c == accumulated_value)
    accumulated_value -= 0xef6412a2 #0xb6a385b8
    assert(0x4ff1886a == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_4(flag):
    accumulated_value = flag[0] * 0x640ba9
    accumulated_value += 0x516c7a5c #0xaf9486a4
    assert(0x7754e565 == accumulated_value)
    accumulated_value += flag[0] * -0xf1d9e5
    accumulated_value += 0x8b424d6b #0x75beb395
    assert(0xa6f3a30b == accumulated_value)
    accumulated_value += flag[28] * 0xd3e2f8
    accumulated_value += 0x3802be78 #0xc8fe4288
    assert(0x14248c5c3 == accumulated_value)
    accumulated_value -= flag[24] * 0xb558ce
    accumulated_value -= 0x33418c8e #0x33418c8e
    assert(0x131bd38a3 == accumulated_value)
    accumulated_value += flag[8] * -0x2f03a7
    accumulated_value += 0xe050b170 #0x20b04f90
    assert(0x1c35ca503 == accumulated_value)
    accumulated_value += flag[4] * 0xb8fa61
    accumulated_value += 0x1fc22df6 #0xe13ed30a
    assert(0x210367cdb == accumulated_value)
    accumulated_value += flag[18] * -0xe0c507
    accumulated_value += 0xd8376e57 #0x28c992a9
    assert(0x13e26e5dc == accumulated_value)
    accumulated_value -= flag[4] * 0x8e354e
    accumulated_value -= 0xd2cb3108 #0xd2cb3108
    assert(0xa63dc720 == accumulated_value)
    accumulated_value -= 0x01e79080 #0xd2cb3108
    assert(0xffffffffa55636a0 == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_5(flag):
    accumulated_value = flag[17] * 0xa9b448
    accumulated_value += 0x9f938499 #0x616d7c67
    assert(0xba5aa091 == accumulated_value)
    accumulated_value += flag[0] * 0x906550
    accumulated_value += 0x407021af #0xc090df51
    assert(0x131812590 == accumulated_value)
    accumulated_value ^= flag[1] * 0xaa5ad2
    accumulated_value ^= 0x77cf83a7 #0x89317d59
    assert(0x10ac86a61 == accumulated_value)
    accumulated_value ^= flag[29] * 0xc49349
    accumulated_value ^= 0x3067f4e7 #0xd0990c19
    assert(0x17fb4592c == accumulated_value)
    accumulated_value += flag[9] * 0x314f8e
    accumulated_value += 0xcd975f3b #0x3369a1c5
    assert(0x259d0eb75 == accumulated_value)
    accumulated_value ^= flag[3] * 0x81968b
    accumulated_value += 0x893d2e0b #0x77c3d2f5
    assert(0x2f8b897dc == accumulated_value)
    accumulated_value += flag[25] * -0x5ffbac
    accumulated_value += 0xf3378e3a #0x0dc972c6
    assert(0x216aefaa2 == accumulated_value)
    accumulated_value += flag[1] * -0xf63c8e
    accumulated_value -= 0xe4e378d5 #0x1c1d882b
    assert(0x18bf43ead == accumulated_value)
    accumulated_value -= 0x8e5eb48d #0x1c1d882b
    assert(0xfd958a20 == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_6(flag):
    accumulated_value = flag[22] * 0xa6edf9
    accumulated_value += 0x77c58017 #0x893b80e9
    assert(0x472237e4 == accumulated_value)
    accumulated_value += flag[18] * -0xe87bf4
    accumulated_value -= 0x999bd740 #0x999bd740
    assert(0xffffffff81ef22e4 == accumulated_value)
    accumulated_value += flag[2] * -0x19864d
    accumulated_value -= 0x41884bed #0x41884bed
    assert(0xffffffff366e60e3 == accumulated_value)
    accumulated_value += flag[1] * 0x901524
    accumulated_value += 0x247bf095 #0xdc85106b
    assert(0xffffffff535c109a == accumulated_value)
    accumulated_value ^= flag[10] * 0xc897cc
    accumulated_value ^= 0xeff7eea8 #0x11091258
    assert(0xfffffffffda2c916 == accumulated_value)
    accumulated_value ^= flag[2] * 0x731197
    accumulated_value += 0x67a0d262 #0x99602e9e
    assert(0x38f0ea4c == accumulated_value)
    accumulated_value += flag[30] * 0x5f591c
    accumulated_value += 0x316661f9 #0xcf9a9f07
    assert(0x97c7c39d == accumulated_value)
    accumulated_value -= flag[26] * 0x579d0e
    accumulated_value -= 0x3427fa1c #0x3427fa1c
    assert(0x89454585 == accumulated_value)
    accumulated_value -= 0x900d744b #0x3427fa1c
    assert(0xfffffffff937d13a == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_7(flag):
    accumulated_value = flag[23] * 0x9afaf6
    accumulated_value += 0xdb895413 #0x2577aced
    assert(0xc5cc501f == accumulated_value)
    accumulated_value -= flag[19] * 0x7d1a12
    accumulated_value -= 0xc679fc44 #0xc679fc44
    assert(0x1ab007cb == accumulated_value)
    accumulated_value += flag[11] * 0x4d84b1
    accumulated_value += 0xa30387dc #0x5dfd7924
    assert(0xde1a05a2 == accumulated_value)
    accumulated_value += flag[3] * -0x552b78
    accumulated_value += 0xf54a725e #0x0bb68ea2
    assert(0x4f61dd5c == accumulated_value)
    accumulated_value ^= flag[2] * 0xf372a1
    accumulated_value -= 0x4c5103ad #0x4c5103ad
    assert(0xffffffffc428180b == accumulated_value)
    accumulated_value += flag[31] * 0xb40eb5
    accumulated_value += 0x16fa70d2 #0xea06902e
    assert(0xffffffffe0364a21 == accumulated_value)
    accumulated_value ^= flag[3] * 0x9e5c18
    accumulated_value += 0x38784353 #0xc888bdad
    assert(0xffffffffdb70d354 == accumulated_value)
    accumulated_value ^= flag[27] * 0xf2513b
    accumulated_value += 0xa1fc09f0 #0x5f04f710
    assert(0x87042c52 == accumulated_value)
    accumulated_value -= 0x0101e408 #0x5f04f710
    assert(0x852d484a == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_8(flag):
    accumulated_value = flag[28] * 0xac70b9
    accumulated_value += 0xdae0a932 #0x262057ce
    assert(0x12bb57fea == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    accumulated_value ^= flag[4] * 0xc42b6f
    accumulated_value ^= 0xbc03104c #0x44fdf0b4
    assert(0x1c68f9450 == accumulated_value)
    accumulated_value += flag[0] * -0x867193
    accumulated_value += 0xdc48c63a #0x24b83ac6
    assert(0x26fe751d7 == accumulated_value)
    accumulated_value += flag[0] * -0x6d31fe
    accumulated_value += 0x4baeb6d0 #0xb5524a30
    assert(0x20d29d649 == accumulated_value)
    accumulated_value += flag[4] * -0xaaae58
    accumulated_value -= 0xcd7121f8 #0xcd7121f8
    assert(0xf90c83e1 == accumulated_value)
    accumulated_value += flag[18] * 0x9faa7a
    accumulated_value += 0xbe0a2c9c #0x42f6d464
    assert(0x1d506a75d == accumulated_value)
    accumulated_value += flag[24] * 0x354ac6
    accumulated_value += 0xd8ad17f1 #0x2853e90f
    assert(0x10794e0b2 == accumulated_value)
    accumulated_value += flag[8] * -0x3f2acb
    accumulated_value -= 0x8b6b7d89 #0x8b6b7d89
    assert(0x686c03b9 == accumulated_value)
    accumulated_value -= 0x63c13793 #0x8b6b7d89
    assert(0x4aacc26 == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_9(flag):
    accumulated_value = flag[29] * 0xe9d18a
    accumulated_value += 0xcb5557ea #0x35aba916
    assert(0x9966fd6e == accumulated_value)
    accumulated_value ^= flag[25] * 0x8aa5b9
    accumulated_value ^= 0x9125a906 #0x6fdb57fa
    assert(0x13dc57b3 == accumulated_value)
    accumulated_value += flag[17] * -0x241997
    accumulated_value += 0x6e46fcb8 #0x92ba0448
    assert(0x7a19a1cc == accumulated_value)
    accumulated_value += flag[0] * 0xe3da0f
    accumulated_value += flag[1] * 0xa5f9eb
    accumulated_value += 0xbde8f9af #0x43180751
    assert(0x21d0f80a7 == accumulated_value)
    accumulated_value -= flag[3] * 0xd6e0fb
    accumulated_value -= 0xc9d97243 #0xc9d97243
    assert(0x1addcf848 == accumulated_value)
    accumulated_value += flag[1] * 0x8dc36e
    accumulated_value += 0xc54b7d21 #0x3bb583df
    assert(0x2b2d73fd3 == accumulated_value)
    accumulated_value ^= flag[9] * 0xb072ee
    accumulated_value -= 0x2a1ab0c1 #0x2a1ab0c1
    assert(0x273ff60fc == accumulated_value)
    accumulated_value -= 0xbf2044db #0x2a1ab0c1
    assert(0x1b4df1c21 == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_10(flag):
    accumulated_value = flag[30] * 0xd14f3e
    accumulated_value += 0xa06c215b #0x6094dfa5
    assert(0xc3d3e2d7 == accumulated_value)
    accumulated_value += flag[26] * -0xc5ecbf
    accumulated_value += 0xb197c5c0 #0x4f693b40
    assert(0x1205fee85 == accumulated_value)
    accumulated_value ^= flag[1] * 0x19ff9c
    accumulated_value ^= 0x66e7d06c #0x9a193094
    assert(0x14d15edfd == accumulated_value)
    accumulated_value += flag[2] * 0xe3288b
    accumulated_value += 0x80af4325 #0x8051bddb
    assert(0x1257e876c == accumulated_value)
    accumulated_value ^= flag[10] * 0xcfb18c
    accumulated_value -= 0xe13c8393 #0xe13c8393
    assert(0x84eb9375 == accumulated_value)
    accumulated_value ^= flag[18] * 0xd208e5
    accumulated_value += 0xf96d2b51 #0x0793d5af
    assert(0x19cf764d6 == accumulated_value)
    accumulated_value -= flag[2] * 0x42240f
    accumulated_value -= 0x79ced9c3 #0x8732273d
    assert(0x12f9b5375 == accumulated_value)
    accumulated_value += flag[22] * -0x1c6098
    accumulated_value -= 0xd3d45c5a #0xd3d45c5a
    assert(0x5376aa93 == accumulated_value)
    accumulated_value -= 0xf5c382a5 #0xd3d45c5a
    assert(0x48392c38 == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_11(flag):
    accumulated_value = flag[11] * 0x3768cc
    accumulated_value += 0x19f61419 #0xe70aece7
    assert(0xeded95d == accumulated_value)
    accumulated_value += flag[3] * -0x43be16
    accumulated_value += 0x566cc6a8 #0xaa943a58
    assert(0x48b76ebd == accumulated_value)
    accumulated_value ^= flag[3] * 0xb7cca5
    accumulated_value += 0x6db0599e #0x9350a762
    assert(0x72ed94bf == accumulated_value)
    accumulated_value += flag[27] * 0xf6419f
    accumulated_value += 0xbd613538 #0x439fcbc8
    assert(0xf0b4a85 == accumulated_value)
    accumulated_value ^= flag[19] * 0xae52fc
    accumulated_value += 0x717a44dd #0x8f86bc23
    assert(0x9aa3b282 == accumulated_value)
    accumulated_value += flag[23] * -0x5eeb81
    accumulated_value += 0xdd02182d #0x23fee8d3
    assert(0x1651bcb7d == accumulated_value)
    accumulated_value ^= flag[2] * 0xec1845
    accumulated_value ^= 0xef8e5416 #0x1172acea
    assert(0x1d6ace59f == accumulated_value)
    accumulated_value += flag[31] * 0x61a3be
    accumulated_value += 0x9288d4fa #0x6e782c06
    assert(0x160aa27f5 == accumulated_value)
    accumulated_value -= 0x81bdbe05 #0x6e782c06
    assert(0xdeec69f0 == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_12(flag):
    accumulated_value = flag[4] * 0x336e91
    accumulated_value += 0xa1eb20e3 #0x5f15e01d
    assert(0xb736e8ed == accumulated_value)
    accumulated_value += flag[4] * -0xd45de9
    accumulated_value -= 0x381ac71a #0x381ac71a
    assert(0x272d3f59 == accumulated_value)
    accumulated_value += flag[8] * 0x76c8f8
    accumulated_value += 0xd8caa2cd #0x28365e33
    assert(0x9486ae14 == accumulated_value)
    accumulated_value += flag[18] * -0x945339
    accumulated_value += 0x524d7efa #0xaeb38206
    assert(0xcb04925e == accumulated_value)
    accumulated_value -= flag[0] * 0x4474ec
    accumulated_value -= 0xe47e82cd #0xe47e82cd
    assert(0x765cfd == accumulated_value)
    accumulated_value ^= flag[0] * 0x51054f
    accumulated_value ^= 0x3321c9b1 #0xcddf374f
    assert(0x2de497a3 == accumulated_value)
    accumulated_value += flag[24] * -0xd7eb3b
    accumulated_value += 0x36f6829d #0xca0a7e63
    assert(0x3b8713f5 == accumulated_value)
    accumulated_value += flag[28] * -0xad52e1
    accumulated_value += 0x6ce2181a #0x941ee8e6
    assert(0xffffffff86aa2267 == accumulated_value)
    accumulated_value -= 0xf39b4443 #0x941ee8e6
    assert(0xfffffffe930ede24 == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_13(flag):
    accumulated_value = flag[29] * 0x725059
    accumulated_value += 0xa8b69f6b #0x584a6195
    assert(0x8086a021 == accumulated_value)
    accumulated_value += flag[17] * 0x6dcfe7
    accumulated_value += 0x653c249a #0x9bc4dc66
    assert(0xfdc5ce0a == accumulated_value)
    accumulated_value += flag[1] * 0x8f4c44
    accumulated_value += 0x68e87685 #0x98188a7b
    assert(0x156cd6613 == accumulated_value)
    accumulated_value += flag[9] * -0xd2f4ce
    accumulated_value -= 0x87238dc5 #0x87238dc5
    assert(0x9a19b000 == accumulated_value)
    accumulated_value ^= flag[1] * 0xe99d3f
    accumulated_value += 0xed16797a #0x13ea8786
    assert(0x1dffe8cc7 == accumulated_value)
    accumulated_value -= flag[0] * 0xada536
    accumulated_value -= 0x95a05aa9 #0x95a05aa9
    assert(0x18c29cb94 == accumulated_value)
    accumulated_value += flag[25] * -0xe0b352
    accumulated_value += flag[3] * 0x8675b6
    accumulated_value += 0x34a29213 #0xcc5e6eed
    assert(0x18a024cf9 == accumulated_value)
    accumulated_value -= 0x20196a7e #0xcc5e6eed
    assert(0x169e8e27b == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_14(flag):
    accumulated_value = flag[2] * 0x4a5e95
    accumulated_value += 0x5ed7a1f1 #0xa2295f0f
    assert(0x7be49425 == accumulated_value)
    accumulated_value += flag[22] * 0x3a7b49
    accumulated_value += 0x87a91310 #0x7957edf0
    assert(0xaafa198 == accumulated_value)
    accumulated_value += flag[1] * -0xf27038
    accumulated_value += 0xf64a0f19 #0x0ab6f1e7
    assert(0xffffffff6b8d3769 == accumulated_value)
    accumulated_value -= flag[30] * 0xa187d0
    accumulated_value -= 0xbbcc735d #0xbbcc735d
    assert(0xfffffffefcbb7d2c == accumulated_value)
    accumulated_value += flag[18] * -0xfc991a
    accumulated_value += 0xf9ddd08f #0x07233071
    assert(0xfffffffe348318c3 == accumulated_value)
    accumulated_value += flag[26] * -0x4e947a
    accumulated_value -= 0x59a9172e #0x59a9172e
    assert(0xfffffffdb9163529 == accumulated_value)
    accumulated_value ^= flag[2] * 0x324ead
    accumulated_value -= 0x6a66869c #0x969a7a64
    assert(0xfffffffd14161459 == accumulated_value)
    accumulated_value += flag[10] * -0x656b1b
    accumulated_value += 0x8c112543 #0x74efdbbd
    assert(0xfffffffd7f457fdb == accumulated_value)
    accumulated_value -= 0xc1db45c7 #0x74efdbbd
    assert(0xfffffffcbd6a3a14 == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_15(flag):
    accumulated_value = flag[11] * 0x251b86
    accumulated_value += 0xa751192c #0x59afe7d4
    assert(0xb6d39a2e == accumulated_value)
    accumulated_value += flag[2] * -0x743927
    accumulated_value += 0xf851da43 #0x08af26bd
    assert(0x713c9cb1 == accumulated_value)
    accumulated_value ^= flag[31] * 0x9a3479
    accumulated_value ^= 0x335087a5 #0xcdb0795b
    assert(0x6932d91c == accumulated_value)
    accumulated_value ^= flag[3] * 0x778a0d
    accumulated_value ^= 0x4bfd30d3 #0xb503d02d
    assert(0x10a1d4b3 == accumulated_value)
    accumulated_value += flag[27] * -0x7e04b5
    accumulated_value -= 0x5d540495 #0x5d540495
    assert(0xffffffff92d09974 == accumulated_value)
    accumulated_value ^= flag[19] * 0xf1c3ee
    accumulated_value += 0x460c48a6 #0xbaf4b85a
    assert(0xffffffffec3e8e0a == accumulated_value)
    accumulated_value += flag[3] * 0x883b8a
    accumulated_value += 0x7b2ffbdc #0x85d10524
    assert(0xa0e7a81e == accumulated_value)
    accumulated_value += flag[23] * 0x993db1
    accumulated_value += 0xa98b28fa #0x5775d806
    assert(0x16860ddaa == accumulated_value)
    accumulated_value -= 0x22087cd4 #0x5775d806
    assert(0x1465860d6 == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_16(flag):
    accumulated_value = flag[4] * 0xbae081
    accumulated_value += 0x2359766f #0xdda78a91
    assert(0x70ba6bd9 == accumulated_value)
    accumulated_value ^= flag[24] * 0xc2483b
    accumulated_value += 0xea986a57 #0x166896a9
    assert(0x1402e22e9 == accumulated_value)
    accumulated_value += flag[28] * -0x520ee2
    accumulated_value += 0xa6ff8114 #0x5a017fec
    assert(0x1bf48a9ed == accumulated_value)
    accumulated_value += flag[8] * 0x9864ba
    accumulated_value += 0x42833507 #0xbe7dcbf9
    assert(0x2316b5914 == accumulated_value)
    accumulated_value += flag[0] * -0x7cd278
    accumulated_value += 0x360be811 #0xcaf518ef
    assert(0x23414718d == accumulated_value)
    accumulated_value ^= flag[4] * 0xbe6605
    accumulated_value -= 0x4c927a8d #0x4c927a8d
    assert(0x22e2fd512 == accumulated_value)
    accumulated_value += flag[18] * 0x3bd2e8
    accumulated_value += 0xb790cfd3 #0x4970312d
    assert(0x2f0f83065 == accumulated_value)
    accumulated_value += flag[0] * -0x548c2b
    accumulated_value -= 0x6e0e04cc #0x92f2fc34
    assert(0x2fafd18e6 == accumulated_value)
    accumulated_value -= 0x02213287 #0x92f2fc34
    assert(0x2d9ca9154 == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_17(flag):
    accumulated_value = flag[17] * 0xfb213b
   # accumulated_value -= UNKNOWN
    assert(0xffffffffd0768fe0 == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    accumulated_value ^= flag[9] * 0xde6876
    accumulated_value ^= 0x8649fde3 #0x7ab7031d
    assert(0xffffffff6e47f7f5 == accumulated_value)
    accumulated_value ^= flag[29] * 0x629ff7
    accumulated_value ^= 0xa0eeb203 #0x60124efd
    assert(0xffffffffec057920 == accumulated_value)
    accumulated_value += flag[25] * -0xdbb107
    accumulated_value += 0x94aa6b62 #0x6c56959e
    assert(0xffffffff54eb5fd9 == accumulated_value)
    accumulated_value += flag[1] * -0x262675
    accumulated_value -= 0xdfcf5488 #0xdfcf5488
    assert(0xfffffffe63f8c4c2 == accumulated_value)
    accumulated_value -= flag[0] * 0xd691c5
    accumulated_value -= 0x5b3ee746 #0x5b3ee746
    assert(0xfffffffe5a071921 == accumulated_value)
    accumulated_value += flag[1] * -0xcafc93
    accumulated_value -= 0x111bde22 #0x111bde22
    assert(0xfffffffdedbbc4f6 == accumulated_value)
    accumulated_value += flag[3] * -0x81f945
    accumulated_value -= 0x70fdc5f8 #0x90033b08
    assert(0xfffffffd26e360d2 == accumulated_value)
    accumulated_value -= 0x6349d7cf #0x90033b08
    assert(0xfffffffcc3998903 == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_18(flag):
    accumulated_value = flag[10] * 0x52f44d
    accumulated_value += 0x33b3d0e4 #0xcd4d301c
    assert(0x2956e413 == accumulated_value)
    accumulated_value ^= flag[30] * 0xe6e66e
    accumulated_value -= 0x275d79b0 #0x275d79b0
    assert(0x2001bacf == accumulated_value)
    accumulated_value += flag[1] * -0xf98017
    accumulated_value += 0x456e6c1d #0xbb9294e3
    assert(0xffffffffea835c67 == accumulated_value)
    accumulated_value += flag[2] * -0x34fcb0
    accumulated_value += 0x28709cd8 #0xd8906428
    assert(0xfffffffffda03b7f == accumulated_value)
    accumulated_value ^= flag[2] * 0x4d8ba9
    accumulated_value += 0xb5482f53 #0x4bb8d1ad
    assert(0x9932e4ce == accumulated_value)
    accumulated_value ^= flag[18] * 0x6c7e92
    accumulated_value += flag[22] * 0xa4711e
    accumulated_value += 0x22e79af6 #0xde19660a
    assert(0xca63c04f == accumulated_value)
    accumulated_value -= flag[26] * 0x33d374
    accumulated_value -= 0x117efc14 #0x117efc14
    assert(0xcf29a013 == accumulated_value)
    accumulated_value -= 0x9379438e #0x117efc14
    assert(0x3bb05c85 == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_19(flag):
    accumulated_value = flag[27] * 0x65ac37
    accumulated_value += 0x15e586b0 #0xeb1b7a50
    assert(0x301becde == accumulated_value)
    accumulated_value ^= flag[31] * 0xc6dde0
    accumulated_value ^= 0x2354cad4 #0xddac362c
    assert(0x24a1410a == accumulated_value)
    accumulated_value ^= flag[3] * 0x154abd
    accumulated_value ^= 0xfee57fd5 #0x021b812b
    assert(0xd2bfb963 == accumulated_value)
    accumulated_value ^= flag[19] * 0xa5e467
    accumulated_value += 0x315624ef #0xcfaadc11
    assert(0x1284c74da == accumulated_value)
    accumulated_value ^= flag[23] * 0xb6bed6
    accumulated_value -= 0x5285b0a5 #0x5285b0a5
    assert(0xb9778071 == accumulated_value)
    accumulated_value += flag[2] * -0x832ae7
    accumulated_value += 0xe961bedd #0x179f4223
    assert(0x16f9c7d12 == accumulated_value)
    accumulated_value -= flag[11] * 0xc46330
    accumulated_value -= 0x4a9e1d65 #0x4a9e1d65
    assert(0x17713d4bd == accumulated_value)
    accumulated_value ^= flag[3] * 0x3f8467
    accumulated_value ^= 0x95a6a1c4 #0x6b5a5f3c
    assert(0x1f87eae0d == accumulated_value)
    accumulated_value -= 0x110e3519 #0x6b5a5f3c
    assert(0x1e77078f4 == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_20(flag):
    accumulated_value = flag[24] * 0xb74a52
    accumulated_value += 0x8354d4e8 #0x7dac2c18
    assert(0xa041ed5a == accumulated_value)
    accumulated_value ^= flag[4] * 0xf22ecd
    accumulated_value -= 0x34cbf23b #0x34cbf23b
    assert(0x8f3a9b7d == accumulated_value)
    accumulated_value += flag[18] * 0xbef4be
    accumulated_value += 0x60a6c39a #0xa05a3d66
    assert(0xd3aebc87 == accumulated_value)
    accumulated_value ^= flag[8] * 0x7fe215
    accumulated_value += 0xb14a7317 #0x4fb68de9
    assert(0x1a5a28d2e == accumulated_value)
    accumulated_value += flag[4] * -0xdb9f48
    accumulated_value -= 0xbca905f2 #0xbca905f2
    assert(0x8e09936c == accumulated_value)
    accumulated_value += flag[28] * -0xbb4276
    accumulated_value -= 0x920e2248 #0x920e2248
    assert(0xffffffffa43449d4 == accumulated_value)
    accumulated_value ^= flag[0] * 0xa3fbef
    accumulated_value += 0x4c22d2d3 #0xb4de2e2d
    assert(0xffffffffe6390f2e == accumulated_value)
    accumulated_value ^= flag[0] * 0xc5e883
    accumulated_value ^= 0x50a6e5c9 #0xb05a1b37
    assert(0xfffffffffc62f344 == accumulated_value)
    accumulated_value -= 0xd8e5bdc6 #0xb05a1b37
    assert(0xffffffff237d357e == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_21(flag):
    accumulated_value = flag[1] * 0x4b2d02
    accumulated_value += 0x4b59b93a #0xb5a747c6
    assert(0x6a9c8edc == accumulated_value)
    accumulated_value += flag[9] * -0x84bb2c
    accumulated_value += 0x42d5652c #0xbe2b9bd4
    assert(0xa3c6d9c == accumulated_value)
    accumulated_value ^= flag[25] * 0x6f2d21
    accumulated_value += 0x1620133a #0xeae0edc6
    assert(0x3239a349 == accumulated_value)
    accumulated_value -= flag[29] * 0x5fe38f
    accumulated_value -= 0x62807b20 #0x62807b20
    assert(0xfffffffff16f286f == accumulated_value)
    accumulated_value += flag[3] * 0xea20a5
    accumulated_value += 0x60779ceb #0xa0896415
    assert(0x344372e0 == accumulated_value)
    accumulated_value ^= flag[17] * 0x5c17aa
    accumulated_value ^= 0x1aaf8a2d #0xe65176d3
    assert(0x3a6dbc17 == accumulated_value)
    accumulated_value += flag[0] * -0xb9feb0
    accumulated_value -= 0xadbe02fb #0xadbe02fb
    assert(0xffffffff4636386c == accumulated_value)
    accumulated_value += flag[1] * -0x782f79
    accumulated_value -= 0xcfc12836 #0xcfc12836
    assert(0xfffffffe4077bcdb == accumulated_value)
    accumulated_value -= 0x488d6b06 #0xcfc12836
    assert(0xfffffffdf7ea51d5 == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_22(flag):
    accumulated_value = flag[1] * 0x608d19
    accumulated_value -= 0x2eee62ec #0x2eee62ec
    assert(0xfffffffffc70ff4f == accumulated_value)
    accumulated_value += flag[2] * -0xbe18f4
    accumulated_value += 0xb86f9b72 #0x4891658e
    assert(0xffffffff0a40a48d == accumulated_value)
    accumulated_value ^= flag[30] * 0x88dec9
    accumulated_value += 0xaf5cd797 #0x51a42969
    assert(0xfffffffffad766de == accumulated_value)
    accumulated_value ^= flag[18] * 0xb68150
    accumulated_value -= 0xc3f9c55b #0x3d073ba5
    assert(0xffffffff9be81e39 == accumulated_value)
    accumulated_value += flag[22] * 0x4d166c
    accumulated_value += 0xbb1e1039 #0x45e2f0c7
    assert(0x6d9bc016 == accumulated_value)
    accumulated_value += flag[2] * -0x495e3f
    accumulated_value += 0xe727b98e #0x19d94772
    assert(0x1381aa908 == accumulated_value)
    accumulated_value += flag[10] * -0x5caba1
    accumulated_value -= 0x1a3cf6c1 #0x1a3cf6c1
    assert(0xffd20d14 == accumulated_value)
    accumulated_value -= flag[26] * 0x183a4d
    accumulated_value -= 0xca0397e1 #0xca0397e1
    assert(0x40378249 == accumulated_value)
    accumulated_value -= 0x6684a31d #0xca0397e1
    assert(0xffffffffd9b2df2c == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_23(flag):
    accumulated_value = flag[11] * 0xffd0ca
    accumulated_value -= 0x8f26cee8 #0x8f26cee8
    assert(0xffffffffdbc57586 == accumulated_value)
    accumulated_value ^= flag[2] * 0xbf2b59
    accumulated_value += 0xc76bad6e #0x39955392
    assert(0x58d548b0 == accumulated_value)
    accumulated_value += flag[23] * 0x29df01
    accumulated_value += 0xeef034a2 #0x1210cc5e
    assert(0x14ff30b84 == accumulated_value)
    accumulated_value ^= flag[27] * 0xbbda1d
    accumulated_value += 0x5923194e #0xa7dde7b2
    assert(0x1d8c04a4c == accumulated_value)
    accumulated_value += flag[31] * -0x5d24a5
    accumulated_value -= 0x7ff0f967 #0x81100799
    assert(0x13d7df44b == accumulated_value)
    accumulated_value -= flag[3] * 0x3dc505
    accumulated_value -= 0x69baee91 #0x69baee91
    assert(0xedd223d6 == accumulated_value)
    accumulated_value ^= flag[19] * 0x4e25a6
    accumulated_value += 0x2468b30a #0xdc984df6
    assert(0x12132d290 == accumulated_value)
    accumulated_value += flag[3] * -0xae1920
    accumulated_value += 0xd3db6142 #0x2d259fbe
    assert(0x41b5852 == accumulated_value)
    accumulated_value -= 0xbb7af00f #0x2d259fbe
    assert(0xffffffff48a06843 == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_24(flag):
    accumulated_value = flag[4] * 0xf56c62
    accumulated_value += 0x6c7d1f41 #0x9483e1bf
    assert(0x9e3ffd5 == accumulated_value)
    accumulated_value += flag[4] * 0x615605
    accumulated_value += 0x5b52f6ee #0xa5ae0a12
    assert(0x8d8494d5 == accumulated_value)
    accumulated_value += flag[18] * 0x828456
    accumulated_value += 0x6f059759 #0x91fb69a7
    assert(0xcaf8f3ac == accumulated_value)
    accumulated_value += flag[28] * -0x50484b
    accumulated_value += 0x84e222af #0x7c1ede51
    assert(0x12a393333 == accumulated_value)
    accumulated_value ^= flag[8] * 0x89d640
    accumulated_value += 0xfd21345b #0x03dfcca5
    assert(0x1fe4cfb8e == accumulated_value)
    accumulated_value += flag[24] * -0xe4b191
    accumulated_value += 0xfe15a789 #0x02eb5977
    assert(0x2d09ca656 == accumulated_value)
    accumulated_value ^= flag[0] * 0x8c58c1
    accumulated_value ^= 0x4c49099f #0xb4b7f761
    assert(0x2a9f80ee8 == accumulated_value)
    accumulated_value += flag[0] * 0xa13c4c
    accumulated_value += 0x27c5288e #0xd93bd872
    assert(0x2c0cacf3a == accumulated_value)
    accumulated_value -= 0x0398db0b #0xd93bd872
    #confirm accumulated_value
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_25(flag):
    accumulated_value = flag[1] * 0x73aaf0
    accumulated_value += 0xa04e34f1 #0x60b2cc0f
    assert(0x93bbfd21 == accumulated_value)
    accumulated_value += flag[29] * 0xf61e43
    accumulated_value += 0xd09b66f3 #0x30659a0d
    assert(0x1bade07a2 == accumulated_value)
    accumulated_value += flag[25] * 0x8cb5f0
    accumulated_value += 0xc11c9b4b #0x3fe465b5
    assert(0x29802e1bd == accumulated_value)
    accumulated_value ^= flag[17] * 0x4f53a8
    accumulated_value -= 0x6465672e #0x6465672e
    assert(0x22545daa7 == accumulated_value)
    accumulated_value += flag[9] * 0xb2e1fa
    accumulated_value += 0x77c07fd8 #0x89408128
    assert(0x2257144f9 == accumulated_value)
    accumulated_value += flag[3] * -0xb8b7b3
    accumulated_value -= 0x78d4ebdf #0x882c1521
    assert(0x14f57b054 == accumulated_value)
    accumulated_value += flag[1] * 0x13b807
    accumulated_value += 0x758dd142 #0x8b732fbe
    assert(0x12dbe8a3b == accumulated_value)
    accumulated_value ^= flag[0] * 0xdd40c4
    accumulated_value -= 0x449786e6 #0x449786e6
    assert(0x139d37999 == accumulated_value)
    accumulated_value -= 0xb05dd93c #0x449786e6
    assert(0x8975a05d == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_26(flag):
    accumulated_value = flag[2] * 0xca894b
    accumulated_value += 0xa34fe406 #0x5db11cfa
    assert(0xf26d8552 == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    accumulated_value += flag[18] * 0x11552b
    accumulated_value += 0x3764ecd4 #0xc99c142c
    assert(0x12d126a36 == accumulated_value)
    accumulated_value ^= flag[22] * 0x7dc36b
    accumulated_value += 0xb45e777b #0x4ca28985
    assert(0x1be28a1ea == accumulated_value)
    accumulated_value ^= flag[26] * 0xcec5a6
    accumulated_value ^= 0x2d59bc15 #0xd3a744eb
    assert(0x1cba9f0ab == accumulated_value)
    accumulated_value += flag[30] * 0xb6e30d
    accumulated_value += 0xfab9788c #0x06478874
    assert(0x2d86b5c51 == accumulated_value)
    accumulated_value ^= flag[10] * 0x859c14
    accumulated_value += 0x41868e54 #0xbf7a72ac
    assert(0x334c15481 == accumulated_value)
    accumulated_value += flag[1] * 0xd178d3
    accumulated_value += 0x958b0be3 #0x6b75f51d
    assert(0x42865a72d == accumulated_value)
    accumulated_value ^= flag[2] * 0x61645c
    accumulated_value += 0x9dc814cf #0x6338ec31
    assert(0x4ac36a9ac == accumulated_value)
    accumulated_value -= 0x8580ebbe #0x6338ec31
    assert(0x430b6946a == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_27(flag):
    accumulated_value = flag[27] * 0x7239e9
    accumulated_value -= 0x76145ada #0x76145ada
    assert(0xffffffffa75e9338 == accumulated_value)
    accumulated_value += flag[3] * -0xf1c3d1
    accumulated_value -= 0xef28a068 #0xef28a068
    assert(0xfffffffe523756a4 == accumulated_value)
    accumulated_value ^= flag[11] * 0x1b1367
    accumulated_value ^= 0x31e00d5a #0xcf20f3a6
    assert(0xfffffffe688647f3 == accumulated_value)
    accumulated_value ^= flag[19] * 0x8038b3
    accumulated_value += 0xb5163447 #0x4beaccb9
    assert(0xffffffff29a05522 == accumulated_value)
    accumulated_value += flag[31] * 0x65fac9
    accumulated_value += 0xe04a889a #0x20b67866
    assert(0x26996644 == accumulated_value)
    accumulated_value += flag[23] * -0xd845ca
    accumulated_value -= 0x5583e4a8 #0xab7d1c58
    assert(0xffffffff50dea878 == accumulated_value)
    accumulated_value += flag[3] * 0xb2bbbc
    accumulated_value ^= flag[2] * 0x33c8bd
    accumulated_value += 0x540376e3 #0xacfd8a1d
    assert(0x6824071 == accumulated_value)
    accumulated_value -= 0xb0e80c93 #0xacfd8a1d
    assert(0xffffffff559a33de == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_28(flag):
    accumulated_value = flag[0] * 0x53a4e0
    accumulated_value -= 0x6061803e #0x6061803e
    assert(0xffffffffbf4ff8a2 == accumulated_value)
    accumulated_value += flag[4] * -0x9bbfda
    accumulated_value += 0x69b383f1 #0x974d7d0f
    assert(0xffffffffe8860c4f == accumulated_value)
    accumulated_value += flag[24] * -0x6b38aa
    accumulated_value -= 0x69ede960 #0x971317a0
    assert(0xffffffff3ced1c25 == accumulated_value)
    accumulated_value += flag[18] * 0x5d266f
    accumulated_value += 0x5a4b0e60 #0xa6b5f2a0
    assert(0xffffffffa8af5f55 == accumulated_value)
    accumulated_value += flag[8] * -0xedc3d3
    accumulated_value += 0x93e59af6 #0x6d1b660a
    assert(0xffffffffcd87b793 == accumulated_value)
    accumulated_value += flag[4] * -0xb1f16c
    accumulated_value += 0xe8d2b9a9 #0x182e4757
    assert(0xffffffff6b0b7972 == accumulated_value)
    accumulated_value -= flag[0] * 0x1c8e5b
    accumulated_value -= 0x68839283 #0x68839283
    assert(0xffffffff0d59d76a == accumulated_value)
    accumulated_value -= flag[28] * 0x78f67b
    accumulated_value -= 0xf53dd889 #0xf53dd889
    assert(0xfffffffe50cf8889 == accumulated_value)
    accumulated_value -= 0xb255dea3 #0xf53dd889
    assert(0xfffffffe0224662c == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_29(flag):
    accumulated_value = flag[17] * 0x87184c
    accumulated_value -= 0x72a15ad8 #0x72a15ad8
    assert(0xffffffffab730e14 == accumulated_value)
    accumulated_value ^= flag[25] * 0xf6372e
    accumulated_value += 0x16ad4f89 #0xea53b177
    assert(0xffffffffb12d3fc7 == accumulated_value)
    accumulated_value += flag[3] * -0xd7355c
    accumulated_value -= 0xbb20fe35 #0xbb20fe35
    assert(0xfffffffe9b41bec2 == accumulated_value)
    accumulated_value ^= flag[0] * 0x471dc1
    accumulated_value ^= 0x572c95f4 #0xa9d46b0c
    assert(0xfffffffed69f6d17 == accumulated_value)
    accumulated_value += flag[1] * -0x8c4d98
    accumulated_value -= 0x6c9bf48c #0x94650c74
    assert(0xfffffffe0333855b == accumulated_value)
    accumulated_value += flag[1] * -0x5ceea1
    accumulated_value += 0xf703dcc1 #0x09fd243f
    assert(0xfffffffd2e778fc9 == accumulated_value)
    accumulated_value += flag[29] * -0xeb0863
    accumulated_value += 0xad3bc09d #0x53c54063
    assert(0xfffffffd89125d98 == accumulated_value)
    accumulated_value ^= flag[9] * 0xb6227f
    accumulated_value -= 0xba5296e9 #0x46ae6a17
    assert(0xfffffffd607e3590 == accumulated_value)
    accumulated_value -= 0x315e8118 #0x46ae6a17
    assert(0xfffffffd2f1fb478 == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_30(flag):
    accumulated_value = flag[30] * 0x8c6412
    accumulated_value += 0xc08c361c #0x4074cae4
    assert(0x826b8688 == accumulated_value)
    accumulated_value ^= flag[2] * 0xb253c4
    accumulated_value += 0x21bb1147 #0xdf45efb9
    assert(0xe97e4f5f == accumulated_value)
    accumulated_value -= flag[2] * 0x8f0579
    accumulated_value -= 0xfa691186 #0xfa691186
    assert(0x26f3611d == accumulated_value)
    accumulated_value += flag[22] * -0x7ac48a
    accumulated_value += 0xbb787dd5 #0x4588832b
    assert(0xbe744a84 == accumulated_value)
    accumulated_value += flag[10] * 0x2737e6
    accumulated_value += 0xa2bb7683 #0x5e458a7d
    assert(0x69901c95 == accumulated_value)
    accumulated_value += flag[18] * -0x4363b9
    accumulated_value += 0x88c45378 #0x783cad88
    assert(0xd4293a9d == accumulated_value)
    accumulated_value ^= flag[1] * 0xb38449
    accumulated_value -= 0x209dc078 #0x209dc078
    assert(0x63ef95de == accumulated_value)
    accumulated_value += flag[26] * 0x6e1316
    accumulated_value += 0x1343dee9 #0xedbd2217
    assert(0xa67fa83b == accumulated_value)
    accumulated_value -= 0xe3699527 #0xedbd2217
    assert(0xffffffffc3161314 == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

def checkpoint_31(flag):
    accumulated_value = flag[19] * 0x390b78
    accumulated_value += 0x7d5deea4 #0x83a3125c
    assert(0x89d870e4 == accumulated_value)
    accumulated_value += flag[3] * -0x70e6c8
    accumulated_value -= 0x6ea339e2 #0x6ea339e2
    assert(0xffffffffeb93daa2 == accumulated_value)
    accumulated_value ^= flag[27] * 0xd8a292
    accumulated_value -= 0x288d6ec5 #0x288d6ec5
    assert(0xffffffffb3bcc441 == accumulated_value)
    accumulated_value += flag[23] * -0x978c71
    accumulated_value -= 0xe5d85ed8 #0xe5d85ed8
    assert(0xfffffffeb04af757 == accumulated_value)
    accumulated_value -= flag[31] * 0x9a14d4
    accumulated_value -= 0x4a6a9034 #0xb69670cc
    assert(0xfffffffe250a622b == accumulated_value)
    accumulated_value ^= flag[2] * 0x995144
    accumulated_value -= 0xd2e77342 #0xd2e77342
    assert(0xfffffffd4c026979 == accumulated_value)
    accumulated_value ^= flag[11] * 0x811c39
    accumulated_value -= 0xd330cb9b #0x2dd03565
    assert(0xfffffffd4c246d45 == accumulated_value)
    accumulated_value ^= flag[3] * 0x9953d7
    accumulated_value ^= 0x80877669 #0x80798a97
    assert(0xfffffffd8c0c4598 == accumulated_value)
    accumulated_value -= 0xf9422478 #0x80798a97
    assert(0xfffffffc92ca2120 == accumulated_value)
    accumulated_value &= 0xffffffffffffffff
    return accumulated_value

