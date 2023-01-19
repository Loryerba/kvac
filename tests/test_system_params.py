from curve25519_dalek.ristretto import RistrettoPoint, CompressedRistretto

import kvac

SIGNAL_SYSTEM_HARDCODED = [
    0x9a, 0xe7, 0xc8, 0xe5, 0xed, 0x77, 0x9b, 0x11, 0x4a, 0xe7, 0x70, 0x8a, 0xa2, 0xf7, 0x94,
    0x67, 0xa, 0xdd, 0xa3, 0x24, 0x98, 0x7b, 0x65, 0x99, 0x13, 0x12, 0x2c, 0x35, 0x50, 0x5b,
    0x10, 0x5e, 0x6c, 0xa3, 0x10, 0x25, 0xd2, 0xd7, 0x6b, 0xe7, 0xfd, 0x34, 0x94, 0x4f, 0x98,
    0xf7, 0xfa, 0xe, 0x37, 0xba, 0xbb, 0x2c, 0x8b, 0x98, 0xbb, 0xbd, 0xbd, 0x3d, 0xd1, 0xbf,
    0x13, 0xc, 0xca, 0x2c, 0x8a, 0x9a, 0x3b, 0xdf, 0xaa, 0xa2, 0xb6, 0xb3, 0x22, 0xd4, 0x6b,
    0x93, 0xec, 0xa7, 0xb0, 0xd5, 0x1c, 0x86, 0xa3, 0xc8, 0x39, 0xe1, 0x14, 0x66, 0x35, 0x82,
    0x58, 0xa6, 0xc1, 0xc, 0x57, 0x7f, 0xc2, 0xbf, 0xfd, 0x34, 0xcd, 0x99, 0x16, 0x4c, 0x9a,
    0x6c, 0xd2, 0x9f, 0xab, 0x55, 0xd9, 0x1f, 0xf9, 0x26, 0x93, 0x22, 0xec, 0x34, 0x58, 0x60,
    0x3c, 0xc9, 0x6a, 0xd, 0x47, 0xf7, 0x4, 0x5, 0x82, 0x88, 0xf6, 0x2e, 0xe0, 0xac, 0xed,
    0xb8, 0xaa, 0x23, 0x24, 0x21, 0x21, 0xd9, 0x89, 0x65, 0xa9, 0xbb, 0x29, 0x91, 0x25, 0xc,
    0x11, 0x75, 0x80, 0x95, 0xec, 0xe0, 0xfd, 0x2b, 0x33, 0x28, 0x52, 0x86, 0xfe, 0x1f, 0xcb,
    0x5, 0x61, 0x3, 0xb6, 0x8, 0x17, 0x44, 0xb9, 0x75, 0xf5, 0x50, 0xd0, 0x85, 0x21, 0x56,
    0x8d, 0xd3, 0xd8, 0x61, 0x8f, 0x25, 0xc1, 0x40, 0x37, 0x5a, 0xf, 0x40, 0x24, 0xc3, 0xaa,
    0x23, 0xbd, 0xff, 0xfb, 0x27, 0xfb, 0xd9, 0x82, 0x20, 0x8d, 0x3e, 0xcd, 0x1f, 0xd3, 0xbc,
    0xb7, 0xac, 0xc, 0x3a, 0x14, 0xb1, 0x9, 0x80, 0x4f, 0xc7, 0x48, 0xd7, 0xfa, 0x45, 0x6c,
    0xff, 0xb4, 0x93, 0x4f, 0x98, 0xb, 0x6e, 0x9, 0xa2, 0x48, 0xa6, 0xf, 0x44, 0xa6, 0x15, 0xa,
    0xe6, 0xc1, 0x3d, 0x7e, 0x3c, 0x6, 0x26, 0x1d, 0x7e, 0x4e, 0xed, 0x37, 0xf3, 0x9f, 0x60,
    0xb0, 0x4d, 0xd9, 0xd6, 0x7, 0xfd, 0x35, 0x70, 0x12, 0x27, 0x4d, 0x3c, 0x63, 0xdb, 0xb3,
    0x8e, 0x73, 0x78, 0x59, 0x9c, 0x9e, 0x97, 0xdf, 0xbb, 0x28, 0x84, 0x26, 0x94, 0x89, 0x1d,
    0x5f, 0xd, 0xdc, 0x72, 0x99, 0x19, 0xb7, 0x98, 0xb4, 0x13, 0x15, 0x3, 0x40, 0x8c, 0xc5,
    0x7a, 0x9c, 0x53, 0x2f, 0x44, 0x27, 0x63, 0x2c, 0x88, 0xf5, 0x4c, 0xea, 0x53, 0x86, 0x1a,
    0x5b, 0xc4, 0x4c, 0x61, 0xcc, 0x60, 0x37, 0xdc, 0x31, 0xc2, 0xe8, 0xd4, 0x47, 0x4f, 0xb5,
    0x19, 0x58, 0x7a, 0x44, 0x86, 0x93, 0x18, 0x2a, 0xd9, 0xd6, 0xd8, 0x6b, 0x53, 0x59, 0x57,
    0x85, 0x8f, 0x54, 0x7b, 0x93, 0x40, 0x12, 0x7d, 0xa7, 0x5f, 0x80, 0x74, 0xca, 0xee, 0x94,
    0x4a, 0xc3, 0x6c, 0xa, 0xc6, 0x62, 0xd3, 0x8c, 0x9b, 0x3c, 0xcc, 0xe0, 0x3a, 0x9, 0x3f,
    0xcd, 0x96, 0x44, 0x4, 0x73, 0x98, 0xb8, 0x6b, 0x6e, 0x83, 0x37, 0x2f, 0xf1, 0x4f, 0xb8,
    0xbb, 0xd, 0xea, 0x65, 0x53, 0x12, 0x52, 0xac, 0x70, 0xd5, 0x8a, 0x4a, 0x8, 0x10, 0xd6,
    0x82, 0xa0, 0xe7, 0x9, 0xc9, 0x22, 0x7b, 0x30, 0xef, 0x6c, 0x8e, 0x17, 0xc5, 0x91, 0x5d,
    0x52, 0x72, 0x21, 0xbb, 0x0, 0xda, 0x81, 0x75, 0xcd, 0x64, 0x89, 0xaa, 0x8a, 0xa4, 0x92,
    0xa5, 0x0, 0xf9, 0xab, 0xee, 0x56, 0x90, 0xb9, 0xdf, 0xca, 0x88, 0x55, 0xdc, 0xb, 0xd0,
    0x2a, 0x7f, 0x27, 0x7a, 0xdd, 0x24, 0xf, 0x63, 0x9a, 0xc1, 0x68, 0x1, 0xe8, 0x15, 0x74,
    0xaf, 0xb4, 0x68, 0x3e, 0xdf, 0xf6, 0x3b, 0x9a, 0x1, 0xe9, 0x3d, 0xbd, 0x86, 0x7a, 0x4,
    0xb6, 0x16, 0xc7, 0x6, 0xc8, 0xc, 0x75, 0x6c, 0x11, 0xa3, 0x1, 0x6b, 0xbf, 0xb6, 0x9, 0x77,
    0xf4, 0x64, 0x8b, 0x5f, 0x23, 0x95, 0xa4, 0xb4, 0x28, 0xb7, 0x21, 0x19, 0x40, 0x81, 0x3e,
    0x3a, 0xfd, 0xe2, 0xb8, 0x7a, 0xa9, 0xc2, 0xc3, 0x7b, 0xf7, 0x16, 0xe2, 0x57, 0x8f, 0x95,
    0x65, 0x6d, 0xf1, 0x2c, 0x2f, 0xb6, 0xf5, 0xd0, 0x63, 0x1f, 0x6f, 0x71, 0xe2, 0xc3, 0x19,
    0x3f, 0x6d,
]


def get_signal_system_hardcoded() -> kvac.SystemParams:
    def get_point_from_hardcoded_system(system_index: int) -> RistrettoPoint:
        start, end = system_index * 32, (system_index + 1) * 32
        return CompressedRistretto(bytes(SIGNAL_SYSTEM_HARDCODED[start:end])).decompress()

    return kvac.SystemParams(
        G_w=get_point_from_hardcoded_system(0),
        G_wprime=get_point_from_hardcoded_system(1),
        G_x0=get_point_from_hardcoded_system(2),
        G_x1=get_point_from_hardcoded_system(3),
        G_ys=[get_point_from_hardcoded_system(i) for i in range(4, 10)],
        G_ms=[get_point_from_hardcoded_system(i) for i in range(10, 15)],
        G_V=get_point_from_hardcoded_system(15),
        G_z=get_point_from_hardcoded_system(16),
    )


def test_generate_signal_hardcoded_test_system():
    # assumption: kvac.RistrettoSho uses HMAC-SHA-256 SHO
    assert kvac.SystemParams.generate_signal_parameters() == get_signal_system_hardcoded()