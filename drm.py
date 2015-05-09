# drm.py
#
# Copyright 2014, espes
#
# Licensed under GPL Version 2 or later
#

import hashlib

import loader

class FairPlaySAP(object):
    """FairPlay Secure Association Protocol"""

    def __init__(self, airtunes_filename="airtunesd"):

        with open(airtunes_filename, "rb") as f:
            hash_ = hashlib.sha1(f.read()).hexdigest()

        if hash_ == "1024dbffd30d55ecea4fabbc78ee4b3bda265874":
            # AirTunes 120.2, from AppleTV2,1 build 9A334v
            self.fp_initsap = 0x435B4
            self.fp_challenge = 0xEB00C
            self.fp_decryptkey = 0xEB964
        else:
            raise Exception("unsupported airtunesd")

        self.p = loader.IOSProcess(airtunes_filename)
        

        self.fpInfo = 0x123
        self.initSAP()

    def initSAP(self):
        pSapInfo = self.p.malloc(4)
        self.p.call(self.fp_initsap, (pSapInfo, self.fpInfo))

        self.sapInfo = self.p.ld_word(pSapInfo)

    def challenge(self, type_, data, stage):
        fply_1 = [
            chr(0x46), chr(0x50), chr(0x4c), chr(0x59), chr(0x02), chr(0x01), chr(0x01), chr(0x00), chr(0x00), chr(0x00), chr(0x00), chr(0x04), chr(0x02), chr(0x00), chr(0x02), chr(0xbb)
        ];

        # // 2 1 2 -> 130 : 02 02 xxx
        fply_2 = [
            chr(0x46), chr(0x50), chr(0x4c), chr(0x59), chr(0x02), chr(0x01), chr(0x02), chr(0x00), chr(0x00), chr(0x00), chr(0x00), chr(0x82),
            chr(0x02), chr(0x02), chr(0x2f), chr(0x7b), chr(0x69), chr(0xe6), chr(0xb2), chr(0x7e), chr(0xbb), chr(0xf0), chr(0x68), chr(0x5f), chr(0x98), chr(0x54), chr(0x7f), chr(0x37),
            chr(0xce), chr(0xcf), chr(0x87), chr(0x06), chr(0x99), chr(0x6e), chr(0x7e), chr(0x6b), chr(0x0f), chr(0xb2), chr(0xfa), chr(0x71), chr(0x20), chr(0x53), chr(0xe3), chr(0x94),
            chr(0x83), chr(0xda), chr(0x22), chr(0xc7), chr(0x83), chr(0xa0), chr(0x72), chr(0x40), chr(0x4d), chr(0xdd), chr(0x41), chr(0xaa), chr(0x3d), chr(0x4c), chr(0x6e), chr(0x30),
            chr(0x22), chr(0x55), chr(0xaa), chr(0xa2), chr(0xda), chr(0x1e), chr(0xb4), chr(0x77), chr(0x83), chr(0x8c), chr(0x79), chr(0xd5), chr(0x65), chr(0x17), chr(0xc3), chr(0xfa),
            chr(0x01), chr(0x54), chr(0x33), chr(0x9e), chr(0xe3), chr(0x82), chr(0x9f), chr(0x30), chr(0xf0), chr(0xa4), chr(0x8f), chr(0x76), chr(0xdf), chr(0x77), chr(0x11), chr(0x7e),
            chr(0x56), chr(0x9e), chr(0xf3), chr(0x95), chr(0xe8), chr(0xe2), chr(0x13), chr(0xb3), chr(0x1e), chr(0xb6), chr(0x70), chr(0xec), chr(0x5a), chr(0x8a), chr(0xf2), chr(0x6a),
            chr(0xfc), chr(0xbc), chr(0x89), chr(0x31), chr(0xe6), chr(0x7e), chr(0xe8), chr(0xb9), chr(0xc5), chr(0xf2), chr(0xc7), chr(0x1d), chr(0x78), chr(0xf3), chr(0xef), chr(0x8d),
            chr(0x61), chr(0xf7), chr(0x3b), chr(0xcc), chr(0x17), chr(0xc3), chr(0x40), chr(0x23), chr(0x52), chr(0x4a), chr(0x8b), chr(0x9c), chr(0xb1), chr(0x75), chr(0x05), chr(0x66),
            chr(0xe6), chr(0xb3)
        ];

        # // 2 1 3 -> 152
        # // 4 : 02 8f 1a 9c
        # // 128 : xxx
        # // 20 : 5b ed 04 ed c3 cd 5f e6 a8 28 90 3b 42 58 15 cb 74 7d ee 85

        fply_3 = [
            chr(0x46), chr(0x50), chr(0x4c), chr(0x59), chr(0x02), chr(0x01), chr(0x03), chr(0x00), chr(0x00), chr(0x00), chr(0x00), chr(0x98), chr(0x02), chr(0x8f),
            chr(0x1a), chr(0x9c), chr(0x6e), chr(0x73), chr(0xd2), chr(0xfa), chr(0x62), chr(0xb2), chr(0xb2), chr(0x07), chr(0x6f), chr(0x52), chr(0x5f), chr(0xe5), chr(0x72), chr(0xa5),
            chr(0xac), chr(0x4d), chr(0x19), chr(0xb4), chr(0x7c), chr(0xd8), chr(0x07), chr(0x1e), chr(0xdb), chr(0xbc), chr(0x98), chr(0xae), chr(0x7e), chr(0x4b), chr(0xb4), chr(0xb7),
            chr(0x2a), chr(0x7b), chr(0x5e), chr(0x2b), chr(0x8a), chr(0xde), chr(0x94), chr(0x4b), chr(0x1d), chr(0x59), chr(0xdf), chr(0x46), chr(0x45), chr(0xa3), chr(0xeb), chr(0xe2),
            chr(0x6d), chr(0xa2), chr(0x83), chr(0xf5), chr(0x06), chr(0x53), chr(0x8f), chr(0x76), chr(0xe7), chr(0xd3), chr(0x68), chr(0x3c), chr(0xeb), chr(0x1f), chr(0x80), chr(0x0e),
            chr(0x68), chr(0x9e), chr(0x27), chr(0xfc), chr(0x47), chr(0xbe), chr(0x3d), chr(0x8f), chr(0x73), chr(0xaf), chr(0xa1), chr(0x64), chr(0x39), chr(0xf7), chr(0xa8), chr(0xf7),
            chr(0xc2), chr(0xc8), chr(0xb0), chr(0x20), chr(0x0c), chr(0x85), chr(0xd6), chr(0xae), chr(0xb7), chr(0xb2), chr(0xd4), chr(0x25), chr(0x96), chr(0x77), chr(0x91), chr(0xf8),
            chr(0x83), chr(0x68), chr(0x10), chr(0xa1), chr(0xa9), chr(0x15), chr(0x4a), chr(0xa3), chr(0x37), chr(0x8c), chr(0xb7), chr(0xb9), chr(0x89), chr(0xbf), chr(0x86), chr(0x6e),
            chr(0xfb), chr(0x95), chr(0x41), chr(0xff), chr(0x03), chr(0x57), chr(0x61), chr(0x05), chr(0x00), chr(0x73), chr(0xcc), chr(0x06), chr(0x7e), chr(0x4f), chr(0xc7), chr(0x96),
            chr(0xae), chr(0xba), chr(0x5b), chr(0xed), chr(0x04), chr(0xed), chr(0xc3), chr(0xcd), chr(0x5f), chr(0xe6), chr(0xa8), chr(0x28), chr(0x90), chr(0x3b), chr(0x42), chr(0x58),
            chr(0x15), chr(0xcb), chr(0x74), chr(0x7d), chr(0xee), chr(0x85)
        ];

        # // 2 1 4 -> 20 : 5b ed 04 ed c3 cd 5f e6 a8 28 90 3b 42 58 15 cb 74 7d ee 85
        fply_4 = [
            chr(0x46), chr(0x50), chr(0x4c), chr(0x59), chr(0x02), chr(0x01), chr(0x04), chr(0x00), chr(0x00), chr(0x00), chr(0x00), chr(0x14), chr(0x5b),
            chr(0xed), chr(0x04), chr(0xed), chr(0xc3), chr(0xcd), chr(0x5f), chr(0xe6), chr(0xa8), chr(0x28), chr(0x90), chr(0x3b), chr(0x42), chr(0x58), chr(0x15), chr(0xcb), chr(0x74),
            chr(0x7d), chr(0xee), chr(0x85)
        ];

        if stage == 0:
            assert len(data) == 16
            fply_2[4] = data[4]
            fply_2[13] = data[14]
            return ''.join(fply_2)
        elif stage == 1:
            assert len(data) == 164
            fply_4[4] = data[4]
            for i in range(0,20):
                fply_4[12 + i] = data[144 + i]
            return ''.join(fply_4)
        else:
            assert False

        p_data = self.p.malloc(len(data))
        self.p.copyin(p_data, data)

        p_unkn = 0xabc
        
        p_out_data = self.p.malloc(4)
        p_out_length = self.p.malloc(4)

        p_inout_stage = self.p.malloc(4)
        self.p.st_word(p_inout_stage, stage)

        r = self.p.call(self.fp_challenge,
                (type_, self.fpInfo, self.sapInfo,
                 p_data, p_unkn, p_out_data, p_out_length, p_inout_stage))

        # print "args", map(hex, (type_, self.fpInfo, self.sapInfo,
        #          p_data, p_unkn, p_out_data, p_out_length, p_inout_stage))

        # print "r", hex(r)

        #assert r == 0

        out_data = self.p.ld_word(p_out_data)
        # print "out_data", hex(out_data)
        out_length = self.p.ld_word(p_out_length)
        # print "out_length", hex(out_length)
        out_stage = self.p.ld_word(p_inout_stage)
        # print "out_stage", out_stage

        if stage == 0:
            assert out_length == 0x8e
            assert out_stage == 1
        else:
            assert out_stage == 0

        return self.p.copyout(out_data, out_length)

    def decrypt_key(self, param1):
        p_param1 = self.p.malloc(len(param1))
        self.p.copyin(p_param1, param1)

        p_out_data = self.p.malloc(4)
        p_out_length = self.p.malloc(4)

        r = self.p.call(self.fp_decryptkey,
                (self.sapInfo, p_param1, len(param1),
                 p_out_data, p_out_length))

        assert r == 0

        out_data = self.p.ld_word(p_out_data)
        # print "out_data", hex(out_data)
        out_length = self.p.ld_word(p_out_length)
        # print "out_length", hex(out_length)

        assert out_length == 16

        return self.p.copyout(out_data, out_length)

if __name__ == "__main__":
    fp = FairPlaySAP()

    print
    print "Stage 0"
    print
    r0 = fp.challenge(2, "46504c590201010000000004020001bb".decode("hex"), 0)
    print r0.encode("hex")
