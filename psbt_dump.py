#!/usr/bin/env python3
#
# To use this, install with:
#
#   pip install --editable .
#
# That will create the command "psbt_dump" in your path... or just use "./psbt_dump foo.psbt" here
#
#
import click, sys, os, pdb, struct, io
from pprint import pformat
from binascii import b2a_hex as _b2a_hex
from binascii import a2b_hex as _a2b_hex
from collections import namedtuple
from base64 import b64encode, b64decode
from pycoin.tx.Tx import Tx
from pycoin.tx.TxOut import TxOut
from pycoin.encoding import b2a_hashed_base58, hash160
from pycoin.serialize import b2h_rev
from segwit_addr import encode as bech32_encode

# BIP-174 aka PSBT defined values
PSBT_GLOBAL_UNSIGNED_TX 	= (0)
PSBT_GLOBAL_XPUB        	= (1)

PSBT_IN_NON_WITNESS_UTXO 	= (0)
PSBT_IN_WITNESS_UTXO 	    = (1)
PSBT_IN_PARTIAL_SIG 	    = (2)
PSBT_IN_SIGHASH_TYPE 	    = (3)
PSBT_IN_REDEEM_SCRIPT 	    = (4)
PSBT_IN_WITNESS_SCRIPT 	    = (5)
PSBT_IN_BIP32_DERIVATION 	= (6)
PSBT_IN_FINAL_SCRIPTSIG 	= (7)
PSBT_IN_FINAL_SCRIPTWITNESS = (8)

PSBT_OUT_REDEEM_SCRIPT 	    = (0)
PSBT_OUT_WITNESS_SCRIPT 	= (1)
PSBT_OUT_BIP32_DERIVATION 	= (2)


SIGHASH_MAP = {
    1: "ALL",
    2: "NONE",
    3: "SINGLE",
    1 | 0x80: "ALL|ANYONECANPAY",
    2 | 0x80: "NONE|ANYONECANPAY",
    3 | 0x80: "SINGLE|ANYONECANPAY",
}

b2a_hex = lambda a: str(_b2a_hex(a), 'ascii')

# no endian swap needed here, because we read as byte string from file
xfp2hex = lambda a: b2a_hex(a).upper()

def deser_compact_size(f, nit=None):
    nit = nit if nit is not None else struct.unpack("<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    return nit

def render_address(script, testnet=True):
    # take a scriptPubKey (part of the TxOut) and convert into conventional human-readable
    # string... aka: the "payment address"

    ll = len(script)

    if not testnet:
        bech32_hrp = 'bc'
        b58_addr    = bytes([0])
        b58_script  = bytes([5])
    else:
        bech32_hrp = 'tb'
        b58_addr    = bytes([111])
        b58_script  = bytes([196])

    # P2PKH
    if ll == 25 and script[0:3] == b'\x76\xA9\x14' and script[23:26] == b'\x88\xAC':
        return b2a_hashed_base58(b58_addr + script[3:3+20])

    # P2SH
    if ll == 23 and script[0:2] == b'\xA9\x14' and script[22] == 0x87:
        return b2a_hashed_base58(b58_script + script[2:2+20])

    # P2WPKH
    if ll == 22 and script[0:2] == b'\x00\x14':
        return bech32_encode(bech32_hrp, 0, script[2:])

    # P2WSH, P2TR and later.
    if ll == 34 and (0 <= script[0] <= 16) and script[1] == 0x20:
        return bech32_encode(bech32_hrp, script[0], script[2:])

    return '[script: %s]' % b2a_hex(script)


@click.command()
@click.argument('psbt', type=click.File('rb'))
@click.option('--hex-output', '-h', help="Just show hex string of binary", is_flag=True)
@click.option('--bin-output', '-b', type=click.File('wb'), help="Output binary PSBT")
@click.option('--base64', '-6', help="Output base64 encoded PSBT", is_flag=True)
@click.option('--testnet', '-t', help="Assume testnet3 addresses", is_flag=True, default=False)
@click.option('--show-addrs', '-a', help="Attempt decode of addresses", is_flag=True, default=False)
def dump(psbt, hex_output, bin_output, testnet, base64, show_addrs):

    raw = psbt.read()
    if raw[0:10] == b'70736274ff':
        raw = _a2b_hex(raw.strip())
    if raw[0:6] == b'cHNidP':
        raw = b64decode(raw)

    #assert raw[0:5] == b'psbt\xff'

    if hex_output:
        print(b2a_hex(raw))
        sys.exit(0)

    if base64:
        print(str(b64encode(raw), 'ascii'))
        sys.exit(0)
    
    print("%d bytes in PSBT: %s" % (len(raw), psbt.name))

    if bin_output:
        bin_output.write(raw)
        sys.exit(0)

    with io.BytesIO(raw) as fd:
        hdr = fd.read(4)
        sep1 = fd.read(1)

        print("-- HEADER --\n\n%s 0x%02x\n" % (str(hdr, 'ascii'), sep1[0]))

        print("-- GLOBALS --")
        num_ins = None
        num_outs = None
        section = 'globals'
        section_idx = 0
        expect_outs = set()

        while 1:
            first = fd.read(1)
            if first == b'':
                print("-- ACTUAL EOF --")
                break

            try:
                ks = deser_compact_size(fd, first[0])
            except:
                print("? confused at %d=0x%x" % (fd.tell(), fd.tell()))
                break

            if ks == 0:
                section_idx += 1

                if section == 'globals':
                    section_idx = 0
                    section = 'inputs'
                    print("-- INPUT #0 --")
                elif section == 'inputs':
                    if section_idx == num_ins:
                        print("-- OUTPUT #0 --")
                        section = 'outputs'
                        section_idx = 0
                    else:
                        print("-- INPUT #%d --" % section_idx)
                elif section == 'outputs':
                    if section_idx == num_outs:
                        print("-- EXPECT EOF --")
                        section = 'past eof'
                        section_idx = 0
                    else:
                        print("-- OUTPUT #%d --" % section_idx)
                else:
                    print("-- ?? %s ??  --" % section.upper())
                continue

            try:
                assert ks
                key = fd.read(ks)

                vs = deser_compact_size(fd)
                assert vs
                val = fd.read(vs)

            except:
                print("? confused at %d=0x%x" % (fd.tell(), fd.tell()))
                break

            try:
                if section == 'globals':
                    purpose = [ 'GLOBAL_UNSIGNED_TX',
                                'GLOBAL_XPUB'][key[0]]
                elif section == 'inputs':
                    purpose = [ 'IN_NON_WITNESS_UTXO',
                                'IN_WITNESS_UTXO',
                                'IN_PARTIAL_SIG',
                                'IN_SIGHASH_TYPE',
                                'IN_REDEEM_SCRIPT',
                                'IN_WITNESS_SCRIPT',
                                'IN_BIP32_DERIVATION',
                                'IN_FINAL_SCRIPTSIG',
                                'IN_FINAL_SCRIPTWITNESS'][key[0]]
                elif section == 'outputs':
                    purpose = [ 'OUT_REDEEM_SCRIPT',
                                'OUT_WITNESS_SCRIPT',
                                'OUT_BIP32_DERIVATION'][key[0]]

            except IndexError:
                purpose = 'Unknown type=0x%0x' % key[0]

            print('\n  key: %02x ' % key[0], end='')
            if len(key) <= 1:
                print("(%s)" % purpose)
            else:
                print('%s\n       (%s + %d bytes)' % (b2a_hex(key[1:]), purpose, ks-1))

            print('value: ', end='')

            if len(val) == 4 and key[0] != PSBT_GLOBAL_XPUB:
                nn, = struct.unpack("<I", val)
                if key[0] == PSBT_IN_SIGHASH_TYPE:
                    print("'%s' = 0x%x = %d = %s\n" % (b2a_hex(val), nn, nn, SIGHASH_MAP[nn]))
                else:
                    print("'%s' = 0x%x = %d\n" % (b2a_hex(val), nn, nn))
                continue

            print('%s  (%d bytes)\n' % (b2a_hex(val), vs))

            # prefix byte for addresses in current network
            ADP = b'\x6f' if testnet else b'\0'

            if (section, key[0]) in [ ('globals', PSBT_GLOBAL_UNSIGNED_TX),
                                      ('inputs', PSBT_IN_NON_WITNESS_UTXO)]:
                # Parse and sumarize the bitcoin transaction.
                # - also works for non-witness UTXO 
                
                try:
                    t = Tx.parse(io.BytesIO(val))
                    print(" Transaction: (%d inputs, %d outputs, %d witness)" % (
                                    len(t.txs_in), len(t.txs_out),
                                    sum(1 for i in t.txs_in if i.witness)))
                    print("            : txid %s" % t.hash())
                    for n,i in enumerate(t.txs_in):
                        print("   [in #%d] %s" % (n, i.address(ADP) if i.script else '(not signed)'))
                        if section == 'globals':
                            print("    from %s : %d" % (b2h_rev(i.previous_hash), i.previous_index))
                    for n,o in enumerate(t.txs_out):
                        out_addr = render_address(o.script, testnet)
                        print("  [out #%d] %.8f => %s" % (n, o.coin_value/1E8, out_addr))
                        expect_outs.add(out_addr)
                    print("\n")

                    if num_ins is None:
                        num_ins = len(t.txs_in)
                        num_outs = len(t.txs_out)
                except:
                    print("(unable to parse txn)")
                    raise

            if (section, key[0]) == ('globals', PSBT_GLOBAL_XPUB):
                # key is: binary BIP32 serialization (not base58)
                # value is: master key fingerprint catenated with the derivation path of public key

                fingerprint = val[0:4]
                if len(val) > 4:
                    path = [struct.unpack_from('<I', val, offset=i)[0] for i in range(4, len(val), 4)]
                    path = [str(i & 0x7fffffff) + ("'" if i & 0x80000000 else "") for i in path]
                else:
                    # valid: no subpath, just xfp.
                    path = []
                
                print("       XPUB: %s" % b2a_hashed_base58(key[1:]))
                print("    HD Path: (m=%s)/%s\n" % (xfp2hex(fingerprint), '/'.join(path)))

            if (section, key[0]) in [('inputs', PSBT_IN_BIP32_DERIVATION),
                                     ('outputs', PSBT_OUT_BIP32_DERIVATION)]:
                # HD key paths
                try:
                    pubkey = key[1:]
                    fingerprint = val[0:4]
                    path = [struct.unpack_from('<I', val,offset=i)[0] 
                                for i in range(4, len(val), 4)]
                    path = [str(i & 0x7fffffff) + ("'" if i & 0x80000000 else "") for i in path]

                    # conservative: render them all, pick one found if expected
                    # - but not helpful for multisig, need to look around to know if thats the case
                    addrs = []
                    if show_addrs:
                        if len(pubkey) in {33, 65}:
                            # assume old skool b58 p2pkh, bitcoin mainnet, etc.
                            h20 = hash160(pubkey)
                            for prefix in [0, 111]:
                                addrs.append(b2a_hashed_base58(bytes([prefix]) + h20))
                            for hrp in ['bc', 'tb']:
                                addrs.append(bech32_encode(hrp, 0, h20))        # really?

                        match = set(addrs).intersection(expect_outs)
                        if match:
                            addrs = list(match)

                    print("     Pubkey: %s (%d bytes)" % (b2a_hex(pubkey), len(pubkey)))
                    print("    HD Path: (m=%s)/%s" % (xfp2hex(fingerprint), '/'.join(path)))
                    for addr in addrs:
                        print("             = %s" % addr)
                    print("\n")
                except:
                    print("(unable to parse hdpath)")

            if (section, key[0]) in [('inputs', PSBT_IN_REDEEM_SCRIPT),
                                     ('inputs', PSBT_IN_WITNESS_SCRIPT),
                                     ('outputs', PSBT_OUT_REDEEM_SCRIPT),
                                     ('outputs', PSBT_OUT_WITNESS_SCRIPT)]:

                try:
                    if val[-1] == 0xAE and len(val) > 22:
                        M, N = (val[0]-80, val[-2]-80)
                        print("     P2SH Multisig: %d of %d" % (M, N))
                        print("     Pubkeys: ")
                        for idx in range(N):
                            pk = val[1 + (34 * idx):]
                            assert pk[0] == 0x21
                            print("        #%d: %s" % (idx+1, b2a_hex(pk[1:1+33])))

                        exp = ((N*34) + 3)
                        if len(val) > exp:
                            print("        (plus JUNK: %d bytes)" % (len(val) - exp))
                        print("\n")
                        
                        # XXX decode implied p2sh addresses here too?
                except:
                    print("(unable to parse POSSIBLE multisig redeem script)")

if __name__ == '__main__':
    dump()

# EOF
