#!/usr/bin/env python3
#
# To use this, install with:
#
#   pip install --editable .
#
# That will create the command "psbt_dump" in your path... or just use "./psbt_dump foo.psbt" here
#
#
import click, sys, pdb, struct, io, copy
from binascii import b2a_hex as _b2a_hex
from binascii import a2b_hex as _a2b_hex
from base64 import b64encode, b64decode
from pycoin.symbols.btc import network
from pycoin.symbols.xtn import network as testnetwork
from pycoin.encoding.hash import hash160
from pycoin.encoding.b58 import b2a_hashed_base58
from pycoin.encoding.hexbytes import b2h_rev
from segwit_addr import encode as bech32_encode

Tx = network.Tx

# BIP-174 aka PSBT defined values
#
# GLOBAL ===
PSBT_GLOBAL_UNSIGNED_TX 	     = 0x00
PSBT_GLOBAL_XPUB        	     = 0x01
PSBT_GLOBAL_VERSION              = 0xfb
PSBT_GLOBAL_PROPRIETARY          = 0xfc
# BIP-370
PSBT_GLOBAL_TX_VERSION           = 0x02
PSBT_GLOBAL_FALLBACK_LOCKTIME    = 0x03
PSBT_GLOBAL_INPUT_COUNT          = 0x04
PSBT_GLOBAL_OUTPUT_COUNT         = 0x05
PSBT_GLOBAL_TX_MODIFIABLE        = 0x06

# INPUTS ===
PSBT_IN_NON_WITNESS_UTXO 	     = 0x00
PSBT_IN_WITNESS_UTXO 	         = 0x01
PSBT_IN_PARTIAL_SIG 	         = 0x02
PSBT_IN_SIGHASH_TYPE 	         = 0x03
PSBT_IN_REDEEM_SCRIPT 	         = 0x04
PSBT_IN_WITNESS_SCRIPT 	         = 0x05
PSBT_IN_BIP32_DERIVATION 	     = 0x06
PSBT_IN_FINAL_SCRIPTSIG 	     = 0x07
PSBT_IN_FINAL_SCRIPTWITNESS      = 0x08
PSBT_IN_POR_COMMITMENT           = 0x09   # Proof of Reserves
PSBT_IN_RIPEMD160                = 0x0a
PSBT_IN_SHA256                   = 0x0b
PSBT_IN_HASH160                  = 0x0c
PSBT_IN_HASH256                  = 0x0d
# BIP-370
PSBT_IN_PREVIOUS_TXID            = 0x0e
PSBT_IN_OUTPUT_INDEX             = 0x0f
PSBT_IN_SEQUENCE                 = 0x10
PSBT_IN_REQUIRED_TIME_LOCKTIME   = 0x11
PSBT_IN_REQUIRED_HEIGHT_LOCKTIME = 0x12
# BIP-371
PSBT_IN_TAP_KEY_SIG              = 0x13
PSBT_IN_TAP_SCRIPT_SIG           = 0x14
PSBT_IN_TAP_LEAF_SCRIPT          = 0x15
PSBT_IN_TAP_BIP32_DERIVATION     = 0x16
PSBT_IN_TAP_INTERNAL_KEY         = 0x17
PSBT_IN_TAP_MERKLE_ROOT          = 0x18

# OUTPUTS ===
PSBT_OUT_REDEEM_SCRIPT 	         = 0x00
PSBT_OUT_WITNESS_SCRIPT 	     = 0x01
PSBT_OUT_BIP32_DERIVATION 	     = 0x02
# BIP-370
PSBT_OUT_AMOUNT                  = 0x03
PSBT_OUT_SCRIPT                  = 0x04
# BIP-371
PSBT_OUT_TAP_INTERNAL_KEY        = 0x05
PSBT_OUT_TAP_TREE                = 0x06
PSBT_OUT_TAP_BIP32_DERIVATION    = 0x07

v2_FIELDS = (
    PSBT_GLOBAL_TX_VERSION,
    PSBT_GLOBAL_FALLBACK_LOCKTIME,
    PSBT_GLOBAL_INPUT_COUNT,
    PSBT_GLOBAL_OUTPUT_COUNT,
    PSBT_GLOBAL_TX_MODIFIABLE,
    PSBT_IN_PREVIOUS_TXID,
    PSBT_IN_OUTPUT_INDEX,
    PSBT_IN_SEQUENCE,
    PSBT_IN_REQUIRED_TIME_LOCKTIME,
    PSBT_IN_REQUIRED_HEIGHT_LOCKTIME,
    PSBT_OUT_AMOUNT,
    PSBT_OUT_SCRIPT,
)

global_purpose = {}
output_purpose = {}
input_purpose  = {}
# need to copy here otherwise - length changed during iteration
for k, v in copy.copy(globals()).items():
    if "PSBT_OUT_" in k:
        output_purpose[v] = k
    if "PSBT_IN_" in k:
        input_purpose[v] = k
    if "PSBT_GLOBAL_" in k:
        global_purpose[v] = k


SIGHASH_MAP = {
    0: "DEFAULT",  # Taproot specific
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

    # segwit v0 (P2WPKH, P2WSH)
    if script[0] == 0 and script[1] in (0x14, 0x20) and ll in (22, 34):
        return bech32_encode(bech32_hrp, script[0], script[2:])

    # segwit v1 (P2TR) and later segwit version
    if ll == 34 and 0x51 <= script[0] <= 0x60 and script[1] == 0x20:
        return bech32_encode(bech32_hrp, script[0] - 80, script[2:])

    return '[script: %s]' % b2a_hex(script)


@click.command()
@click.argument('psbt', type=click.File('rb'))
@click.option('--hex-output', '-h', help="Just show hex string of binary", is_flag=True)
@click.option('--bin-output', '-b', type=click.File('wb'), help="Output binary PSBT")
@click.option('--base64', '-6', help="Output base64 encoded PSBT", is_flag=True)
@click.option('--testnet', '-t', help="Assume testnet3 addresses", is_flag=True, default=False)
@click.option('--show-addrs', '-a', help="Attempt decode of addresses", is_flag=True, default=False)
def dump(psbt, hex_output, bin_output, testnet, base64, show_addrs):
    has_txn = False
    version = None
    v2_fields = False

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
                    purpose = global_purpose[key[0]]
                elif section == 'inputs':
                    purpose = input_purpose[key[0]]
                elif section == 'outputs':
                    purpose = output_purpose[key[0]]

            except IndexError:
                purpose = 'Unknown type=0x%0x' % key[0]

            print('\n  key: %02x ' % key[0], end='')
            if len(key) <= 1:
                print("(%s)" % purpose)
            else:
                print('%s\n       (%s + %d bytes)' % (b2a_hex(key[1:]), purpose, ks-1))

            print('value: ', end='')

            if key[0] in v2_FIELDS:
                v2_fields = True

            if len(val) == 4 and key[0] != PSBT_GLOBAL_XPUB:
                nn, = struct.unpack("<I", val)
                if key[0] == PSBT_IN_SIGHASH_TYPE:
                    print("'%s' = 0x%x = %d = %s\n" % (b2a_hex(val), nn, nn, SIGHASH_MAP[nn]))
                else:
                    print("'%s' = 0x%x = %d\n" % (b2a_hex(val), nn, nn))

                if key[0] == PSBT_GLOBAL_VERSION:
                    print("\tPSBTv%d\n" % nn)
                    version = nn

                continue

            if section == "globals" and key[0] == PSBT_GLOBAL_INPUT_COUNT:
                num_ins = deser_compact_size(io.BytesIO(val))
                v2_fields = True

            if section == "globals" and key[0] == PSBT_GLOBAL_OUTPUT_COUNT:
                num_outs = deser_compact_size(io.BytesIO(val))
                v2_fields = True

            print('%s  (%d bytes)\n' % (b2a_hex(val), vs))

            # prefix byte for addresses in current network
            ADP = testnetwork.address if testnet else network.address

            if section == "globals" and key[0] == PSBT_GLOBAL_TX_MODIFIABLE:
                print("\tbitfield: %s\n" % bin(val[0]))
                if val[0] & 0b1:
                    print("\tInputs can be modified.")
                if val[0] & 0b10:
                    print("\tOutputs can be modified.")
                if val[0] & 0b100:
                    print("\tHas SIGHASH_SINGLE flag.")
                if val[0] & 0xf8:
                    print("\tUndefined bit flag set.")
                print()

            if (section, key[0]) in [ ('globals', PSBT_GLOBAL_UNSIGNED_TX),
                                      ('inputs', PSBT_IN_NON_WITNESS_UTXO)]:
                # Parse and sumarize the bitcoin transaction.
                # - also works for non-witness UTXO 
                if key[0] == PSBT_GLOBAL_UNSIGNED_TX:
                    has_txn = True

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

            if section == "outputs" and key[0] == PSBT_OUT_AMOUNT:
                sats = struct.unpack("<q", val)[0]
                print('\t%d sats\t%d\n' % (sats, sats / 100000000))
                continue

            if section == "outputs" and key[0] == PSBT_OUT_SCRIPT:
                addr = render_address(val, testnet)
                print('\t%s\n' % addr)
                continue

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

            if (section, key[0]) == ("outputs", PSBT_OUT_TAP_TREE):
                reader = io.BytesIO(val)
                print("    Output Taproot Tree:")
                while True:
                    depth = reader.read(1)
                    if not depth:
                        break
                    leaf_version = reader.read(1)[0] & 0xfe
                    script_len = deser_compact_size(reader)
                    script = reader.read(script_len)
                    print("        Depth: %d" % int(depth[0]))
                    print("        Leaf Version: %s" % hex(leaf_version))
                    print("        Script: %s" % b2a_hex(script))

            if (section, key[0]) == ("inputs", PSBT_IN_TAP_SCRIPT_SIG):
                print("    Taproot script signature:")
                assert len(key[1:]) == 64
                xonly, script_hash = key[1:33], key[33:]
                print("    Xonly pubkey: %s" % b2a_hex(xonly))
                print("    Leaf Hash: %s" % b2a_hex(script_hash))
                assert len(val) in (64, 65)
                if len(val) == 64:
                    print("    Schnorr Signature: %s (sighash=DEFAULT)" % b2a_hex(val))
                else:
                    print("    Schnorr Signature: %s (sighash=%s)" % (b2a_hex(val[:-1]), SIGHASH_MAP[val[-1]]))

            if (section, key[0]) == ("inputs", PSBT_IN_TAP_LEAF_SCRIPT):
                version = key[1]
                control_block = key[2:]
                assert (len(control_block)) % 32 == 0, "PSBT_IN_TAP_LEAF_SCRIPT control block is not valid"
                script, leaf_version = val[:-1], int(val[-1]) & 0xfe
                print("    Leaf Version: %s" % hex(leaf_version))
                print("    Script: %s" % b2a_hex(script))
                cbs = [control_block[i:i + 32] for i in range(0, len(control_block), 32)]
                print("    Control block:")
                print("        Leaf Version: %s (parity bit: %d)" % (hex(version & 0xfe), version & 0x01))
                print("        Internal Key: %s" % b2a_hex(cbs[0]))
                for cb in cbs[1:]:
                    print("        %s" % b2a_hex(cb))

            if (section, key[0]) in [('inputs', PSBT_IN_TAP_BIP32_DERIVATION),
                                     ('outputs', PSBT_OUT_TAP_BIP32_DERIVATION)]:
                # taproot HD key paths
                try:
                    xonly_pubkey = key[1:]
                    reader = io.BytesIO(val)
                    leaf_hash_len = deser_compact_size(reader)
                    leaf_hashes = []
                    for _ in range(leaf_hash_len):
                        leaf_hashes.append(reader.read(32))
                    xfp_path = reader.read()
                    fingerprint = xfp_path[0:4]
                    path = [struct.unpack_from('<I', xfp_path,offset=i)[0]
                                for i in range(4, len(xfp_path), 4)]
                    path = [str(i & 0x7fffffff) + ("'" if i & 0x80000000 else "") for i in path]

                    is_internal = True if not leaf_hash_len else False
                    print("    Xonly Pubkey%s: %s (%d bytes)" % ("(internal)" if is_internal else "",
                                                                 b2a_hex(xonly_pubkey), len(xonly_pubkey)))
                    if leaf_hashes:
                        print("    Leaf Hashes:")
                        for lh in leaf_hashes:
                            print("        %s" % b2a_hex(lh))
                    print("    HD Path: (m=%s)/%s" % (xfp2hex(fingerprint), '/'.join(path)))
                    print("\n")
                except:
                    print("(unable to parse taproot hdpath)")

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

                    print("    Pubkey: %s (%d bytes)" % (b2a_hex(pubkey), len(pubkey)))
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
    print()
    if version is not None:
        if version == 0 and v2_fields:
            print("INVALID: PSBT v0 requires exclusion of PSBT v2 fields.")
        elif version == 2 and has_txn:
            print("INVALID: PSBT v2 requires exclusion of PSBT_GLOBAL_UNSIGNED_TX")
    else:
        if has_txn and v2_fields:
            print("INVALID: PSBT contains PSBT_GLOBAL_UNSIGNED_TX together with PSBT v2 fields.")



if __name__ == '__main__':
    dump()

# EOF
