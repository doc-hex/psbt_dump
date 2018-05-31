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
from base64 import b64encode
from pycoin.tx.Tx import Tx
from pycoin.tx.TxOut import TxOut
from pycoin.encoding import b2a_hashed_base58, hash160
from pycoin.serialize import b2h_rev

b2a_hex = lambda a: str(_b2a_hex(a), 'ascii')

def deser_compact_size(f, nit=None):
    nit = nit if nit is not None else struct.unpack("<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    return nit


@click.command()
@click.argument('psbt', type=click.File('rb'))
@click.option('--hex-output', '-h', help="Just show hex string of binary", is_flag=True)
@click.option('--testnet', '-t', help="Assume testnet3 addresses", is_flag=True, default=True)
def dump(psbt, hex_output, testnet):

    raw = psbt.read()
    if raw[0:10] == b'70736274ff':
        raw = _a2b_hex(raw.strip())

    #assert raw[0:5] == b'psbt\xff'

    if hex_output:
        print(b2a_hex(raw))
        sys.exit(0)
    
    print("%d bytes in PSBT: %s" % (len(raw), psbt.name))

    with io.BytesIO(raw) as fd:
        hdr = fd.read(4)
        sep1 = fd.read(1)

        print("-- HEADER --\n\n%s 0x%02x\n" % (str(hdr, 'ascii'), sep1[0]))

        print("-- GLOBALS --")
        sect = 0

        while 1:
            first = fd.read(1)
            if first == b'':
                print("\n-- EOF --")
                break

            try:
                ks = deser_compact_size(fd, first[0])
            except:
                print("? confused at %d=0x%x" % (fd.tell(), fd.tell()))
                break

            if ks == 0:
                sect += 1
                print("-- SEP -- (below probably for input #%d)" % (sect-1))
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
                if sect == 0:
                    purpose = ['Transaction', 'Redeem Script', 'Witness Script',
                                    'HD Path', 'Num PSBT Inputs'][key[0]]
                else:
                    purpose = ['UTXO', 'Witness UTXO', 'Parial Sig',
                                    'Sighash Type', 'Input Index'][key[0]]
            except IndexError:
                purpose = 'UNKNOWN'

            print('\n  key: %02x %s (%s bytes, %r)' % (
                        key[0], b2a_hex(key[1:]) if len(key) > 1 else '', ks, purpose))
            print('value:\n\n%s  (%d bytes)\n' % (b2a_hex(val), vs))

            # prefix byte for addresses in current network
            ADP = b'\x6f' if testnet else b'\0'

            if (sect, key[0]) == (0, 0) or key[0] == 0:
                # Parse and sumarize the bitcoin transaction.
                # - also works for UTXO on the outputs side
                
                try:
                    t = Tx.parse(io.BytesIO(val))
                    print(" Transaction: (%d inputs, %d outputs, %d witness)" % (
                                    len(t.txs_in), len(t.txs_out),
                                    sum(1 for i in t.txs_in if i.witness)))
                    print("            : txid %s" % t.hash())
                    for n,i in enumerate(t.txs_in):
                        print("   [in #%2d] %s" % (n, i.address(ADP) if i.script else '(not signed)'))
                        if sect == 0:
                            print("            from %s : %d" % (b2h_rev(i.previous_hash), i.previous_index))
                    for n,o in enumerate(t.txs_out):
                        print("  [out #%d] %s" % (n, o.address('XTN' if testnet else 'BTC')))
                    print("\n")
                except:
                    raise
                    print("(unable to parse txn)")

            if sect == 0 and key[0] == 0x3:
                # HD key paths
                try:
                    pubkey = key[1:]
                    fingerprint = val[0:4]
                    path = [struct.unpack_from('<I', val,offset=i)[0] 
                                for i in range(4, len(val), 4)]
                    path = [str(i & 0x7fffffff) + ("'" if i & 0x80000000 else "") for i in path]

                    if len(pubkey) in {33, 65}:
                        # assume old skool b58 p2pkh, bitcoin mainnet, etc.
                        addr = b2a_hashed_base58(ADP + hash160(pubkey))
                    else:
                        addr = '(bad length)'

                    print("    Address: %s (%d bytes)" % (b2a_hex(pubkey), len(pubkey)))
                    print("             = %s" % addr)
                    print("    HD Path: (m=0x%08x)/%s" % (
                                    struct.unpack('<I',fingerprint)[0], '/'.join(path)))
                    print("\n")
                except:
                    print("(unable to parse hdpath)")

            

if __name__ == '__main__':
    dump()

