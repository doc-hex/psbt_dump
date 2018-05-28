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
def dump(psbt):

    raw = psbt.read()
    if raw[0:10] == b'70736274ff':
        raw = _a2b_hex(raw.strip())

    #assert raw[0:5] == b'psbt\xff'
    
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

            if (sect, key[0]) == (0, 0) or key[0] == 0:
                # Parse and sumarize the bitcoin transaction.
                # - also works for UTXO on the outputs side
                
                try:
                    t = Tx.parse(io.BytesIO(val))
                    print(" Transaction: (%d inputs, %d outputs, %d witness, %s)" % (
                                    len(t.txs_in), len(t.txs_out),
                                    sum(1 for i in t.txs_in if i.witness), t.hash()))
                    for n,i in enumerate(t.txs_in):
                        print("   [in #%d] %s" % (n, i.address() if i.script else '(not signed)'))
                    for n,o in enumerate(t.txs_out):
                        print("  [out #%d] %s" % (n, o.address()))
                    print("\n")
                except:
                    print("(unable to parse txn)")

            

if __name__ == '__main__':
    dump()

