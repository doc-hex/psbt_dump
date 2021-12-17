# PSBT Dump

Quick program to dump the contents of a PSBT: Partially Signed Bitcoin Transaction (see BIP 174).

Accepts binary or hex-encoded PSBT files, and displays each byte. Parses what it can
understand along the way.

**NOTE** Prior to Nov 20/2019, this program would display the XFP (extended fingerprint)
of the derivation paths in the wrong endian.

## Usage

```
# python3 -m pip install --editable .
# pbst_dump data/example.psbt
```

## Requirements

- `python3`
- `pycoin` version 0.80
- `click`

(See `requirements.txt`)

## Data

There are a few PSBT files I've collected from the BIP test vectors
and elsewhere in `./data`. Don't expect them to be 100% correct or
golden reference or anything like that.

# Example Output

```
% psbt_dump data/worked-7.psbt

976 bytes in PSBT: data/worked-7.psbt
-- HEADER --

psbt 0xff

-- GLOBALS --

  key: 00  (GLOBAL_UNSIGNED_TX)
value:

020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000  (154 bytes)

 Transaction: (2 inputs, 2 outputs, 0 witness)
            : txid 82efd652d7ab1197f01a5f4d9a30cb4c68bb79ab6fec58dfa1bf112291d1617b
   [in #0 ] (not signed)
            from 75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858 : 0
   [in #1 ] (not signed)
            from 1dea7cd05979072a3578cab271c02244ea8a090bbb46aa680a65ecd027048d83 : 1
  [out #0 ] tb1qmpwzkuwsqc9snjvgdt4czhjsnywa5yjdzglap9
  [out #1 ] tb1qqzh2ngh97ru8dfvgma25d6r595wcwqy06sqc03


-- INPUT #0 --

  key: 00  (IN_NON_WITNESS_UTXO)
value:

0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f618765000000  (187 bytes)

 Transaction: (1 inputs, 2 outputs, 0 witness)
            : txid 75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858
   [in #0 ] (unknown)
  [out #0 ] 2MtgN5EvHUm2kNVvqKgqsZ9v2fGH3jCpXVF
  [out #1 ] 2Mw4CE6tUQ7Ak9Zf9TKujgzbVjDZqgRbUVP



  key: 07  (IN_FINAL_SCRIPTSIG)
value:

00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae  (218 bytes)

-- INPUT #1 --

  key: 01  (IN_WITNESS_UTXO)
value:

00c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e887  (32 bytes)


  key: 07  (IN_FINAL_SCRIPTSIG)
value:

2200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903  (35 bytes)


  key: 08  (IN_FINAL_SCRIPTWITNESS)
value:

0400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae  (218 bytes)

-- OUTPUT #0 --

  key: 02 03a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca58771 (OUT_BIP32_DERIVATION, 34 bytes)
value:

d90c6a4f000000800000008004000080  (16 bytes)

    Address: 03a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca58771 (33 bytes)
             = n1ExfZ1rECtYdzfBHoeYtAWzTURXsdSVkb
    HD Path: (m=0x4f6a0cd9)/0'/0'/4'


-- OUTPUT #1 --

  key: 02 027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b50051096 (OUT_BIP32_DERIVATION, 34 bytes)
value:

d90c6a4f000000800000008005000080  (16 bytes)

    Address: 027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b50051096 (33 bytes)
             = mfaZXpvjGrisYP1rW2wL2YBHJt22sCoX53
    HD Path: (m=0x4f6a0cd9)/0'/0'/5'


-- EXPECT EOF --
-- ACTUAL EOF --
```
