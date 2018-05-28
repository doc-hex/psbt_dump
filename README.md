# PSBT Dump

Quick program to dump the contents of a PSBT: Partially Signed Bitcoin Transaction (see BIP 174)

## Usage

```
# python3 -m pip install --editable .
# rehash
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
% psbt_dump data/worked-sign2.psbt
902 bytes in PSBT: data/worked-sign2.psbt
-- HEADER --

psbt 0xff

-- GLOBALS --

  key: 00  (1 bytes, 'Transaction')
value:

02000000022e8c7d8d37c427e060ec002ec1c2bc30196fc2f75d6a8844cbc03651c081430a0100000000ffffffff96a04e0cc636f377933e3d93accc627faacdbcdb5a9624df1b490bd045f24d2c0000000000ffffffff01e02be50e0000000017a914b53bb0dc1db8c8d803e3e39f784d42e4737ffa0d8700000000  (124 bytes)

 Transaction: (2 inputs, 1 outputs, 0 witness, 49f50a39d9b9e12f6c6d3e6bf175ab514543da4c684fbdcfdda5078fd6e08ee0)
   [in #0] (not signed)
   [in #1] (not signed)
  [out #0] 3JDHjf9tXTm6tCSZeVPeS6QLH6SZyAAAEN



  key: 01 203736c3c06053896d7041ce8f5bae3df76cc491 (21 bytes, 'Redeem Script')
value:

522103c8727ce35f1c93eb0be21406ee9a923c89219fe9c9e8504c8314a6a22d1295c02103c74dc710c407d7db6e041ee212d985cd2826d93f806ed44912b9a1da691c977352ae  (71 bytes)


  key: 01 f3ba8a120d960ae07d1dbe6f0c37fb4c926d76d5 (21 bytes, 'Redeem Script')
value:

0020a8f44467bf171d51499153e01c0bd6291109fc38bd21b3c3224c9dc6b57590df  (34 bytes)


  key: 02 a8f44467bf171d51499153e01c0bd6291109fc38bd21b3c3224c9dc6b57590df (33 bytes, 'Witness Script')
value:

522102e80dec31d167865c1685e9d7a9291e66a4ea22c65cfee324289a1667ccda3b87210258cbbc3cb295a8bebac233aadc7773978804993798be5390ab444f6dd4c5327e52ae  (71 bytes)

-- SEP -- (below probably for input #0)

  key: 00  (1 bytes, 'UTXO')
value:

02000000018b2dd2f735d0a9338af96402a8a91e4841cd3fed882362e7329fb04f1ff65325000000006a473044022077bedfea9910c9ba4e00dec941dace974f8b47349992c5d4312c1cf5796cce5502206164e6bfff7ac11590064ca571583709337c8a38973db2e70f4e9d93b3bcce1d0121032d64447459784e37cb2dda366c697adbbdc8aae2ad6db74ed2dade39d75882fafeffffff0382b42a04000000001976a914da533648fd339d5797790e6bb1667d9e86fdfb6888ac80f0fa020000000017a914203736c3c06053896d7041ce8f5bae3df76cc4918700b4c4040000000017a914b53bb0dc1db8c8d803e3e39f784d42e4737ffa0d879e2f1300  (255 bytes)

 Transaction: (1 inputs, 3 outputs, 0 witness, 0a4381c05136c0cb44886a5df7c26f1930bcc2c12e00ec60e027c4378d7d8c2e)
   [in #0] 1QL9LAAE6F1JErwLEtL8DgRiYGH75dtje7
  [out #0] 1LuPzVdqmtg7uneoEQZbpvqfgEuchEH6FR
  [out #1] 34dMh1iAGdxepiYzUqx6MDCyWLLzeFyZFA
  [out #2] 3JDHjf9tXTm6tCSZeVPeS6QLH6SZyAAAEN



  key: 02 03c8727ce35f1c93eb0be21406ee9a923c89219fe9c9e8504c8314a6a22d1295c0 (34 bytes, 'Parial Sig')
value:

304402204a33aa884465a7d909000c366afb90c9256b66575f0c7e5f12446a16d8cc1a4d02203fa9fc43d50168f000b280be6b3db916cf9e483de8e6d9eac948b0d08f7601df01  (71 bytes)

-- SEP -- (below probably for input #1)

  key: 01  (1 bytes, 'Witness UTXO')
value:

00c2eb0b0000000017a914f3ba8a120d960ae07d1dbe6f0c37fb4c926d76d587  (32 bytes)


  key: 02 0258cbbc3cb295a8bebac233aadc7773978804993798be5390ab444f6dd4c5327e (34 bytes, 'Parial Sig')
value:

3045022100cdac5ee547b60f79feec111d0e082c3350b30a087c130d5e734e0199b3f8c14702205deddd38d8f7ddb19931059f46b2de0c8548fe79f8c8aea34c5e653ea0136b9501  (72 bytes)

-- SEP -- (below probably for input #2)

-- EOF --
```
