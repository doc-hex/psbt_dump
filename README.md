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

There are a few PSBT files I've collected from the BIP test vectors and
elsewhere in `./data`. Don't expect them to be 100% correct or reference
or anything like that.

