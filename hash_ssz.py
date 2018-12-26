from eth_hash.auto import (
    keccak,
)
from beacon_chain.state import crystallized_state as cs
from ssz.sedes import Serializable, List, UnsignedInteger, Hash

def hash_eth2(x):
    return keccak(x)


CHUNKSIZE = 128


# Merkle tree hash of a list of homogenous, non-empty items
def merkle_hash(lst):
    # Store length of list (to compensate for non-bijectiveness of padding)
    datalen = len(lst).to_bytes(32, 'big')

    if len(lst) == 0:
        # Handle empty list case
        chunkz = [b'\x00' * CHUNKSIZE]
    elif len(lst[0]) < CHUNKSIZE:
        # See how many items fit in a chunk
        items_per_chunk = CHUNKSIZE // len(lst[0])

        # Build a list of chunks based on the number of items in the chunk
        chunkz = [b''.join(lst[i:i+items_per_chunk])
                  for i in range(0, len(lst), items_per_chunk)]
    else:
        # Leave large items alone
        chunkz = lst

    # Tree-hash
    while len(chunkz) > 1:
        if len(chunkz) % 2 == 1:
            chunkz.append(b'\x00' * CHUNKSIZE)
        chunkz = [hash_eth2(chunkz[i] + chunkz[i+1])
                  for i in range(0, len(chunkz), 2)]

    # Return hash of root and length data
    return hash_eth2(chunkz[0] + datalen)


def hash_ssz(val, typ=None):
    if typ is None and hasattr(val, '_meta'):
        typ = type(val)
    if typ in ('hash32', 'address'):
        assert len(val) == 20 if typ == 'address' else 32
        return val
    elif isinstance(typ, str) and typ[:3] == 'int':
        length = int(typ[3:])
        assert length % 8 == 0
        return val.to_bytes(length // 8, 'big', signed=True)
    elif isinstance(typ, str) and typ[:4] == 'uint':
        length = int(typ[4:])
        assert length % 8 == 0
        assert val >= 0
        return val.to_bytes(length // 8, 'big')
    elif isinstance(typ, UnsignedInteger):
        b = val.to_bytes(typ.num_bytes, 'big')
        if typ.num_bytes > 32:
            return hash_eth2(b)
        return b
    elif isinstance(typ, Hash):
        return val
    elif typ == 'bytes':
        return hash_eth2(val)
    elif isinstance(typ, list):
        assert len(typ) == 1
        return merkle_hash([hash_ssz(x, typ[0]) for x in val])
    elif isinstance(typ, List):
        return merkle_hash([hash_ssz(x, typ.element_sedes) for x in val])
    elif isinstance(val, Serializable):
        sub = b''.join(
            [hash_ssz(val[field_name], field_sedes)
                for field_name, field_sedes in typ._meta.fields]
        )
        return hash_eth2(sub)
    raise Exception("Cannot serialize",val, typ)
