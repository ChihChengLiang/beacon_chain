import hash_ssz
from beacon_chain.state import crystallized_state as cs
from old_ssz import ssz
import time
from eth_hash.auto import (
    keccak,
)
from ssz import encode
from ssz.sedes import Serializable, List, uint32, uint64, uint24, uint384, hash32
from ssz.tree_hash.tree_hash import hash_tree_root


def hash(x):
    return keccak(x)


class ValidatorRecord(Serializable):
    fields = [
        ('pubkey', uint384),
        ('withdrawal_credentials', hash32),
        ('randao_commitment', hash32),
        ('randao_layers', uint64),
        ('status', uint64),
        ('latest_status_change_slot', uint64),
        ('exit_count', uint64),
        ('poc_commitment', hash32),
        ('last_poc_change_slot', uint64),
        ('second_last_poc_change_slot', uint64),
    ]


class CrosslinkRecord(Serializable):
    fields = [

        ('slot', uint64),
        ('shard_block_root', hash32),
    ]


class ShardCommittee(Serializable):
    fields = [
        ('shard', uint64),
        ('committee', List(uint24)),
        ('total_validator_count', uint64),
    ]


class State(Serializable):
    fields = [
        ('validator_registry', List(ValidatorRecord)),
        ('shard_and_committee_for_slots', List(List(ShardCommittee))),
        ('latest_crosslinks', List(CrosslinkRecord)),
    ]


v = ValidatorRecord(
    pubkey=123,
    withdrawal_credentials=b'\x56'*32,
    randao_commitment=b'\x56'*32,
    randao_layers=123,
    status=123,
    latest_status_change_slot=123,
    exit_count=123,
    poc_commitment=b'\x56'*32,
    last_poc_change_slot=123,
    second_last_poc_change_slot=123,
)
c = CrosslinkRecord(slot=12847, shard_block_root=b'\x67' * 32)
cr_stubs = [c for i in range(1024)]


def make_state(valcount):
    sc_stub = ShardCommittee(
        shard=1, committee=list(range(valcount // 1024)),
        total_validator_count=valcount,
    )
    sc_stubs = [[sc_stub for i in range(16)] for i in range(64)]
    c = State(
        validator_registry=[v for i in range(valcount)],
        shard_and_committee_for_slots=sc_stubs,
        latest_crosslinks=cr_stubs,
    )
    return c


def time_test(valcount):
    c = make_state(valcount)
    a = time.time()
    h = hash_ssz.hash_ssz(c)
    print("Old hash_ssz:", time.time() - a)


def time_test_pyssz(valcount):
    c = make_state(valcount)
    a = time.time()
    s = hash_tree_root(c)
    print("New hash_tree_root",  time.time() - a)


if __name__ == '__main__':
    time_test(2**18)
    time_test_pyssz(2**18)
