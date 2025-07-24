from textwrap import dedent

from spec import Raw
from spec_gen import GenSpec, NamedConst, Select, Sequence, Struct, Bounded, FixRaw, Names, FORCE_RANK, SourceGen
from tls13_spec import Record
from util import kwdict

specs: dict[str, GenSpec] = kwdict(
    ProverMsgType = NamedConst(8)(
        SERVER_HANDSHAKE_TX = 1,
        HASH_1S             = 2,
        HASH_4S             = 3,
        COMMITMENT          = 4,
        KEX_SHARES          = 5,
        PROOF               = 6,
        CLIENT_RANDOMS      = 7,
    ),

    VerifierMsgType = NamedConst(8)(
        KEX_SHARES_PHASE_1 = 1,
        HANDSHAKE_KEYS     = 2,
        APPLICATION_KEYS   = 3,
        KEX_SHARE_PHASE_2  = 4,
        KEX_SECRETS        = 5,
        MASTER_SECRETS     = 99, # for testing purposes only!
    ),

    ProverMsg = Select('ProverMsgType', 24)(
        SERVER_HANDSHAKE_TX = Sequence(Struct(
                server_hello = Record,
                encrypted_extensions = Record,
                certificate = Record,
                cert_verify = Record,
                server_finished = Record
            )),
        HASH_1S = Struct(hashes = Sequence(FixRaw(32))),
        HASH_4S = Struct(hashes = Sequence(FixRaw(32))),
        COMMITMENT = Struct(commitment = Raw),
        KEX_SHARES = Struct(kex_shares = Sequence(FixRaw(32))),
        PROOF = Struct(proof = Raw),
        CLIENT_RANDOMS = Struct(cli_randoms = Sequence(FixRaw(32))),
    ),

    VerifierMsg = Select('VerifierMsgType', 16)(
        KEX_SHARES_PHASE_1 = Struct(kex_shares = Bounded(16, Sequence(FixRaw(32)))),
        HANDSHAKE_KEYS = Sequence(Struct(chts = FixRaw(32), shts = FixRaw(32))),
        APPLICATION_KEYS = Sequence(Struct(cats = FixRaw(32), sats = FixRaw(32))),
        KEX_SHARE_PHASE_2  = Struct(kex_share = FixRaw(32)),
        KEX_SECRETS        = Struct(kex_secrets = Sequence(FixRaw(32))),
        MASTER_SECRETS     = Struct(secrets = Sequence(Bounded(8, Raw))), # for testing purposes only!
    )
)


def write_to(fname: str) -> None:
    with open(fname, 'w') as fout:
        ns = Names()

        for (name, spec) in specs.items():
            spec.suggest(name, FORCE_RANK)
            ns.register(spec)

        sg = SourceGen(fout, ns.assign())
        sg.preamble()
        fout.write(dedent("""\
            import tls13_spec
            from tls_common import *
            from proof_common import *
        """))
        sg.write_all(ns.order())
        sg.epilogue()

    print('specs written to', fname)


if __name__ == '__main__':
    write_to('proof_spec.py')