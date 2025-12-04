from textwrap import dedent

from tls13.spec import Raw, String
from tls13.spec_gen import GenSpec, NamedConst, Select, Sequence, Struct, Bounded, Names, FORCE_RANK, SourceGen
from tls13.tls13_spec import TicketInfo, NamedGroup, KeyShareEntry, Uint8
from tls13.util import kwdict

specs: dict[str, GenSpec] = kwdict(
    ClientHelloValues=Struct(
        hostname=Bounded(8, String),
        ticket_info=TicketInfo,
        binder_key=Bounded(8, Raw),
        kex_shares=Bounded(16, Sequence(KeyShareEntry))
    ),

    ProverMsgType = NamedConst(8)(
        KEX_SHARES  = 1
    ),

    VerifierMsgType = NamedConst(8)(
        TICKETS           = 1,
        APP_KEY_SHARES    = 2,
        OK                = 97, # for benchmarking
        HANDSHAKE_SECRETS = 98, # for testing
        MASTER_SECRETS    = 99, # for testing
    ),

    ProverMsg = Select('ProverMsgType', 16)(
        KEX_SHARES =
            Sequence(Bounded(16, Sequence(Struct(
                group=NamedGroup,
                pubkey=Bounded(16, Raw)
            )))),
    ),

    VerifierMsg = Select('VerifierMsgType', 16)(
        TICKETS = Sequence('ClientHelloValues'),
        APP_KEY_SHARES = Struct(
            server_key_share = Bounded(8, Raw),
            client_key_share = Bounded(8, Raw),
        ),
        OK = Uint8,
        HANDSHAKE_SECRETS=Sequence(Struct(secret=Bounded(8, Raw))),  # for testing purposes only!
        MASTER_SECRETS = Sequence(Struct(secret=Bounded(8, Raw))), # for testing purposes only!
    ),
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
            import tls13.tls13_spec
            from tls13.tls_common import *
            from tickettohide.proof_common import *
        """))
        sg.write_all(ns.order())
        sg.epilogue()

    print('specs written to', fname)


if __name__ == '__main__':
    write_to('tickettohide/proof_spec.py')