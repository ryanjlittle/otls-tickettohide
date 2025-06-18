import util
import spec
import tls13_spec
import tls_common
import tls_crypto
import tls_keycalc
import tls_records
import tls_ech
import tls_client
import tls_server

from importlib import reload

def re():
    for mod in (
        util,
        spec,
        tls13_spec,
        tls_common,
        tls_crypto,
        tls_keycalc,
        tls_records,
        tls_ech,
        tls_client,
        tls_server,
    ):
        reload(mod)
