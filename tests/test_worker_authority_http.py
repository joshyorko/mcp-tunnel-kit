import ipaddress
import json
import threading
import urllib.request
import urllib.error
from types import SimpleNamespace

import pytest
from test_devsy_bridge import bridge
from test_owned_workspace import owned, NAME, UID, TOKEN


def test_private_authority_reports_revocation_without_provider_or_credentials(tmp_path):
    module = bridge()
    _, scope, _ = owned(tmp_path)
    scope.owned_workspace(NAME, UID, TOKEN)
    scope.metadata = lambda *args: pytest.fail('Authority must not query provider')
    devsy = SimpleNamespace(scope=scope, stopping=threading.Event())
    server = module.BridgeServer(('127.0.0.1', 0), devsy, ipaddress.ip_network('127.0.0.0/8'), 'fixture')
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f'http://127.0.0.1:{server.server_port}/worker-authorized?name={NAME}&uid={UID}&operation_id=owned-operation'
    try:
        assert json.load(urllib.request.urlopen(url, timeout=2)) == {'authorized': True}
        with pytest.raises(urllib.error.HTTPError):
            urllib.request.urlopen(url + '&command=bad', timeout=2)
        config = json.loads(scope.config.read_text()); config['enabled'] = False
        scope.config.write_text(json.dumps(config))
        assert json.load(urllib.request.urlopen(url, timeout=2)) == {'authorized': False}
        request = urllib.request.Request(url, headers={'Host': 'outside.invalid'})
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request, timeout=2)
        assert error.value.code == 403
    finally:
        server.shutdown(); server.server_close(); thread.join()
