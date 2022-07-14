from services.maglev_cli.maglevclihandler import MaglevSystemCommandLine as MSCL


def test_mscl_init():
    try:
        mscl = MSCL(
            node_ip='10.195.227.14',
            username='admin',
            password='Maglev123',
            port=2222,
        )
    except Exception:
        assert 'fail'
