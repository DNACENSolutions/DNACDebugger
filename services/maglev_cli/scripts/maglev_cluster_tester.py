import logging
import time
from pprint import pprint as pp
from ..maglevclusterhandler import MaglevClusterCommandLine as MCCL

if __name__ == '__main__':
    logger_handler = logging.FileHandler('./' + time.strftime('%Y%m%d-%H%M%S.mccl.log'))
    logger_formatter = logging.Formatter('@MSCL: %(asctime)s [%(levelname)s] %(message)s')
    logger_handler.setFormatter(logger_formatter)
    logger = logging.getLogger('maglevclihandler')
    logger.addHandler(logger_handler)
    logger.setLevel(logging.DEBUG)

    # '172.21.236.15'
    systems = {
        'maglev': (
            '10.195.144.142',
            '10.195.144.142',
            'maglev',
            'Maglev123',
            2222,
            'admin',
            'Maglev123',
        ),
        'c1': (
            '172.21.236.15',
            '50.41.41.1',
            'maglev',
            'Maglev123',
            2222,
            'admin',
            'Maglev123',
        ),
        'c2': (
            '172.21.236.16',
            '50.41.41.2',
            'maglev',
            'Maglev123',
            2222,
            'admin',
            'Maglev123',
        ),
        'c3': (
            '172.21.236.17',
            '50.41.41.3',
            'maglev',
            'Maglev123',
            2222,
            'admin',
            'Maglev123',
        ),
    }
    nodes = [systems[key] for key in ['c1', 'c2', 'c3']]
    #nodes = [systems[key] for key in ['maglev']]
    mccl = MCCL(nodes, use_persistent_connection=True)

    print('yeh')
