import logging
import random

from pexpect.pxssh import ExceptionPxssh

from services.maglev_cli.maglevclihandler import MaglevSystemCommandLine as MSCL
import services.maglev_cli.utils as utils

class MaglevClusterCommandLine:
    def __init__(self, nodeinfo: list, *, default_identifier=None, default_timeout=30, use_persistent_connection=True):
        """
        Instantiate an object representing a cluster of maglev appliances.  Add additional appliances to this cluster via `add_node()`.

        Default values set here are used when adding any new nodes.

        :param nodeinfo list:   List of tuples representing node details to add to the cluster (shortcut for `add_node` calls)
                                Use an empty list to start with no nodes.
                                Tuples must be either 5 or 7 items in length, reflecting the arguments to `add_node`

        :kwarg default_identifier str:         (See property docstring below)
        :kwarg default_timeout int:            Maximum time to wait for a response (some commands may use their own default)
        :kwarg use_persistent_connection bool: Whether to maintain a single connection per method call
        """
        self._default_identifier = default_identifier
        self.default_timeout=default_timeout
        self.logger = logging.getLogger(__name__)
        self._nodes = {}
        self._nodeset = set()
        self._service_statuses = {}
        self.use_persistent_connection=use_persistent_connection

        if nodeinfo:
            for nodetuple in nodeinfo:
                if len(nodetuple) == 5:
                    self.add_node(*nodetuple)
                elif len(nodetuple) == 7:
                    required_params = nodetuple[:5]
                    optional_kwargs = {
                        'admin_username': nodetuple[5],
                        'admin_password': nodetuple[6],
                    }
                    self.add_node(*required_params, **optional_kwargs)
                else:
                    msg = 'Tuples must be exactly 5 or 7 items in length.  See `add_node` for argument details.'
                    self.logger.error(msg)
                    raise TypeError(msg)
            self.refresh_nodes()

    @property
    def default_identifier(self):
        """
        Defines the default identifier for what cluster node to access when delegating methods.

        Valid identifiers are either the IP address of a node, the fabric IP address of a node, or the name of a service on a node.
        Node lookups will access the node with that IP, or the node which has that service active.

        Notes:
            - By default, methods will require an 'identifier' keyword argument unless this is set.
            - If this is set to an empty string, it will access a random node
            - If multiple nodes have the service running, it will access the first one it sees (arbitrarily).

        :return: Identifier string
        :rtype:  str
        """
        return self._default_identifier

    @default_identifier.setter
    def default_identifier(self, val):
        msg = 'Setting default identifier to "{}"'.format(val)
        self.logger.debug(msg)
        self._default_identifier = val

    @property
    def nodes(self):
        return [node for node, node_ip, fabric_ip in self._nodeset]

    def add_node(self, node_ip, fabric_ip, username, password, port, *,
                 admin_username='admin', admin_password=None):
        """
        Adds a node to the cluster.

        See maglevclihandler.py for more details.

        :param node_ip str:     IP address of added node
        :param fabric_ip str:   Fabric IP address of added node
        :param username str:    Username to access added node
        :param password str:    Password to use to access added node
        :param port int:        Port to use to access added node

        :kwarg admin_username str:  Administrator username to access added node (default: 'admin')
        :kwarg admin_password str:  Administrator password to use to access added node (default: same as password)
        """
        node = MSCL(node_ip, username, password, port,
                    admin_username=admin_username, admin_password=admin_password,
                    default_timeout=self.default_timeout,
                    use_persistent_connection=self.use_persistent_connection)
        self._nodeset |= set([(node, node_ip, fabric_ip)])

    def identify_node(self, identifier):
        """
        Selects a node from the cluster's registered nodes based on the given identifier.

        See the docstring for 'default_identifier' for info on identifiers.

        Notes:
            - Identifies based on an internal index.  Make sure the index is up-to-date by running `refresh_nodes` first.
            - Chooses a random node if the identifier is empty.
            - Raises an IndexError when given an otherwise bad identifier.

        :param identifier str:  Identifier to use to identify node in cluster.

        :raises: IndexError

        :return: Node associated with the given identifier
        :rtype:  MaglevSystemCommandLine object
        """
        if identifier:
            matchlist = [(id_key, nodes) for id_key, nodes in self._nodes.items() if id_key.startswith(identifier)]
            if len(matchlist) > 1:
                id_keys = [id_key for id_key, nodes in matchlist]
                msg = 'Multiple matches for identifier "{}": {}. Use a more specific identifier.'.format(identifier, id_keys)
                self.logger.error(msg)
                raise IndexError(msg)
            elif len(matchlist) == 1:
                id_key, nodelist = matchlist[0]
                ret = list(nodelist)[0]
                if len(nodelist) > 1:
                    msg = 'Matched nodes to identifier "{}" @ IPs: {}. Selecting randomly.'.format(id_key, [node.node_ip for node in nodelist])
                    self.logger.debug(msg)
                else:
                    msg = 'Matched node to identifier "{}" to node @ IP: {}'.format(id_key, ret.node_ip)
                    self.logger.debug(msg)
            else:
                msg = 'No nodes are indexed to identifier "{}". ' \
                      '(Did you refresh the index with `refresh_nodes`?)'.format(identifier)
                self.logger.error(msg)
                raise IndexError(msg)
        else:
            ret = random.choice(list(self.nodes))
            msg = 'Randomly chose node @ IP: {}'.format(ret.node_ip)
            self.logger.debug(msg)
        return ret

    def refresh_nodes(self):
        """
        Looks up service statuses on one of the registered nodes and indexes them to each other.

        Notes:
        - Node identification relies on this method to associate services to nodes correctly.
        - Rerun this method whenever a command might change service status.
        - Raises exception on connection failure.

        :raises: ExceptionPxssh
        """
        #TODO: know how to get the right nodes?
        # Reset known identifiers
        self._nodes = {}
        self._service_statuses = {}
        for node, node_ip, fabric_ip in self._nodeset:
            self._nodes[node_ip] = node
            self._nodes[fabric_ip] = node
        # Lookup current services status on any node
        maglev_cmd = 'magctl appstack status | tr -s \' \' | cut -d \' \' -f 2,4,8'
        for node in self.nodes:
            try:
                lines = node.send_cmd(maglev_cmd).split('\n')[1:-1]  # Cut the header and trailing newline
                break
            except ExceptionPxssh:
                msg = 'Failed to connect to node @ IP: {}'.format(node.node_ip)
                self.logger.warning(msg)
                node.disconnect()
        else:
            msg = 'Failed to connect to any node.  Check your systems or connection.'
            self.logger.error(msg)
            raise ExceptionPxssh(msg)
        # Update identifiers
        for line in lines:
            service, status, fabric_ip = line.split(' ')
            if status not in self._service_statuses:
                self._service_statuses[status] = set()
            self._service_statuses[status] |= set([service])
            if fabric_ip == '<none>':
                msg = 'Service {} pending node assignment'.format(service)
                self.logger.debug(msg)
            else:
                node = set([self._nodes[fabric_ip]])
                if service not in self._nodes:
                    self._nodes[service] = set()
                self._nodes[service] |= node

    def __getattr__(self, attr):
        def wrapper(*args, identifier=None, **kwargs):
            try:
                if identifier is None:
                    if self.default_identifier is None:
                        # "identifier" is a mandatory argument
                        msg = '{} missing required keyword argument \'identifier\'. ' \
                              'Set \'default_identifier\' property to bypass this. ' \
                              'Use an empty string identifier to access a random node.'
                        msg = msg.format(attr)
                        self.logger.error(msg)
                        raise TypeError(msg)
                    else:
                        identifier = self.default_identifier
                        msg = 'Accessing via default identifier "{}"'.format(identifier)
                        self.logger.debug(msg)
                node = self.identify_node(identifier)
                msg = 'Accessing attribute "{}" of node @ IP: {}'.format(attr, node.node_ip)
                self.logger.debug(msg)
                getresult = getattr(node, attr)
                self.logger.debug(msg)
                if callable(getresult):
                    ret = getresult(*args, **kwargs)
                elif len(args) > 0 or len(kwargs) > 0:
                    msg = 'Too many arguments: "{}" is a property, not a method.'.format(attr)
                    raise TypeError(msg)
                else:
                    ret = getresult
                return ret
            except AttributeError as err:
                self.logger.error(err)
                raise
        return wrapper
