import json
import requests
import os
import sys
import importlib
import time
from pyats.easypy import runtime
import logging
logger = logging.getLogger("ClientManager")
log = logger

class ResponseDict(dict):
    """ Data structure to extend dict attribute access """

    def __init__(self, response):
        """ initialize a dict to ResponseDict

        Args:
            response (dict): dict to convert
        """
        self._response = response
        for k, v in response.items():
            if isinstance(v, dict):
                self[k] = ResponseDict(v)
            else:
                self[k] = v
            if isinstance(v, list):
                val_list = []
                for item in v:
                    if isinstance(item, dict):
                        val_list.append(ResponseDict(item))
                    else:
                        val_list.append(item)
                self[k] = val_list

    def __getattr__(self, name):
        """ extend attribute access

        Args:
            name (str): name of attribute

        Returns:
            object: attribute of response
        """

        return self.get(name)
        
class ClientManager(object):
    """ Client manager to interact with API Clients of various services. """

    TIMEOUT = 60
    AUTHORIZATION_TOKEN = 'X-JWT-ACCESS-TOKEN'

    def __init__(self, server, username, password, base_url, protocol="https", port=None):
        """ Object initializer

        Initializer also authenticates using the credentials, and stores the generated
        authentication ticket/token.

        Args:
            server (str): cluster server name (routable DNS addess or ip)
            username (str): user name to authenticate with
            password (str): password to authenticate with
            base_url (str): default/constant portion of the url
            protocol (str): network protocol - http or https
            port (str): port number

        Raises:
            ApiClientException: when unsupported protocol is passed
        """

        self.log = log

        self.server = server
        self.username = username
        self.password = password

        self.port = str(port)
        if port:
            self.server = self.server + ":" + self.port

        if protocol not in ["http", "https"]:
            self.log.error("Not supported protocol {}.".format(protocol))
            raise BaseException("Not supported protocol {}.".format(protocol))

        self.base_url = "{}://{}{}".format(protocol, self.server, base_url)
        self.server_url = "{}://{}".format(protocol, self.server)

        self._default_headers = {}
        self._common_headers = {}

    def initialize_loggers(self):
        self.unique_calls_path = '{0}/{1}'.format(runtime.directory, self.unique_calls_fname)
        self.unique_calls_logger = logging.getLogger('unique_ext_calls')
        self.unique_calls_logger.propagate = False
        self.unique_calls_logger.setLevel(logging.DEBUG)
        if not self.unique_calls_logger.hasHandlers():
            fh = logging.FileHandler(self.unique_calls_path)
            fh.setLevel(logging.DEBUG)
            self.unique_calls_logger.addHandler(fh)

        self.all_calls_path = '{0}/{1}'.format(runtime.directory, self.all_calls_fname)
        self.all_calls_logger = logging.getLogger('all_ext_calls')
        self.all_calls_logger.propagate = False
        self.all_calls_logger.setLevel(logging.DEBUG)
        if not self.all_calls_logger.hasHandlers():
            fh = logging.FileHandler(self.all_calls_path)
            fh.setLevel(logging.DEBUG)
            self.all_calls_logger.addHandler(fh)

    def __repr__(self):
        """ Overrides the default object representation to display the object attributes. """

        return "[API Client: <server:{}> <username:{}> <password:{}>]".format(self.server,
                                                                              self.username,
                                                                              self.password)

    def add_api(self, name, obj):
        """ Add an api client to client manager.

        Args:
            name (str): name you want to set to the api client, has to follow python variable naming
                        rule.
            obj (object): api client which actually calling call_api method.
        """

        setattr(self, name, obj)

    def connect(self, force=None):
        """ Generates a new ticket/token.

        Args:
            force (bool): If true, forces a new connection, else authenticates the existing one
        """

        self.log.info("Connecting to the API client.")
        self.authenticate(force=force)

    def disconnect(self):
        """ Disconnect from API client"""

        self.log.info("Disconnecting from the API client.")

    def authenticate(self):
        """ Generates a new authentication ticket or token. """

        raise NotImplementedError

    @property
    def default_headers(self):
        return self._default_headers

    @default_headers.setter
    def default_headers(self, headers):
        """ Set default headers of client.

        Args:
            headers (dict): headers to set.
        """

        self._default_headers.update(headers)

    @property
    def common_headers(self):
        return self._common_headers

    @common_headers.setter
    def common_headers(self, headers):
        """ Set common headers of client.

        Args:
            headers (dict): headers to set.
        """

        self._common_headers.update(headers)

    def call_api(self,
                 method,
                 resource_path,
                 raise_exception=True,
                 response_dict=True,
                 port=None,
                 protocol=None,
                 **kwargs):
        """ Handles the requests and response.

        Args:
            method (str): type of request.
            resource_path (str): URL in the request object.
            raise_exception (boolean): If True, http exceptions will be raised.
            response_dict (boolean): If True, response dict is returned, else response object
            port (int): port value
            protocol (str): indicates whether protocol is http or https
            kwargs (dict):
                url (optional): URL for the new Request object.
                params (optional): Dictionary or bytes to be sent in query string for the Request.
                data (optional): Dictionary, bytes, or file-like object to send in the body of the
                                 Request.
                json (optional): json data to send in the body of the Request.
                headers (optional): Dictionary of HTTP Headers to send with the Request.
                cookies (optional): Dict or CookieJar object to send with the Request.
                files (optional): Dictionary of 'name': file-like-objects
                                  (or {'name': ('filename', fileobj)}) for multipart encoding upload
                auth (optional): Auth tuple to enable Basic/Digest/Custom HTTP Auth.
                timeout (float or tuple) (optional): How long to wait for the server to send data
                                                     before giving up, as a float, or a (connect
                                                     timeout, read timeout) tuple.
                allow_redirects (bool) (optional): Boolean. Set to True if POST/PUT/DELETE redirect
                                                   following is allowed.
                proxies (optional): Dictionary mapping protocol to the URL of the proxy.
                verify (optional): if True, the SSL cert will be verified. A CA_BUNDLE path can also
                                   be provided.
                stream (optional): if False, the response content will be immediately downloaded.
                cert (optional): if String, path to ssl client cert file (.pem). If Tuple,
                                 (‘cert’, ‘key’) pair
        Returns:
            object: response as a dict if response_dict is False
            dict: response as a dict if response_dict is True

        Raises:
            e: requests.exceptions.HTTPError, when HTTP error occurs
        """

        resource_path = requests.utils.quote(resource_path)

        if port:
            if self.port in self.base_url:
                base_url = self.base_url.replace(self.port, port)
                server_url = self.server_url.replace(self.port, port)
            else:
                base_url = self.base_url + ":{}".format(port)
                server_url = self.server_url + ":{}".format(port)
            if "full_path" in kwargs :
                kwargs.pop("full_path" )
                url = server_url + resource_path
            elif resource_path.find("/dna/intent/api/v") != -1 or resource_path.find("/dna/api/v") != -1 or resource_path.find("/dna/data/api/v") != -1 or\
                resource_path.find("/api/system/") != -1 or resource_path.find("/api/dnacaap/v") != -1 or resource_path.find("/api/sys-ops/v") != -1:
                url = server_url + resource_path
            else:
                url = base_url + resource_path
        else:
            if "full_path" in kwargs:
                kwargs.pop("full_path" )
                url = self.server_url + resource_path
            elif resource_path.find("/dna/intent/api/v") != -1 or resource_path.find("/dna/api/v") != -1 or resource_path.find("/dna/data/api/v") != -1 or\
                resource_path.find("/api/system/") != -1 or resource_path.find("/api/dnacaap/v") != -1 or resource_path.find("/api/sys-ops/v") != -1:
                url = self.server_url + resource_path
            else:
                url = self.base_url + resource_path
        self.log.info("Resource path full url: {}".format(url))
        if protocol:
            if protocol == "http" and "https:" in url:
                url = url.replace("https:", "http:")

            if protocol == "https" and "http:" in url:
                url = url.replace("http:", "https:")

        if "/api/v1/v2/" in url:
            url = url.replace("/api/v1/v2/", "/api/v2/")

        if "headers" in kwargs:
            headers = kwargs.pop("headers")
        else:
            headers = self.default_headers

        if not kwargs.get("timeout"):
            kwargs["timeout"] = ClientManager.TIMEOUT

        headers.update(self.common_headers)

        if "verify" in kwargs:
            verify = kwargs.pop("verify")
        else:
            verify = False
            requests.packages.urllib3.disable_warnings()

        self.log.debug("Request:\nmethod:\n{}\nurl: {}\nheaders: {}\nParameters: {}"
                       .format(method, url, headers, kwargs))
        response = requests.request(method, url, headers=headers, verify=verify, **kwargs)

        time_taken = response.elapsed.seconds + response.elapsed.microseconds / 1e6
        self.log.debug("API Response:\nurl: {}\nmethod: {}\ntime taken in seconds: {}\ntext: {}"
                       .format(url, method, format(time_taken, '.2f'), response.text))

        if hasattr(response, 'headers'):
            if response.headers and 'set-cookie' in response.headers:
                self.log.debug("Response has set-cookie: {}".format(response.headers['set-cookie']))
                if ClientManager.AUTHORIZATION_TOKEN in response.headers['set-cookie']:
                    self.log.debug("Response cookie has {}. Update cookie: {}".format(
                        ClientManager.AUTHORIZATION_TOKEN, response.headers['set-cookie']))
                    self.common_headers["Cookie"] = response.headers['set-cookie']

        if raise_exception:
            try:
                response.raise_for_status()
            except requests.exceptions.HTTPError as e:
                self.log.exception("Error Code: {} URL:{} Data:{} Headers:{} Message:{}"
                                   .format(e.response.status_code, url, kwargs, headers,
                                           e.response.text))
                raise e

        if response_dict:
            if response.text:
                return json.loads(response.text)
            else:
                return response
        else:
            return response

class ApicemClientManager(ClientManager):
    """ Client manager to interact with API Client. """

    MAGLEV_TIMEOUT = 30 # As requested by Maglev team via Olaf

    FORTY_FIVE_MIN = 600
    SIXTY_MIN = 900

    def __init__(self, server, username, password, version="v1",base_url = "/api", connect=True, maglev=False, api_logger=False):
        """ Object initializer.

        Initializer also aunthenticates using the credentials, and stores the generated
        authentication ticket.

        Args:
            server (str): cluster server name (routable DNS address or ip)
            username (str): user name to authenticate with
            password (str): password to authenticate with
            version (str): version of the API to be used
            connect (bool): flag to authenticate and establish swagger client
            maglev (bool): flag to call the maglev authenticate
        """

        #base_url = base_url
        protocol = "https"
        self.version = version
        super().__init__(
            server,
            username,
            password,
            base_url,
            protocol=protocol)

        self.default_headers = {"Content-Type": "application/json"}
        self.__connected = False
        self._is_maglev = maglev
        self.cas_ticket = None
        self.all_calls_fname = 'ext_api_log.log'
        self.unique_calls_fname = 'unique_ext_calls_log.log'
        self._maglev_token_time = ""
        self.api_logger = api_logger
        if self.api_logger:
            self.initialize_loggers()
        if connect:
            self.connect()
        self.setup_api()

    def setup_api(self):
        """ Creates the APIC-EM apis.

        For example:
            self.backup is an instance of BackupApi.
            self.capacity_manager is an instance of CapacityManagerApi
        Note:
            self.log is the instance of LogApi
        """

        self.log.debug("Initializing the APIC-EM APIs.")

    def connect(self, force=False):
        """ Generates a new ticket and establishes a fresh swagger client.

        Args:
            force (bool): If true, forces a new connection, else authenticates the existing one
        """

        if force:
            self.__connected = False

        self.log.info("Connecting to the Apic-em northbound API client.")
        if not self._is_maglev:
            self._authenticate()
        else:
            self._maglev_authenticate()
            self._maglev_token_time = int(time.time())
            self.log.debug("Initial Maglev login time: '{}'.".format(self._maglev_token_time))

    def disconnect(self):
        """ Deletes the generated ticket and effectively disconnecting the user. """

        try:
            self.log.info("Disconnecting the Apic-em northbound API client.")
            if not self._is_maglev:
                self.common_headers.pop("X-Auth-Token")
                self.common_headers.pop("X-CSRF-Token")
            else:
                self.common_headers.pop("Cookie")
        except KeyError:
            self.log.info("Already disconnected from Northbound API client.")
        self.__connected = False

    def call_api(self, method, resource_path, **kwargs):
        """ Wrapper of call_api to encode post data.

        Args:
            resource_path (str): resource_path
            method (str): http method, support "GET", "POST", "PUT", "DELETE"
            kwargs (dict):
                url (optional): URL for the new Request object.
                params (optional): Dictionary or bytes to be sent in query string for the Request.
                data (optional): Dictionary, bytes, or file-like object to send in the body of the
                                 Request.
                json (optional): json data to send in the body of the Request.
                headers (optional): Dictionary of HTTP Headers to send with the Request.
                cookies (optional): Dict or CookieJar object to send with the Request.
                files (optional): Dictionary of 'name': file-like-objects
                                  (or {'name': ('filename', fileobj)}) for multipart encoding upload
                auth (optional): Auth tuple to enable Basic/Digest/Custom HTTP Auth.
                timeout (float or tuple) (optional): How long to wait for the server to send data
                                                     before giving up, as a float, or a (connect
                                                     timeout, read timeout) tuple.
                allow_redirects (bool) (optional): Boolean. Set to True if POST/PUT/DELETE redirect
                                                   following is allowed.
                proxies (optional): Dictionary mapping protocol to the URL of the proxy.
                verify (optional): if True, the SSL cert will be verified. A CA_BUNDLE path can also
                                   be provided.
                stream (optional): if False, the response content will be immediately downloaded.
                cert (optional): if String, path to ssl client cert file (.pem). If Tuple,
                                 (‘cert’, ‘key’) pair

        Returns:
            dict: response of request.
        """
        if resource_path.find("/dna/intent/api/v") != -1 or resource_path.find("/api/v") != -1 or\
            resource_path.find("/api/system/") != -1 or resource_path.find("/api/dnacaap/v") != -1 or resource_path.find("/api/sys-ops/v") != -1:
            copyargs = {'method': method, 'URL': "{}{}".format(self.base_url, resource_path)}
        else:
            copyargs = {'method': method, 'URL': "{}{}".format(self.server, resource_path)}
        copyargs.update(kwargs)
        if self.__connected and self._is_maglev:
            self.log.debug("Checking the validity of the Maglev cookie.")
            self._handle_maglev_idle_timeout()

        headers = self.default_headers.copy()
        #TODO (mingyazh): remove trailing back slash of resource path in client

        if self._is_maglev:
            if not kwargs.get("timeout"):
               timeout = ApicemClientManager.MAGLEV_TIMEOUT
            else:
               timeout = kwargs.get("timeout")
               kwargs.pop("timeout")
        else:
            timeout = None

        if "headers" in kwargs:
            headers.update(kwargs.pop("headers"))
        resource_path = resource_path.rstrip('\/')

        if "data" in kwargs and "files" not in kwargs:
            if isinstance(kwargs["data"], dict):
                kwargs["data"] = json.dumps(kwargs["data"])
                if "encode" in kwargs:
                    kwargs["data"] = kwargs["data"].encode(kwargs.pop("encode"))
            if isinstance(kwargs["data"], list):
                kwargs["data"] = json.dumps(kwargs["data"]).encode("utf-8")
        if "files" in kwargs:
            if kwargs["files"]:
                if isinstance(kwargs["files"], dict):
                    fd = kwargs["files"]
                    if len(fd) == 1 and isinstance(list(fd.values())[0], tuple):
                        ft = fd[list(fd.keys())[0]]
                        fd[list(fd.keys())[0]] = ft[:1] + (open(ft[1], "rb"), ) + ft[2:]
                    else:
                        kwargs["files"] = {key:open(val, "rb") for key, val in fd.items()}

                if isinstance(kwargs["files"], str):
                    kwargs["files"] = open(kwargs["files"], "rb")

                if headers.get("Content-Type") == "application/json":
                    headers.pop("Content-Type")
            else:
                #TODO (mingyazh): deal with header parameters in client
                kwargs.pop("files")
                headers["Content-Type"] = "multipart/form-data"

        if method == "GET":
            if (headers.get('Content-Type') == 'multipart/form-data'
                    or headers.get('Accept') == 'application/octet-stream'
                    or headers.get('Content-Type') == 'application/octet-stream'):
                return super(ApicemClientManager, self).call_api(method=method,
                                                                 resource_path=resource_path,
                                                                 headers=headers,
                                                                 timeout=timeout,
                                                                 response_dict=False)
        if "dna" in kwargs:
            del kwargs['dna']

        response = super(ApicemClientManager, self).call_api(method=method,
                                                             resource_path=resource_path,
                                                             headers=headers,
                                                             timeout=timeout,
                                                             **kwargs)
        if self.api_logger:
            self.log_all_calls(response, copyargs)
            self.log_unique_calls(copyargs)

        if isinstance(response, dict):
            return ResponseDict(response)

        if isinstance(response, list):
            response_list = []
            for item in response:
                if isinstance(item, dict):
                    response_list.append(ResponseDict(item))
                else:
                    response_list.append(item)
            return response_list

        return response

    def log_all_calls(self, response, kwargs):
        self.all_calls_logger.debug(kwargs)

    def log_unique_calls(self, kwargs):
        found = False
        fpath = self.unique_calls_path

        if not os.path.isfile(fpath):
            p = open(fpath, 'w')
            p.close()
        with open(fpath, 'r') as funique:
            for line in funique:
                if str(line).find(str(kwargs)) != -1:
                    found = True
        if not found:
            self.unique_calls_logger.debug(str(kwargs))

    def _authenticate(self):
        """ Generates a new authentication cas_ticket. """

        if not self.__connected:
            resource_path = "/api/system/" + self.version + "/auth/token"
            data = json.dumps({"username": self.username, "password": self.password})
            response = self.call_api("POST",
                                     resource_path,
                                     auth=(self.username, self.password),
                                     raise_exception=True,
                                     response_dict=False,verify=False,full_path=True)
            result_json = json.loads(response.text)
            if 'Token' in result_json.keys():
                token = result_json["Token"]
            else:
                # If ticket is not generated for a user, don't want to proceed
                raise Exception("Cannot create NB client for an unauthorized user {}"
                                .format(self.username))
            headers = {"X-Auth-Token": token}
            self.common_headers = headers
            self.cas_ticket = token
            self.__connected = True
        else:
            self.log.info("Already connected to Northbound API client.")
    def _maglev_authenticate(self):
        """ Generates a new authentication cookie for Maglev. """
        self._authenticate()
        '''
        Common Auth
        '''
    def add_new_apis(self, client_path):
        """ Add new clients to ApicemClientManager.

        Args:
            client_path (str): path to new clients, inside it should contain python modules for
            clients

        Notes:
            If there is api file having the same filename and classname as in default api client
            folder, it will override the default one.
        """

        client_path = os.path.expanduser(client_path)
        if not os.path.isdir(client_path):
            self.log.error("{} is not a valid directory.".format(client_path))
            raise Exception("{} is not a valid directory.".format(client_path))
        sys.path.append(client_path)

        for file in os.listdir(client_path):
            if file.endswith("api.py"):
                client_name = file.replace(".py", "")
                client_module = importlib.import_module(client_name)
                for obj in dir(client_module):
                    if (not obj.startswith("__") and issubclass(getattr(client_module, obj), Apicem)
                        and not issubclass(Apicem, getattr(client_module, obj))):
                        client_instance = getattr(client_module, obj)(self)
                        setattr(self, client_name, client_instance)

    def _handle_maglev_idle_timeout(self):
        """ Handles the timeout for the maglev login """

        elapsed_time = int(time.time()) - self._maglev_token_time
        self.log.debug("Initial login: '{}', Elapsed time: '{}'.".format(self._maglev_token_time,
                                                                         elapsed_time))

        if ApicemClientManager.FORTY_FIVE_MIN <= elapsed_time < ApicemClientManager.SIXTY_MIN:
            self.log.debug("Cookie Age: '{}'. Cookie will be renewed.".format(elapsed_time))
            self._maglev_token_time = int(time.time())
            self.__connected = False
            self._maglev_authenticate()
            self.log.debug("New login time: '{}'".format(self._maglev_token_time))

        elif elapsed_time >= ApicemClientManager.SIXTY_MIN:
            self.log.debug("Cookie Age: '{}'. Re-authentication will be initiated".format(elapsed_time))
            self.__connected = False
            self._maglev_authenticate()
            self._maglev_token_time = int(time.time())
            self.log.debug("New login time: '{}'".format(self._maglev_token_time))

        else:
            self.log.debug("Cookie age: '{}'. It is still valid.".format(elapsed_time))

