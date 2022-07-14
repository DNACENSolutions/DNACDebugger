import logging
import os
import os.path
import pprint
import re
import shutil
import subprocess
import time

from pexpect import pxssh
from pexpect import EOF as PexpectEof
from pexpect import TIMEOUT as PexpectTimeout
import paramiko 
from scp import SCPClient
import services.maglev_cli.utils as utils


class MaglevSystemCommandLine:
    """
    Hello world!
    """
    def __init__(self, node_ip, username, password, port, *,
                 admin_username='admin', admin_password=None,
                 default_timeout=30, use_persistent_connection=True, key=None):
        """
        Instantiates access details for the node.

        Notes:
            - If 'admin_password' is None, it defaults to using the user password.
            - By default, will open and close a connection for each method call.
              Set 'use_persistent_connection' to override this behavior.
            - Most methods utilize 'default_timeout' as the maximum timeout for response.
              However, some methods define their own (they will define a 'timeout' keyword arg).

        :param node_ip str:     IP address of added node
        :param username str:    Username to access added node
        :param password str:    Password to use to access added node
        :param port int:        Port to use to access added node

        :kwarg admin_username str:  Administrator username to access added node (default: 'admin')
        :kwarg admin_password str:  Administrator password to use to access added node (default: same as password)
        :kwarg default_timeout int: Maximum time to wait for a response (some commands may use their own default)
        :kwarg use_persistent_connection bool: Whether to maintain a single connection per method call
        """
        self.logger = logging.getLogger(__name__)
        self.logger.info('Log started.')
        self.node_ip = node_ip
        self.username = username
        self.password = password
        self.admin_username = admin_username
        self.key = key
        if admin_password is None:
            self.admin_password = password
        else:
            self.admin_password = admin_password
        self.port = port
        utils.log_kwargs(
            self.logger,
            'Configuring MSCL with login details:',
            {'Node IP': node_ip, 'Port': port},
            {'Username': username, 'Password': password},
            {'Admin Username': admin_username, 'Admin Password': self.admin_password},
        )

        self._default_prompt = '\n[#$]'
        self._default_timeout = default_timeout
        options = {
            'StrictHostKeyChecking':    'no',
            'UserKnownHostsFile':       '/dev/null',
        }
        self.ssh = pxssh.pxssh(timeout=default_timeout, options=options)
        if use_persistent_connection:
            self.logger.info('Using persistent connection.')
        self.persistent = use_persistent_connection

        self.logger.debug('MaglevSystemCommandLine object @ IP %s instantiated successfully.', node_ip)

    def __del__(self):
        if self.is_connected:
            self.disconnect()

    def __enter__(self):
        self.logger.debug('Entering context loop.')
        if not self.persistent:
            self.logger.debug('Using persistent connection for context loops.')
            self.persistent = True
        if not self.is_connected:
            self.connect()
        return self

    def __exit__(self, *_):
        self.logger.debug('Exiting context loop.')
        if self.is_connected:
            self.disconnect()

    @property
    def is_connected(self):
        """
        :return:    Whether the ssh connection is live
        :rtype:     bool
        """
        return not self.ssh.closed

    #####
    ##### Internal class methods
    #####

    def connect(self):
        """
        Class method for opening an ssh connection.

        :return:    None
        """
        if self.is_connected:
            self.logger.warning('Attempted to connect when session is already connected.')
            return

        args = (self.node_ip, self.username, self.password)
        kwargs = {
            'auto_prompt_reset':    False,
            'check_local_ip':       True,
            'login_timeout':        self._default_timeout,
            'original_prompt':      self._default_prompt,
            'port':                 self.port,
            'quiet':                True,
            'ssh_key':              self.key,
            'sync_multiplier':      1,
            'terminal_type':        'ansi',
        }
        self.logger.info(args)
        utils.log_kwargs(
            self.logger,
            'Opening ssh connection:',
            {'Node IP': self.node_ip, 'Username': self.username, 'Password': self.password},
            kwargs,
        )

        try:
            if not self.ssh.login(*args, **kwargs):
                self.logger.error("Login failed.")
            else:
                self.logger.info("Received login response:")
                self.logger.info(self.get_ssh_last_response(trim=False))
                self.logger.info("Successfully connected to cluster.")
                self.logger.info("Trying to connect  to bash shell:")
                #Temperory fix untill the full secure shell feature is available in DNAC.
                cmd = "_shell"
                expect = "$:"
                self.logger.info('Sending line: `%s`\n', cmd)
                if expect is not None:
                    self.logger.debug('Expecting following prompt: %s', expect)
                self.ssh.sendline(cmd)
                time.sleep(1)
                self.ssh.sendline(self.password)
                self.ssh.set_unique_prompt()
                self.logger.info(self.get_ssh_last_response(trim=False))
                
                self.logger.info("Successfully connected to cluster unsecure bash shell.")
        except Exception as err:
            msg = 'Encountered error on login.  Check login details or try again.  Error details:\n'
            msg += str(err)
            self.logger.error(msg)
            raise

        self.logger.info('Connection opened.')

    def connect_redis(self):
        """
        Class method for redis shell connection.
        :return:    None
        """
        if not self.is_connected:
            self.connect()
        try:
            self.logger.info("Received login response:")
            self.logger.info(self.get_ssh_last_response(trim=False))
            self.logger.info("Successfully connected to cluster.")
            self.logger.info("Trying to connect  to bash shell:")
            cmd = "magctl service attach -D redis"
            expect = "$:"
            self.logger.info('Sending line: `%s`\n', cmd)
            if expect is not None:
                self.logger.debug('Expecting following prompt: %s', expect)
            self.ssh.sendline(cmd)
            time.sleep(1)
            self.ssh.set_unique_prompt()
            self.logger.info(self.get_ssh_last_response(trim=False))
            self.logger.info("Successfully connected to redis bash shell.")
        except Exception as err:
            msg = 'Encountered error on login.  Check login details or try again.  Error details:\n'
            msg += str(err)
            self.logger.error(msg)
            raise
        self.logger.info('Connection opened.')

    def copy_file_to_dnac(self, filepath, dstpath=""):
        """
        Method to copy files to DNAC

        :return:    None
        """

        args = (self.node_ip, self.port,self.username, self.password)
        self.logger.info(args)
        try:
            ssh = paramiko.SSHClient()
            # ssh.load_system_host_keys()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.logger.info(args)
            ssh.connect(*args)
            with SCPClient(ssh.get_transport()) as scp:
                scp.put(filepath, dstpath)
        except Exception as err:
            msg = 'Encountered error while copying file to dnac:\n'
            msg += str(err)
            self.logger.error(msg)
            raise

        self.logger.info('File copied to DNAC')

    def copy_rca_from_dnac(self, filepath, dstpath="./"):
        """
        Method to copy files from DNAC

        :return:    None
        """
        args = (self.node_ip, self.port,self.username, self.password)
        self.logger.info(args)
        try:
            ssh = paramiko.SSHClient()
            # ssh.load_system_host_keys()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.logger.info(args)
            ssh.connect(*args)
            with SCPClient(ssh.get_transport()) as scp:
                scp.get(filepath, dstpath)
        except Exception as err:
            msg = 'Encountered error while copying file to dnac:\n'
            msg += str(err)
            self.logger.error(msg)
            raise

        self.logger.info('File copied to DNAC')

    def disconnect(self, *, try_interrupt=True):
        """
        Class method for closing an ssh connection.

        :return:    None
        """
        self.logger.debug('Disconnecting session...')
        if try_interrupt and self.is_connected:
            try:
                self.logger.debug('Attempting interrupt on session...')
                self.ssh.sendcontrol('c')
                self.ssh.prompt()
                self.ssh.sendline("exit")
                self.ssh.logout()
                self.logger.debug('Interrupt succeeded.')
            except PexpectEof:
                self.logger.debug('Connection broken.')
        self.ssh.close()
        self.logger.info('Session closed.')
        self.ssh = pxssh.pxssh(timeout=self._default_timeout)
        self.logger.debug('Ssh handler reset.')

    def get_ssh_last_response(self, *, clean=True, trim=True):
        """
        Class method for returning the last response from the ssh connection.
        Converts the output to unicode and removes the input line.

        :kwarg bool clean: Whether to remove bash control characters and carriage returns
        :kwarg bool trim: Whether to trim the first line of output

        :return:    Last response
        :rtype:     str
        """
        if self.ssh.after is None:
            return ''
        output = self.ssh.before.decode('utf-8')
        if clean:
            output = utils.clean(output)
        if trim:
            match = re.search(r'\n', output)
            if match is not None:
                output = output[match.start()+1:]
        return output

    def _poll(self, cmd, pass_pattern, interval, timeout):
        utils.log_kwargs(
            self.logger,
            'Polling result of command `{}` until parsing passing output:'.format(cmd),
            {'pass pattern': pass_pattern, 'interval': interval, 'timeout': timeout},
        )
        time_start = time.time()
        while time.time() - time_start < timeout:
            try:
                cmd_interval_start = time.time()
                self._send(cmd, timeout=interval)
                cmd_interval = cmd_interval_start - time.time()
                out = self.get_ssh_last_response()
                match = re.search(pass_pattern, out)
                if match is not None:
                    msg = 'Poll succeeded after {} seconds.'.format(time.time() - time_start)
                    self.logger.debug(msg)
                    break
                time.sleep(interval - cmd_interval)
            except PexpectTimeout:
                self.logger.debug('Hit command timeout on interval - sending interrupt')
                self.ssh.sendcontrol('c')
                self.ssh.prompt()
        else:
            raise PexpectTimeout('Poll timeout exceeded.')

    def _ping(self, interval, timeout):
        utils.log_kwargs(
            self.logger,
            'Pinging system {}:'.format(self.node_ip),
            {'interval': interval, 'timeout': timeout},
        )
        ping_cmd = ['ping', '-c 1', self.node_ip]
        time_start = time.time()
        while time.time() - time_start < timeout:
            time.sleep(interval)
            ping_process = subprocess.Popen(ping_cmd, stdout=subprocess.PIPE)
            ping_process.communicate()
            if ping_process.returncode == 0:
                msg = 'System is live after {} seconds'.format(time.time() - time_start)
                self.logger.debug(msg)
                break
        else:
            raise PexpectTimeout('Ping timeout exceeded.')

    def _send(self, cmd, *, auto_auth=True, interrupt=False, expect=None, timeout=None):
        """
        Class method for sending a message through an open ssh connection.

        :param str cmd:           Message to send
        :kwarg bool auto_auth:    Automatically detect and handle authentication queries.
        :kwarg bool interrupt:    Interrupts the current ssh session (waits timeout seconds).
        :kwarg str expect:        Expected prompt after send.  Uses default if None.
        :kwarg int timeout:       Maximum wait time for prompt.  Uses default if None.

        :return:    String output of the command
        :rtype:     str

        :raises pxssh.ExceptionPxssh:   Attempted to send a command without connecting first.
        :raises PexpectEof:             Encountered an EOF while communicating with maglev.
        :raises PexpectTimeout:         Timed out while expecting a response from maglev.
        """
        if not self.is_connected:
            msg = 'Send command requires an open connection.'
            self.logger.error(msg)
            raise pxssh.ExceptionPxssh(msg)

        if timeout is None:
            timeout = self._default_timeout

        self.logger.info('Sending line: `%s`\n', cmd)
        self.logger.debug('Command timeout: %s', timeout)
        if expect is not None:
            self.logger.debug('Expecting following prompt: %s', expect)

        self.ssh.sendline(cmd)

        expect_list = [PexpectTimeout, PexpectEof]
        if expect is None:
            expect_list.append(self.ssh.PROMPT)
        else:
            expect_list.append(expect)

        if auto_auth:
            # Add authentication prompts to the expect list
            prompt_sudo_pw = r'\[sudo\] password for \w+:'
            expect_list.append(prompt_sudo_pw)
            prompt_admin_user = r'\[administration\] username for \'[0-9a-zA-Z.:/-]+\':'
            expect_list.append(prompt_admin_user)
            prompt_admin_pw = r'\[administration\] password for \'\w+\':'
            expect_list.append(prompt_admin_pw)
            prompt_shell_pw = r'Password:'
            expect_list.append(prompt_shell_pw)
        try:
            while True:
                index = self.ssh.expect(expect_list, timeout=timeout)
                if index == 0:
                    # Timeout case
                    try:
                        self.logger.info('Parsed timeout: sending interrupt.')
                        self.ssh.sendcontrol('c')
                        self.ssh.prompt()
                    except Exception as err:
                        self.logger.error('Exception on interrupt.')
                        self.logger.error(err)
                    raise PexpectTimeout('Timeout exceeded.')
                elif index == 1:
                    # EOF case (connection is closed)
                    eof_msg = 'EOF received - connection is closed.  Cleaning up session.'
                    self.logger.error(eof_msg)
                    self.disconnect(try_interrupt=False)
                    raise PexpectEof(eof_msg)
                elif index == 2:
                    # Expected prompt reached
                    break
                elif index == 3:
                    # sudo password prompt
                    #TODO: do we need a specific sudo password?
                    cmd = self.password
                    self.logger.info('Encountered sudo password prompt with auto-auth')
                    self.logger.info('Context:\n%s', self.get_ssh_last_response())
                    self.logger.info('Automatically sending line: `%s`', cmd)
                    self.ssh.sendline(cmd)
                elif index == 4:
                    # admin username prompt
                    cmd = self.admin_username
                    self.logger.info('Encountered admin username prompt with auto-auth')
                    self.logger.info('Context:\n%s', self.get_ssh_last_response())
                    self.logger.info('Automatically sending line: `%s`', cmd)
                    self.ssh.sendline(cmd)
                elif index == 5:
                    # admin password prompt
                    cmd = self.admin_password
                    self.logger.info('Encountered admin password prompt with auto-auth')
                    self.logger.info('Context:\n%s', self.get_ssh_last_response())
                    self.logger.info('Automatically sending line: `%s`', cmd)
                    self.ssh.sendline(cmd)
                elif index == 6:
                    # admin password prompt
                    cmd = self.admin_password
                    self.logger.info('Encountered Secure shell prompt for password')
                    self.logger.info('Context:\n%s', self.get_ssh_last_response())
                    self.logger.info('Automatically sending line: `%s`', cmd)
                    self.ssh.sendline(cmd)
        except PexpectTimeout:
            if interrupt:
                pass
            else:
                raise
        finally:
            if interrupt:
                self.logger.debug('Connection interruption indicated.  Closing session.')
                self.disconnect(try_interrupt=False)
        time.sleep(2)
        output = self.get_ssh_last_response()
        self.logger.info(u'Response received:\n%s', output)
        self.logger.info('Send complete')
        return output

    #####
    ##### Convenience Methods
    #####

    @utils.encapsulate
    def send_cmd(self, cmd, *, timeout=None):
        """
        Sends a generic command and returns the result.
        This method is essentially a handle to the internal _send method.

        :param str cmd:         Message to send
        :kwarg int timeout:   Maximum wait time for prompt.  Uses default if None.

        :return:    String output of the command
        :rtype:     str
        """
        return self._send(cmd, timeout=timeout)

    @utils.encapsulate
    def list_all(self):
        """
        Sends an `ls -a` command, and parses the result.

        :return:    `ls -a` output, as a list of strings
        :rtype:     list
        """
        return re.findall(r'[a-zA-Z._]+', self._send('ls -a'))

    @utils.encapsulate
    def get_disk_usage(self, *, alert=False, alert_threshold=90):
        out = self._send('df -h')
        pattern = r'([-0-9a-zA-Z/_:.]+)\s+([0-9.]+\w|0)\s+([0-9.]+\w|0)\s+([0-9.]+\w|0)\s+(\d+%)\s+(.*)'
        if alert:
            def alert_cond(grp, fs, size, used, avail, use_pcnt, mntpt):
                grp[fs] = '{} used of {}: {}'.format(used, size, use_pcnt)
                return int(use_pcnt[:-1]) > alert_threshold
            alert_msg = 'Filesystem(s) with high usage detected (threshold: {}):'.format(alert_threshold)
            return utils.parse_by_line_and_alert(self.logger, pattern, out, alert_cond=alert_cond, alert_msg=alert_msg)
        else:
            return utils.parse_by_line_and_alert(self.logger, pattern, out)

    @utils.encapsulate
    def get_system_load(self, *, alert=False, alert_threshold=88):
        out = self._send('w')
        pattern = r'.*load average: ([0-9.]+), ([0-9.]+), ([0-9.]+)'
        if alert:
            def alert_cond(grp, one_min, five_min, fifteen_min):
                grp['01 Minute Average'] = one_min
                grp['05 Minute Average'] = five_min
                grp['15 Minute Average'] = fifteen_min
                return any(map(lambda x: float(x) > alert_threshold, [one_min, five_min, fifteen_min]))
            alert_msg = 'High system load detected (threshold: {}):'.format(alert_threshold)
            return utils.parse_by_line_and_alert(self.logger, pattern, out, alert_cond=alert_cond, alert_msg=alert_msg)
        else:
            return utils.parse_by_line_and_alert(self.logger, pattern, out)

    @utils.encapsulate
    def get_maglev_package_status(self, *, alert=False, timeout=300):
        """
        Sends a `maglev package status` command and parses the output.

        If the 'alert' keyword is True, it will also output warnings for any package which is not in the state
        'Deployed'.

        Notes:
            Outputs a list of tuples representing each package:
            (Package Name, Package Display Name, Deployed Version, Available Version, Status)

        :return:    List of 5-tuples (see notes)
        :rtype:     list
        """
        cmd = 'maglev package status'
        try:
            out = self._send(cmd, timeout=timeout)
            pattern = r'([a-z-]+)\s+(.*\w)\s+([0-9.]+|-)\s+([0-9.]+|-)\s+([A-Z_]+)'
            if alert:
                def alert_cond(grp, name, disp_name, dep, avail, status):
                    grp[name] = status
                    return status != 'DEPLOYED'
                alert_msg = 'Detected packages in undeployed state:'
                return utils.parse_by_line_and_alert(self.logger, pattern, out, alert_cond=alert_cond, alert_msg=alert_msg)
            else:
                return utils.parse_by_line_and_alert(self.logger, pattern, out)
        except PexpectTimeout:
            self.logger.warning('Encountered timeout requesting maglev package status (%s seconds).', timeout)
            return False

    @utils.encapsulate
    def get_maglev_catalog_package_listing(self, *, alert=False, timeout=300):
        """
        Sends a `maglev catalog package display` command and parses the output.

        If the 'alert' keyword is True, it will also output warnings for any package which is not in the state
        'Ready'.

        Notes:
            Outputs a list of tuples representing each package:
            (Package Name, Package Display Name, Package Version, Package State, Package Info)

        :return:    List of 4-tuples (see notes)
        :rtype:     list
        """
        cmd = 'maglev catalog package display'
        try:
            out = self._send(cmd, timeout=timeout)
            pattern = r'([a-z-]+)\s+(.*\w)\s+([0-9.]+|-)\s+([A-Z_]+)\s+(.*)'
            if alert:
                def alert_cond(grp, name, version, state, info):
                    grp[name] = state
                    return state != 'READY'
                alert_msg = 'Detected packages in non-ready state:'
                return utils.parse_by_line_and_alert(self.logger, pattern, out, alert_cond=alert_cond, alert_msg=alert_msg)
            else:
                return utils.parse_by_line_and_alert(self.logger, pattern, out)
        except PexpectTimeout:
            self.logger.warning('Encountered timeout requesting maglev catalog packages (%s seconds).', timeout)
            return False

    @utils.encapsulate
    def get_service_message_queue(self):
        magctl_cmd = 'magctl service exec rabbitmq -c rabbitmq \'rabbitmqctl status\''
        return self._send(magctl_cmd)

    @utils.encapsulate
    def get_repository_context(self):
        return self._send('maglev context display')

    @utils.encapsulate
    def set_repository_default_context(self, default_repository):
        # TODO: can add a verification check
        return self._send('maglev context default {}'.format(default_repository))

    @utils.encapsulate
    def set_SB_service(self, server='maglev.maglevcloud3.tesseractinternal.com',
                            proxy="http://proxy-wsa.esl.cisco.com:80", timeout=300):

        magctl_cmd = 'magctl service {} telemetry-agent TETHERING_SERVICE'
        self._send(magctl_cmd.format('unsetenv') + '_HOST')
        self._send(magctl_cmd.format('unsetenv') + '_PORT')
        self._send(magctl_cmd.format('unsetenv') + '_SCHEME')
        self._send('magctl service unsetenv telemetry-agent USE_PROXY')
        self._send('magctl service unsetenv telemetry-agent PROXY_SETTING')
        self._send('magctl service unsetenv dxhub-registry HTTPS_PROXY')
        time.sleep(5)
        self._send(magctl_cmd.format('setenv') + ('_HOST') + ' {}'.format(server))
        self._send(magctl_cmd.format('setenv') + ('_PORT "443"'))
        self._send(magctl_cmd.format('setenv') + ('_SCHEME https'))
        self._send('magctl service setenv telemetry-agent USE_PROXY "True"')
        self._send('magctl service setenv telemetry-agent PROXY_SETTING {}'.format(proxy))
        self._send('magctl service setenv dxhub-registry HTTPS_PROXY {}'.format(proxy))
        return True

    @utils.encapsulate
    def set_catalog_service(self, server, server_repo, server_token, *,
                            proxy="http://proxy-wsa.esl.cisco.com:80", timeout=600):
        magctl_cmd = 'magctl service {} catalogserver PARENT_CATALOG_SERVER{}'
        self._send(magctl_cmd.format('unsetenv', ''))
        self._send(magctl_cmd.format('unsetenv', '_TOKEN'))
        self._send(magctl_cmd.format('unsetenv', '_REPOSITORY'))
        self._send("magctl service restart catalogserver")
        time.sleep(60)
        self._send(magctl_cmd.format('setenv', '') + ' {}'.format(server))
        if server_token:
            self._send(magctl_cmd.format('setenv', '_TOKEN') + ' {}'.format(server_token))
        self._send(magctl_cmd.format('setenv', '_REPOSITORY') + ' {}'.format(server_repo))
        self._send(magctl_cmd.format('setenv', '_OVERRIDE') + ' {}'.format("true"))
        self._send('magctl service unsetenv catalogserver  CATALOG_SRV_INSECURE ')
        self._send('magctl service setenv catalogserver  CATALOG_SRV_INSECURE true')
        self._send('maglev catalog settings validate', timeout=timeout)
        magctl_cmd = 'magctl service {}  catalogserver MAGLEV_HTTPS{}'
        self._send(magctl_cmd.format('unsetenv', '_PROXY'), timeout=timeout)
        self._send(magctl_cmd.format('setenv', '_PROXY') + ' {}'.format(proxy), timeout=timeout)
        self._send("magctl service restart catalogserver")
        time.sleep(60)
        self._send("maglev catalog check_for_updates")
        return self._send('maglev catalog settings display', timeout=timeout)

    @utils.encapsulate
    def reboot(self, *, delay=10, timeout=1800):
        """
        Sends a `sudo reboot` command and returns a bool representing if nothing bad happened.

        Notes:
            This method always disconnects the current ssh session.
            This only blocks until it successfully pings the system.
            (Its services may not be ready yet)

        :return:    True if success, False otherwise
        :rtype:     bool
        """
        ret = False
        try:
            self.logger.info("Sending command: sudo reboot")
            self._send('sudo reboot', interrupt=True)
            self._ping(delay, timeout)
            ret = True
        except Exception as err:
            msg = "Encountered exception during reboot."
            self.logger.error(msg)
            self.logger.error(err, exc_info=True)
            msg = "Last ssh response:\n" + self.get_ssh_last_response()
            self.logger.error(msg)
        finally:
            if self.is_connected:
                self.disconnect()
        return ret

    @utils.encapsulate
    def gen_rca(self, *, timeout=1200):
        """
        Sends an `rca` command and retrieves the package location.

        Notes:
            This command uses its own default timeout due to a long runtime.
            If passwords are not provided, this method will prompt for user input.

        :return:    RCA package location
        :rtype:     str
        """
        last_response = self._send('rca', timeout=timeout)
        out = re.search(r'Created RCA package: (.*)\n', last_response)
        if out is not None:
            return out.groups()[0]
        else:
            self.logger.error('Failed to parse rca command output for package.')
            msg = "Last ssh response:\n" + last_response
            self.logger.error(msg)
            return False

    @utils.encapsulate
    def pull_catalog_packages(self, package_list, export_context, push_context, *,
                              tmp_write_directory='/home/maglev/tmp', no_overwrite=True):
        """
        Pulls the specified packages from the central catalog server.

        Notes:
        - Make sure the correct repository is set as the default before pulling packages (set with
            `set_repository_default_context`).
        - Context inputs must be known to the appliance (check with `get_repository_context`).
        - Make sure the given packages exist before running (check with `get_maglev_catalog_packages`).
        - Will export each package from a temporary 'tmp_write_directory' directory.

        :param package_list List[str]:  List of packages to pull.
                                        Each entry should be in the form: "package-name:version".
                                        E.g. "test-support:2.1.75.60406"
                                        The 'version' field can also use 'x' as a universal matcher.
                                        E.g. "ncp-system:2.1.x.x"
        :param export_context str:      Context to export from.
        :param push_context str:        Context to push pulled packages into.
        :kwarg tmp_write_directory str: Temporary directory to export packages from.
        :kwarg no_overwrite bool:       Raise an exception if the tmp directory already exists,
                                        instead of overwriting.

        :raises OSError:    If the temporary write directory already exists and 'no_overwrite' is True.
        """
        if no_overwrite and os.path.exists(tmp_write_directory):
            msg = 'Temporary write directory "{}" already exists!'.format(tmp_write_directory) \
                + 'Cleanup in advance, or run with no_overwrite=False'
            self.logger.error(msg)
            raise OSError(msg)
        # TODO: validate input
        # TODO: validate repository
        self.logger.info(
            'Using export context "%s" and push context "%s"',
            export_context, push_context,
        )
        # TODO: validate packages are legal
        self.logger.info('Pulling catalog packages:\n%s', pprint.pformat(package_list))
        self.logger.debug('Exporting packages from context: %s', tmp_write_directory)
        for package_string in package_list:
            self.logger.debug('Creating pull directory')
            os.mkdir(tmp_write_directory)
            self.logger.debug('Pulling package "%s"', package_string)
            self._send('maglev -c {} catalog package export {} {}'.format(
                export_context, package_string, tmp_write_directory
            ))
            # TODO: validate output
            self.logger.debug('Pushing package "%s"', package_string)
            self._send('maglev -c {} catalog push {}'.format(
                push_context, tmp_write_directory
            ))
            # TODO: validate output
            shutil.rmtree(tmp_write_directory)
            self.logger.info('Successfully pulled package "%s"', package_string)
        self.logger.info('Successfully pulled all packages')

    @utils.encapsulate
    def check_docker_health(self, *, alert=False):
        pattern = r'Active: active \(running\)'
        out = self._send('systemctl status docker | cat')
        match = re.search(pattern, out)
        if match is None:
            self.logger.warning('Docker service is not active.')
            return False

        out = self._send('docker ps -f status=exited')
        pattern = r'([a-z0-9]+).*(Exited \(\d+\) \d+ \w+ ago).*'
        if alert:
            def alert_cond(grp, cont_id, exit_status):
                grp['Container ID'] = cont_id
                grp['Status'] = exit_status
                return 'days' in exit_status
            alert_msg = 'Detected stale packages:'
            utils.parse_by_line_and_alert(self.logger, pattern, out, alert_cond, alert_msg)
        return True

    @utils.encapsulate
    def service_restart(self, service):
        magctl_cmd = 'magctl service restart {}'.format(service)
        out = self._send(magctl_cmd)
        if 'ERROR' in out:
            msg = 'Failed to identify or restart service "%s" (did you spell it right?).'
            self.logger.error(msg, service)
            return False
        else:
            out = utils.clean(out)
            msg = 'Service "{}" container [{}] restarted'.format(service, out.split('\n')[1])
            self.logger.debug(msg)
            return True

    @utils.encapsulate
    def follow_log_service_initialized(self, service, pattern, *, timeout=1200):
        """
        Follows the given service's magctl log until a specific pattern is parsed or a timeout is reached.

        Notes:
            Leaves a copy of the log on the client in /var/tmp.
            Uses a named pipe on the client to track progress.
            Does not raise timeout exceptions (returns False in this case).

        :return:    True if found, False otherwise
        :rtype:     bool
        """
        msg = 'Parsing service "{}" log for pattern "{}" (T/O: {})'.format(service, pattern, timeout)
        self.logger.debug(msg)
        success = False
        fifo = ''
        try:
            mtime = time.strftime('%Y%m%d-%H%M%S')
            self.logger.debug('Preparing I/O pipe')
            fifo = '/var/tmp/{}.mscl.fifo'.format(mtime)
            setup_cmd = r'mkfifo {} &>/dev/null'.format(fifo)
            self._send(setup_cmd)

            self.logger.debug('Reading service log')
            logfile = '/var/tmp/{}.{}.log'.format(mtime, service)
            self.logger.info('Writing log @ %s:%s', self.node_ip, logfile)
            magctl_cmd = r'magctl service logs -rf {} | tee {} {} &'.format(service, logfile, fifo)
            self._send(magctl_cmd)

            self.logger.debug('Blocking on pattern')
            grep_cmd = r"grep -Pxq '{}' {} && kill %%".format(pattern, fifo)
            self._send(grep_cmd, timeout=timeout)

            # Split EC output as it may get the job termination message from the previous send
            exit_code = int(utils.clean(self._send(r'echo $?')).split('\n')[0])
            success = exit_code == 0
            self.logger.debug('Grep returned with exit code (%s)', exit_code)
            #TODO: Do something if nonzero?
        except PexpectTimeout:
            msg = 'Timeout: Failed to parse pattern "{}" after {} seconds'.format(pattern, timeout)
            self.logger.error(msg)
            success = False
        finally:
            time.sleep(1)
            self.logger.debug('Sending interrupt')
            self.ssh.sendcontrol('c')
            self.ssh.prompt()
            self.logger.debug('Cleaning I/O pipe')
            cleanup_cmd = 'rm -f {}'.format(fifo)
            self._send(cleanup_cmd)
        msg = 'Service "{}" parse "{}" result: {}'.format(service, pattern, success)
        self.logger.debug(msg)
        return success

    @utils.encapsulate
    def verify_all_services_running(self, *, timeout=360):
        """
        Verifies that all services are running.  If not, waits <timeout> seconds until it is.

        Notes:
            Returns whether the service is running.  Logs a warning if not.

        :return:    True if up, False otherwise
        :rtype:     bool
        """
        time_start = time.time()
        is_up = False
        while not is_up and time.time() - time_start < timeout or timeout <= 0:
            magctl_cmd = 'magctl appstack status'
            out = self._send(magctl_cmd)
            running_count_pattern = r'(0\/1)'
            if re.findall(running_count_pattern, out):
                if timeout > 0:
                    time.sleep(20)
                else:
                    break
            else:
                is_up=True
                break
        if not is_up:
            msg = 'Service "{}" not up after {} seconds'.format(service, timeout)
            self.logger.warning(msg)
        return is_up

    @utils.encapsulate
    def verify_service_running(self, service, *, timeout=60):
        """
        Verifies that the given service is running.  If not, waits <timeout> seconds until it is.

        Notes:
            Returns whether the service is running.  Logs a warning if not.

        :return:    True if up, False otherwise
        :rtype:     bool
        """
        time_start = time.time()
        is_up = False
        while not is_up and time.time() - time_start < timeout or timeout <= 0:
            magctl_cmd = 'magctl appstack status | grep {}'.format(service)
            out = self._send(magctl_cmd)
            running_count_pattern = r'([0-9]+)/\1'
            is_up = 'Running' in out and re.search(running_count_pattern, out) is not None
            if timeout > 0:
                time.sleep(5)
            else:
                break
        if not is_up:
            msg = 'Service "{}" not up after {} seconds'.format(service, timeout)
            self.logger.warning(msg)
        return is_up

    @utils.encapsulate
    def validate_catalog_settings(self):
        magctl_cmd = 'maglev catalog settings validate'
        out = self._send(magctl_cmd)
        if 'Parent catalog settings are valid' not in out:
            magctl_cmd = 'maglev catalog settings display'
            out = self._send(magctl_cmd)
            msg = 'Catalog settings are not valid! Current settings:\n' + utils.clean(out)
            self.logger.warning(msg)
            return False
        return True

    @utils.encapsulate
    def add_static_hosts_lookup_for_ise_collector(self, data):
        result = True
        try:
            out = self._add_hosts_ise_collector(data=data)
            self.logger.info("#-------------------------------------")
            for d in data:
                if re.search(r"{}\n".format(d), out):
                    self.logger.info("Configured FQDN Lookup {} for ise collector successfully".format(d))
                else:
                    self.logger.error("Failed to configure FQDN Lookup {} for Ise collector".format(d))
                    result &=False
            # if re.search(r"{}\n".format(data), out):
            #     result = True
            #     self.logger.info("Configured FQDN Lookup {} for ise collector successfully".format(data))
            # else:
            #     self.logger.error("Failed to configure FQDN Lookup {} for Ise collector".format(data))
            self.logger.info("#-------------------------------------")
        except Exception as e:
            self.logger.error(e)
            result &=False
        return result

    def _add_hosts_ise_collector(self, data, *, auto_auth=True, interrupt=False, timeout=None):
        """
        Class method for sending a message through an open ssh connection.

        :param str cmd:           Message to send
        :kwarg bool auto_auth:    Automatically detect and handle authentication queries.
        :kwarg bool interrupt:    Interrupts the current ssh session (waits timeout seconds).
        :kwarg str expect:        Expected prompt after send.  Uses default if None.
        :kwarg int timeout:       Maximum wait time for prompt.  Uses default if None.

        :return:    String output of the command
        :rtype:     str

        :raises pxssh.ExceptionPxssh:   Attempted to send a command without connecting first.
        :raises PexpectEof:             Encountered an EOF while communicating with maglev.
        :raises PexpectTimeout:         Timed out while expecting a response from maglev.
        """
        if not self.is_connected:
            msg = 'Send command requires an open connection.'
            self.logger.error(msg)
            raise pxssh.ExceptionPxssh(msg)

        if timeout is None:
            timeout = self._default_timeout

        # cmd = "magctl service attach collector-ise"
        cmd = "magctl service attach ise-bridge"
        expect = "#"

        self.logger.info('Sending line: `%s`\n', cmd)
        self.logger.debug('Command timeout: %s', timeout)
        if expect is not None:
            self.logger.debug('Expecting following prompt: %s', expect)

        self.ssh.sendline(cmd)

        expect_list = [PexpectTimeout, PexpectEof]
        if expect is None:
            expect_list.append(self.ssh.PROMPT)
        else:
            expect_list.append(expect)

        if auto_auth:
            # Add authentication prompts to the expect list
            prompt_sudo_pw = r'\[sudo\] password for \w+:'
            expect_list.append(prompt_sudo_pw)
            prompt_admin_user = r'\[administration\] username for \'[0-9a-zA-Z.:/-]+\':'
            expect_list.append(prompt_admin_user)
            prompt_admin_pw = r'\[administration\] password for \'\w+\':'
            expect_list.append(prompt_admin_pw)

        try:
            while True:
                index = self.ssh.expect(expect_list, timeout=timeout)
                if index == 0:
                    # Timeout case
                    try:
                        self.logger.info('Parsed timeout: sending interrupt.')
                        self.ssh.sendcontrol('c')
                        self.ssh.prompt()
                    except Exception as err:
                        self.logger.error('Exception on interrupt.')
                        self.logger.error(err)
                    raise PexpectTimeout('Timeout exceeded.')
                elif index == 1:
                    # EOF case (connection is closed)
                    eof_msg = 'EOF received - connection is closed.  Cleaning up session.'
                    self.logger.error(eof_msg)
                    self.disconnect(try_interrupt=False)
                    raise PexpectEof(eof_msg)
                elif index == 2:
                    # Expected prompt reached
                    self.logger.info("\nChecking the entry {} in /etc/hosts".format(data))
                    self.ssh.sendline("cat /etc/hosts".format(data))
                    self.ssh.prompt()
                    res = self.ssh.before.decode('utf-8')
                    # self.logger.info(res)
                    for d in data:
                        if d in res:
                            self.logger.info("\nFound the entry {} in /etc/hosts. Skipp adding\n".format(d))
                        else:
                            self.logger.info("\nAdding {} to /etc/hosts".format(d))
                            self.ssh.sendline("echo '{}'>>/etc/hosts".format(d))
                            self.ssh.prompt()
                            time.sleep(1)
                            self.ssh.sendline("cat /etc/hosts".format(d))
                            self.ssh.prompt()
                            # res2 = self.ssh.before.decode('utf-8')
                            # self.logger.info(res2)
                    time.sleep(2)
                    self.ssh.sendline("exit")
                    time.sleep(2)
                    break
                elif index == 3:
                    # sudo password prompt
                    #TODO: do we need a specific sudo password?
                    cmd = self.password
                    self.logger.info('Encountered sudo password prompt with auto-auth')
                    self.logger.info('Context:\n%s', self.get_ssh_last_response())
                    self.logger.info('Automatically sending line: `%s`', cmd)
                    self.ssh.sendline(cmd)
                elif index == 4:
                    # admin username prompt
                    cmd = self.admin_username
                    self.logger.info('Encountered admin username prompt with auto-auth')
                    self.logger.info('Context:\n%s', self.get_ssh_last_response())
                    self.logger.info('Automatically sending line: `%s`', cmd)
                    self.ssh.sendline(cmd)
                elif index == 5:
                    # admin password prompt
                    cmd = self.admin_password
                    self.logger.info('Encountered admin password prompt with auto-auth')
                    self.logger.info('Context:\n%s', self.get_ssh_last_response())
                    self.logger.info('Automatically sending line: `%s`', cmd)
                    self.ssh.sendline(cmd)
        except PexpectTimeout:
            if interrupt:
                pass
            else:
                raise
        finally:
            if interrupt:
                self.logger.debug('Connection interruption indicated.  Closing session.')
                self.disconnect(try_interrupt=False)

        output = self.get_ssh_last_response()
        self.logger.info(u'\n****Response recieved****\n%s', output)
        self.logger.info('Send complete')
        return output

    def _register_witness(self,reg_cmd, witness_ip, witness_username,witness_password,
                          main_password,*, auto_auth=True, interrupt=False, timeout=None):
        """
        Class method for sending a message through an open ssh connection.

        :param str cmd:           Message to send
        :kwarg bool auto_auth:    Automatically detect and handle authentication queries.
        :kwarg bool interrupt:    Interrupts the current ssh session (waits timeout seconds).
        :kwarg str expect:        Expected prompt after send.  Uses default if None.
        :kwarg int timeout:       Maximum wait time for prompt.  Uses default if None.

        :return:    String output of the command
        :rtype:     str

        :raises pxssh.ExceptionPxssh:   Attempted to send a command without connecting first.
        :raises PexpectEof:             Encountered an EOF while communicating with maglev.
        :raises PexpectTimeout:         Timed out while expecting a response from maglev.
        """
        if not self.is_connected:
            msg = 'Send command requires an open connection.'
            self.logger.error(msg)
            raise pxssh.ExceptionPxssh(msg)

        if timeout is None:
            timeout = self._default_timeout

        cmd = 'ssh -p 2222 {}@{}'.format(witness_username,witness_ip)
        expect = "Are you sure you want to continue connecting"

        self.logger.info('Sending line: `%s`\n', cmd)
        self.logger.debug('Command timeout: %s', timeout)
        if expect is not None:
            self.logger.debug('Expecting following prompt: %s', expect)

        self.ssh.sendline(cmd)

        expect_list = [PexpectTimeout, PexpectEof]
        if expect is None:
            expect_list.append(self.ssh.PROMPT)
        else:
            expect_list.append(expect)

        if auto_auth:
            # Add authentication prompts to the expect list
            prompt_sudo_pw = r'\[sudo\] password for \w+:'
            expect_list.append(prompt_sudo_pw)
            prompt_admin_user = r'\[administration\] username for \'[0-9a-zA-Z.:/-]+\':'
            expect_list.append(prompt_admin_user)
            prompt_admin_pw = r'\[administration\] password for \'\w+\':'
            expect_list.append(prompt_admin_pw)

        try:
            while True:
                index = self.ssh.expect(expect_list, timeout=timeout)
                if index == 0:
                    # Timeout case
                    try:
                        self.logger.info('Parsed timeout: sending interrupt.')
                        self.ssh.sendcontrol('c')
                        self.ssh.prompt()
                    except Exception as err:
                        self.logger.error('Exception on interrupt.')
                        self.logger.error(err)
                    raise PexpectTimeout('Timeout exceeded.')
                elif index == 1:
                    # EOF case (connection is closed)
                    eof_msg = 'EOF received - connection is closed.  Cleaning up session.'
                    self.logger.error(eof_msg)
                    self.disconnect(try_interrupt=False)
                    raise PexpectEof(eof_msg)
                elif index == 2:
                    # Expected prompt reached
                    self.logger.info("Going to send Yes to add to known host")
                    self.ssh.sendline("yes")
                    self.ssh.prompt()
                    res = self.ssh.before.decode('utf-8')
                    if "password" in res.lower():
                        self.logger.info("Found password prompt. Going to send Witness password")
                        self.ssh.sendline(witness_password)
                        self.ssh.prompt()
                        res = self.ssh.before.decode('utf-8')
                        if "$" in res:
                            self.logger.info("Found prompt. Successfully login Witness. Going to send register command")
                            self.ssh.sendline(reg_cmd)
                            self.ssh.prompt()
                            res = self.ssh.before.decode('utf-8')
                            if "password" in res.lower():
                                self.logger.info("Found password prompt. Going to send Main password to register")
                                self.ssh.sendline(main_password)
                                self.ssh.prompt(timeout=600)
                                res = self.ssh.before.decode('utf-8')
                                self.logger.info("Found prompt. The register command should be finished")
                                time.sleep(60)
                    time.sleep(2)
                    self.logger.info("Going to send exit")
                    self.ssh.sendline("exit")
                    time.sleep(2)
                    break
                elif index == 3:
                    # sudo password prompt
                    #TODO: do we need a specific sudo password?
                    cmd = self.password
                    self.logger.info('Encountered sudo password prompt with auto-auth')
                    self.logger.info('Context:\n%s', self.get_ssh_last_response())
                    self.logger.info('Automatically sending line: `%s`', cmd)
                    self.ssh.sendline(cmd)
                elif index == 4:
                    # admin username prompt
                    cmd = self.admin_username
                    self.logger.info('Encountered admin username prompt with auto-auth')
                    self.logger.info('Context:\n%s', self.get_ssh_last_response())
                    self.logger.info('Automatically sending line: `%s`', cmd)
                    self.ssh.sendline(cmd)
                elif index == 5:
                    # admin password prompt
                    cmd = self.admin_password
                    self.logger.info('Encountered admin password prompt with auto-auth')
                    self.logger.info('Context:\n%s', self.get_ssh_last_response())
                    self.logger.info('Automatically sending line: `%s`', cmd)
                    self.ssh.sendline(cmd)
        except PexpectTimeout:
            if interrupt:
                pass
            else:
                raise
        finally:
            if interrupt:
                self.logger.debug('Connection interruption indicated.  Closing session.')
                self.disconnect(try_interrupt=False)

        output = self.get_ssh_last_response()
        self.logger.info(u'\n****Response recieved****\n%s', output)
        self.logger.info('Send complete')
        return output


    @utils.encapsulate
    def register_witness(self, main_ip, main_username, main_password, token, witness_ip, witness_username, witness_password):
        result = False
        try:
            cmd = 'ssh-keygen -f "/home/maglev/.ssh/known_hosts" -R [{}]:2222'.format(witness_ip)
            res = self._send(cmd=cmd)

            reg_cmd = 'witness register -w {} -m {} -t {} -u {}'.format(witness_ip, main_ip, token, main_username)
            out = self._register_witness(reg_cmd=reg_cmd, witness_ip=witness_ip, witness_username=witness_username,
                                         witness_password=witness_password, main_password=main_password, timeout=300)
            if 'registration successful' in out.lower():
                self.logger.info("Found 'registration successful'")
                result = True
        except Exception as e:
            self.logger.error(e)
        return result

    @utils.encapsulate
    def update_ssh_timeout(self, ssh_timeout=900):
        result = False
        try:
            cmd = "sudo sed -i 's/ClientAliveInterval [0-9]*/ClientAliveInterval {}/g' /etc/ssh/sshd_config".format(ssh_timeout)
            res = self._send(cmd=cmd)

            cmd = "sudo systemctl restart ssh.service"
            res = self._send(cmd=cmd)
            result=True
        except Exception as e:
            self.logger.error(e)
        return result

