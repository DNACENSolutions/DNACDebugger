#*******************************************************************************
#*                              DNAC DEBUGGER TOOL
#* ----------------------------------------------------------------------------
#* ABOUT THIS TOOL - Please read
#* Copyright: Cisco Systems 2022
#*
#* Support:
#*    abhigsri@cisco.com, pawansi@cisco.com
#*
#* Description:
#*  This file contains Class definition for DNAC DEBUGGER TOOL
#*
#*
#*******************************************************************************
import logging
import re
import os
import shutil
import json
import yaml
import ipaddress
from services.maglev_cli.maglevclihandler import MaglevSystemCommandLine as MSCL
from services.client_manager import ApicemClientManager as ACM
from services.datadog_integration.datadog_integration import DatadogIntegration as DDIntg

LOGSDIR = 'service_logs'
CACHEDIR = '.cache'
LOGGER = logging.getLogger(__name__)

COL_PURPLE = '\033[95m'
COL_BLUE = '\033[94m'
COL_CYAN = '\033[96m'
COL_GREEN = '\033[92m'
COL_YELLOW = '\033[93m'
COL_RED = '\033[91m'
COL_ENDC = '\033[0m'
COL_BOLD = '\033[1m'
COL_UNDERLINE = '\033[4m'

SERVICE_PATTERN = r"\S+\s+(\S+-\d+\S+)\s+\d+\/\d+\s+\S+\s+\d+"
# logging.basicConfig(level=logging.DEBUG)

ROLE_BASED_AREA_COMMANDS = "config/role_based_cmds.yaml"
AREA_COMMANDS = "config/area_cmds.yaml"

class DNAC_Debugger:
    """
    DNAC Debugger tool main class.
        To start for CLI interface call: Run this main file or call as below.
            deb = DNAC_Debugger(interface_cli=True)
        To Initilize through script use as below.
        from dnac_debugger import DNAC_Debugger
        deb = DNAC_Debugger(node_ip=<Cluster IP>, port =<maglev ssh port>, admin_username=<UI admin/observer username>, 
                            admin_password=<UI admin/observer user password.>, username=<Maglev CLI username>, password=<Maglev CLI Password>)
        Example:
            Python 3.7.9 (v3.7.9:13c94747c7, Aug 15 2020, 01:31:08) 
            [Clang 6.0 (clang-600.0.57)] on darwin
            Type "help", "copyright", "credits" or "license" for more information.
            >>> from dnac_debugger import DNAC_Debugger
            >>> deb = DNAC_Debugger(node_ip="10.195.243.53", admin_username="admin",admin_password="Maglev123")
            /Users/pawansingh/Library/Python/3.7/lib/python/site-packages/urllib3/connectionpool.py:852: InsecureRequestWarning: Unverified HTTPS 
                request is being made. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
              InsecureRequestWarning)
            >>> deb.
            deb.admin_password  deb.cache_list      deb.interface_cli   deb.mscl            deb.password        deb.regex_date      deb.regex_time      deb.unique         
            deb.admin_username  deb.dnac            deb.logger          deb.node_ip         deb.port            deb.regex_line      deb.regex_timestamp deb.username       
    """
    def __init__(self, node_ip=None, port=2222, admin_username='admin', admin_password='Maglev123', 
                username='maglev', password='Maglev123', 
                logs_dir=LOGSDIR, cache_dir = CACHEDIR, 
                interface_cli=False):
        """
        Instantiates the DNAC Debugger tool
        """
        self.logger = LOGGER
        self.logger.info('Log started.')
        self.node_ip = node_ip
        self.port = port
        self.username = username
        self.password = password
        self.admin_username = admin_username
        self.admin_password = admin_password
        self.interface_cli = interface_cli

        self.cache_list = []
        if os.path.isdir(cache_dir):
            self.logger.debug('Found existing cache directory')
        else:
            os.mkdir(cache_dir)
            self.logger.debug('Cache directory created, path = {0}'.format(cache_dir))
        self.__cache_dir = cache_dir

        if os.path.isdir(logs_dir):
            self.logger.debug('Found existing service_logs directory')
        else:
            os.mkdir(logs_dir)
            self.logger.debug('service_logs directory created, path = {0}'.format(logs_dir))
        self.__logs_dir = logs_dir
        import timeit
        cpu_time = str(timeit.default_timer())
        self.unique = cpu_time.replace('.','') # Unique key for the given instance of program

        #Regular expressions
        self.regex_date = r'\d\d\d\d-\d\d-\d\d'
        self.regex_time = r'\d\d:\d\d:\d\d'
        self.regex_timestamp = r'(\d\d\d\d-\d\d-\d\d) (\d\d:\d\d:\d\d)'
        self.regex_line = r'^(\d\d\d\d-\d\d-\d\d(.*\n\D)?.*{}.*(\n\D.*)*)'

        self._login()

    def _get_credentials(self):
        """
        Helper function to get login credentials for the DNAC Cluster

        :return:    node_ip, port, username, password, admin_username, admin_password
        :rtype:     str, int, str, str, str, str
        """
        self.logger.debug('Getting login credentials')
        node_ip = input('## Enter DNAC IP address of added node: ')
        node_ip = node_ip.strip()
        try:
            ipaddress.ip_address(node_ip)
        except ValueError:
            node_ip = input('## Invalid IP, Enter valid IPv4 address(i.e 10.10.10.1): ')
            node_ip = node_ip.strip()
            ipaddress.ip_address(node_ip)

        port = 2222
        username = 'maglev'
        password = 'Maglev123'
        admin_username = 'admin'
        admin_password = password

        manual = input('## Manually input other credentials?[\'y\'/(skip)]: ')
        if manual is 'y':
            port = input('## Enter Port to use to access added node (Skip for default): ')
            if port is '':
                port = 2222
            else:
                try:
                    port = int(port)
                except Exception as e:
                    self.logger.error('Not a valid number')
                    self.logger.error(e)
                    raise
        
            manual = input('## Manually enter username and password?[\'y\'/(skip)]: ')
            if manual is 'y':
                username = input('## Enter Username to access added node: ')
                password = input('## Enter Password to use to access added node: ')
        
            manual = input('## Manually enter admin username and admin password?[\'y\'/(skip)]: ')
            if manual is 'y':
                admin_username = input('## Enter Admin username to access added node: ')
                admin_password = input('## Enter Admin password to use to access added node: ')
        
        return node_ip, port, username, password, admin_username, admin_password

    def _login(self):
        """
        Class method for logging into the Maglev System using Maglev CLI handler

        :return:    None
        """
        if self.interface_cli:
            node_ip, port, username, password, admin_username, admin_password = self._get_credentials()
            self.logger.debug('IP address = {0}'.format(node_ip))
            self.logger.debug('Username = {0}'.format(username))
            self.logger.debug('Password = {0}'.format(password))
            self.logger.debug('Port Number = {0}'.format(port))
            self.logger.debug('Administrator username = {0}'.format(admin_username))
            self.logger.debug('Administrator password = {0}'.format(admin_password))
            self.logger.debug('Attempting login to Maglev')
            self.node_ip=node_ip
            self.username=username
            self.password=password
            self.port=port
            self.admin_username = admin_username
            self.admin_password = admin_password
        try:
            self.mscl = MSCL(self.node_ip, self.username, self.password, self.port, admin_username = self.admin_username, admin_password = self.admin_password)
        except Exception as e:
            self.logger.error('Couldn\'t create Maglev CLI Object')
            self.logger.error(e)
            raise
        self.logger.debug('Maglev System Command Line object created successfully.')

        try:
            self.dnac = ACM(self.node_ip, self.admin_username, self.admin_password, maglev = True)
        except Exception as e:
            self.logger.error('Couldn\'t create DNAC API Client Manager Object')
            self.logger.error(e)
            raise
        self.logger.debug('DNAC API Client Manager object created successfully.')
        
    def _screen(self, title, options = []):
        """
        Utility function to print the current screen with title and
        list of options to choose from

        :param title str:           Title of the current screen
        :param options List[str]:   List of options to choose from

        :return:    Chosen option index
        :rtype:     int
        """
        self.logger.debug('Printing the screen -> ' + title)
        options.append('Exit')
        self.logger.debug('Options for the given screen are: {0}'.format(options))
        print()
        print(title.center(80, ' '))
        print('\tOptions:')
        for i in range(0, len(options)):
            print('\t\t{:<3} ->  {}'.format(i+1, options[i]))
        print('\n' + '*'*80)
        try:
            choice = int(input('## Enter the Option: '))
        except Exception as e:
            self.logger.error('Not a number!')
            self.logger.error(e)
            raise
        if choice < 1 or choice > len(options):
            self.logger.error('Invalid Option choice = {0}'.format(choice))
            print('Invalid option chosen')
            self._exit()
        self.logger.debug('Chosen option => {0}'.format(options[choice-1]))
        if len(options) is choice:
            self._exit()
        return choice-1
        
    def _home(self):
        """
        Utility function to print the home screen for the debugger tool

        :return:    None
        """
        tile = '    Welcome to the Cisco DNAC Debugger Tool    '
        vers = '                 Version 1.0.1                 ' 
        print('*'*80)
        print('*'*80)
        print((' '*len(tile)).center(80, '*'))
        print(tile.center(80, '*'))
        print(vers.center(80, '*'))
        print((' '*len(tile)).center(80, '*'))
        print('*'*80)
        print('*'*80)
        self.logger.debug('Cisco DNAC Debugger Home screen loaded')
        title = 'Cisco DNAC Debugger'
        options = ['Service logs analyzer', 'Device logs collector', 'Generate and collect DNAC RCA', 'Catalog Server Details', 'DNAC Package Upgrade', 'Maglev CLI output', 'Datadog Integration']
        choice = self._screen(title, options)
        if choice is 0:
            self._logs()
        elif choice is 1:
            self._devDeb()
        elif choice is 2:
            print(self.mscl.gen_rca())
            self._exit()
        elif choice is 6:
            ddintg = DDIntg(node_ip=self.node_ip, port=self.port, admin_username=self.admin_username, admin_password=self.admin_password,
                            username=self.username, password=self.password, interface_cli=self.interface_cli, logger=self.logger,
                            mscl = self.mscl)
            ddintg.get_cluster_details(self)
            ddintg.save_and_zip()
            ddintg.upload_and_deploy()
            self._exit()
        else:
            print(COL_RED + 'This option is yet to be supported.' + COL_ENDC)
        return self._home()

    def __get_services(self, output):
        """
        Utility function to get all the services working in DNA Center

        :param output Dict[List[str]]:  Dictionary of output from magctl appstack status
                                        with keys as column names and value as list of instances
                                        of that service 

        :return:    Result dictionary with service names as keys and list 
                    of all instances of that service as value
        :rtype:     Dict[List[str]]
        """
        result = {}
        for item in output['NAME']:
            servicename = item
            item = re.findall("(\S+)-[a-f\d]+\S+", item)
            if item:
                item1 = re.findall("(\S+)-[a-f\d]+\S+", item[0])
                if item1:
                    item=item1
                item = item[0].replace('-', ' ')
                item = item.title()
                if item in result.keys():
                    result[item].append(servicename)
                else:
                    result[item] = [servicename]
        return result

    def __get_logs(self):
        """
        Utility function to get all logs from Maglev cluster

        :return:    Dictionary of column names as keys and list of 
                    command output for that column as value
        :rtype:     Dict[List[str]]
        """
        try:
            out_log = self.mscl.send_cmd('magctl appstack status')
        except Exception as e:
            self.logger.error(e)
            raise
        out = []
        for line in out_log.split('\n'):
            out.append(line)
        output = {}
        keys = []
        for word in out[0].split():
            keys.append(word)
        # Fixing column names
        keys[8] += ' ' + keys[9]
        keys[10] += ' ' + keys[11]
        del keys[9]
        del keys[10]
        for key in keys:
            output[key] = []  
        for i in range(1, len(out)-1):
            ind = 0
            for word in out[i].split():
                output[keys[ind]].append(word)
                ind += 1
        return output

    def _logs(self):
        """
        Utility function to show the list of services present
        in the DNAC for analysis of logs

        :return:    None
        """
        output = self.__get_logs()
        _services = self.__get_services(output)
        services = list(_services.keys())
        title = 'Cisco DNAC Service Log Analyzer'
        choice = self._screen(title, services)

        if len(_services[services[choice]]) == 1:
            service = _services[services[choice]][0]
        else:
            choice2 = self._screen(services[choice], _services[services[choice]])
            service = _services[services[choice]][choice2]    
        self._service_logs(service)

    def _service_logs(self, service):
        """
        Utility function to get the type of log analysis and accordingly
        route the further function calls

        :param service str: Name of the service instance for which logs
                            need to be fetched

        :return:    None
        """
        title = service.replace('-', ' ').title()
        options = ['Analyze existing Log file', 'Capture Live Logs', 'Restart the service']
        choice = self._screen(title, options)

        # Check for pre-existing directory on Maglev cluster
        files = self.mscl.send_cmd('ls').split() 
        try:
            files.index('DNAC_debugger')
        except:
            self.mscl.send_cmd('mkdir DNAC_debugger')
            self.mscl.send_cmd('mkdir DNAC_debugger/service_logs')
        if choice is 0:
            self._old_log_analyzer(service)
        elif choice is 1:
            print(COL_RED + 'Work in Progresssssss.........' + COL_ENDC)
            self._exit()
        elif choice is 2:
            response = self.mscl.service_restart(service)
            if response is True:
                print(COL_GREEN + 'Successfully restarted the service: {0}'.format(service) + COL_ENDC)
            else:
                print(COL_RED + 'Failed to restart the service: {0}'.format(service) + COL_ENDC)
            #self._exit()
        print("Returning to Main Menu:")

    def _old_log_analyzer(self, service):
        """
        Utility function to fetch the old logs for the given service
        and cache it to the local server

        :param service str: Name of the service instance for which logs
                            need to be fetched

        :return:    None 
        """
        file_name = service.replace('-', '') + '-' + self.unique + '.log'
        self.mscl.send_cmd('magctl service logs -r ' + service + ' > DNAC_debugger/service_logs/' + file_name)
        path = self.__cache_dir
        try:
            self.mscl.copy_rca_from_dnac('DNAC_debugger/service_logs/' + file_name, path)
        except Exception as e:
            self.logger.error(e)
            raise
        self.__cache(file_name = file_name)
        self.logger.debug('Log file for {0} cached locally in {1}'.format(service, path))
        self._log_checker(path + '/' + file_name, service)
        
    def _log_checker(self, logfile_path, service):
        """
        Utility function to search the fetched logs for keywords

        :param logfile_path str:    Directory path to the log file stored in the local cache
        :param service str:         Name of the service instance for which logs
                                    need to be fetched

        :return:    None
        """
        title = service.replace('-', ' ').title() + ' Log Analyzer'
        options = ['Download the log file', 'Search for Errors', 'Search for all Exceptions', 
                    'Search for Null Pointer Exception', 'Search for specific keyword']

        choice = self._screen(title, options)
        
        if choice is 0:
            shutil.copy(logfile_path, self.__logs_dir + '/')
            print(COL_YELLOW + 'Log file saved at {0}/{1}\n'.format(self.__logs_dir, service.replace('-', '') + '-' + self.unique + '.log') + COL_ENDC)
        elif choice is 1:
            self._get_logs_for_service(logfile_path, service, 'ERROR')
        elif choice is 2:
            self._get_logs_for_service(logfile_path, service, 'Exception:')
        elif choice is 3:
            self._get_logs_for_service(logfile_path, service, 'NullPointerException:')
        elif choice is 4:
            keyword = input('## Enter the keyword to search for: ')
            self._get_logs_for_service(logfile_path, service, keyword) 

        more = input('## Continue exploring the same log file?[y/n]: ')
        if more is 'y':
            self._log_checker(logfile_path, service)
        #else:
            #self._exit()

    
    def _get_logs_for_service(self, logfile_path, service, keyword):
        """
        Utility function to store the logs based on the keyword and timestamp query

        :param logfile_path str:    Directory path to the log file stored on the DNAC server
        :param service str:         Name of the service instance for which logs
                                    need to be fetched
        :param keyword str:         Keyword to be searched in the log file

        :return:    None
        """
        date, time = self.__get_timestamp(service, keyword, logfile_path)
        try:
            log_file = open(logfile_path, 'r').read()
        except Exception as e:
            self.logger.error(e)
            raise
        self.logger.debug('Search query started for keyword = {0}'.format(keyword))
        all_matches = re.findall(self.regex_line.format(keyword), log_file, re.MULTILINE)
        matches = []
        for item in all_matches:
            here_date = re.search(self.regex_date, item[0]).group()
            if here_date < date:
                continue
            elif here_date == date:
                here_time = re.search(self.regex_time,item[0]).group()
                if here_time < time:
                    continue
            matches.append(item[0].lstrip('\n')+'\n')
        self.logger.debug('{0} matches found for your query!'.format(len(matches)))
        self.logger.debug('Storing the search results')
        file_name = service.replace('-', '') + '-' + re.sub(r'\W+', '', keyword) + time.replace(':','') + '.log'
        try:
            with open(os.path.join(self.__logs_dir, file_name), 'w') as f:
                for item in matches:
                    f.write(item)
            f.close()
        except Exception as e:
            self.logger.error(e)
            raise
        self.logger.debug('Log file saved at {0}/{1}'.format(self.__logs_dir, file_name))
        result = open(os.path.join(self.__logs_dir, file_name), 'r').read()
        print('\n' + '*'*80 + COL_CYAN + result + COL_ENDC + '\n' + '*'*80)
        print(COL_RED + COL_BOLD + '\n{0} matches found for your query!'.format(len(matches)) + COL_ENDC)
        print(COL_YELLOW + 'Log file saved at {0}/{1} \n'.format(self.__logs_dir, file_name) + COL_ENDC)

    def __get_timestamp(self, service, keyword, logfile_path):
        """
        Utility function to get the timestamp for log search

        :param service str:         Name of the service instance for which logs
                                    need to be fetched
        :param keyword str:         Keyword to be searched in the log file
        :param logfile_path str:    Directory path to the log file stored on the DNAC server

        :return:    Date, time as two separate return values
        :rtype:     str, str
        """
        self.logger.debug('Function to get the timestamp started')
        title = service.replace('-', ' ').title() + ' ' + keyword + ' logs'
        options = ['Search all matches', 'Search from a starting time and date',
                    'Search in logs for last "X" minutes']
        choice = self._screen(title, options)
        self.logger.debug('')
        date = '0000-00-00'
        time = '00:00:00'
        if choice is 1:
            date = input('## Enter the start date in "YYYY-MM-DD" format: ')
            time = input('## Enter the start time in "HH:MM" format (24 hrs format): ')
            time += ':00'
        elif choice is 2:
            date, time = self.__get_delta_time(logfile_path)
        
        self.logger.debug('Final date = {0}, and final time = {1}'.format(date, time))
        return date, time
    
    def __get_delta_time(self, logfile_path):
        """
        Utility function to get the date and time for delta mins back

        :param logfile_path str:    Directory path to the log file stored on the DNAC server

        :return:    Date, time
        :rtype:     str, str 
        """
        try:
            delta = int(input('## Enter time delta in minutes: '))
        except Exception as e:
            self.logger.error(e)
            raise
        self.logger.debug('Input delta to search = {0}'.format(delta))
        timestamp = '0000-00-00 00:00:00'
        try:
            log_file = open(logfile_path, 'r').read()
        except Exception as e:
            self.logger.error(e)
            raise
        for match in re.finditer(self.regex_timestamp, log_file):
            timestamp = match.group()
        self.logger.debug('Last timestamp matched in the log file = {0}'.format(timestamp))
        date_format_str = '%Y-%m-%d %H:%M:%S'
        self.logger.debug('Getting date time object from given timestamp')
        try:
            from datetime import datetime
            given_time = datetime.strptime(timestamp, date_format_str)
        except Exception as e:
            self.logger.error(e)
            raise
        try:
            from datetime import timedelta
            final_time = given_time - timedelta(minutes=delta)
        except Exception as e:
            self.logger.error(e)
            raise
        date = str(final_time.date())
        time = str(final_time.time())
        return date, time

    def __cache(self, file_name = None, erase = False):
        """
        Utility function to clear the cache files created during the current use
        of the DNAC Debugger

        :return:    None
        """
        cache_dir = self.__cache_dir
        if file_name is not None:
            self.cache_list.append(file_name)

        if erase:
            for file in self.cache_list:
                os.remove(os.path.join(cache_dir, file))
            self.cache_list.clear()
            self.logger.debug('Cache cleared.')

    def _exit(self):
        """
        Helper function to exit the debugger with an exit message

        :return:    None
        """
        self.__cache(erase = True)
        self.logger.debug('Exiting the DNAC Debugger')
        print('\n' + 'Thank you for using the DNAC Debugger'.center(60, ' ').center(80, '*'))
        exit()

    def _devDeb(self):
        """
        Helper function to perform device logs collection

        :return:    None
        """
        device_uids, device_ips = self.__get_device_uids()
        cmds = self._get_debug_cmds(device_ips)
        self.logger.debug('Device IP: {0}'.format(device_ips))
        self.logger.debug('Device UUID: {0}'.format(device_uids))
        self.logger.debug('Commands: {0}'.format(cmds))

        outputs = []
        
        for (device_uid, commands) in zip(device_uids, cmds):
            data={'name':'command-runner', 'description':'command-runner-network-poller', 
                        'deviceUuids':[device_uid], 'commands':commands}
            self.logger.debug(data)
            try:
                response = self.dnac.call_api(method = 'POST', resource_path = '/v1/network-device-poller/cli/read-request', data = data)
            except Exception as e:
                self.logger.error(e)
                raise
            taskresult = self._wait_for_task_complete(response['response']['taskId'])
            if taskresult['isError']:
                self.logger.error('Error while performing the commands on the given devices')
                self.logger.error(response)
                raise
            fileid = json.loads(taskresult['progress'])['fileId']
            success, response = self.__get_response_from_dnac('/v1/file/{0}'.format(fileid))
            self.logger.debug(success)
            self.logger.debug(response)
            assert success is True
            outputs.append(response[0])
        
        self.__show_cmd_results(device_ips, outputs)
        self._exit()
    
    def __get_device_uids(self):
        """
        Utility function to get the devices IPs and UIDs for performing logs collection

        :return:    List of Devices UIDS and list of device IPs
        :rtype:     List[str], List[str]
        """
        device_list = []

        print('\n' + '*'*80 + '\n')
        ips = input('## Enter IP address(es) of device(s) (separated by a comma [Eg.: 204.1.2.3, 204.1.2.4]):\n>> ')
        for deviceip in ips.split(','):
            deviceip = deviceip.strip()
            device_list.append(deviceip)
        self.logger.debug('Input IPs = {0}'.format(device_list))

        device_ips = []
        device_uids = []
        for deviceip in device_list:
            url = '/v1/network-device/ip-address/{0}'.format(deviceip)
            self.logger.debug('URL = {0}'.format(url))
            success, response = self.__get_response_from_dnac(url)
            self.logger.debug('Success = {0}, Response = {1}'.format(success, response))
            if success is True:
                devid = response['response']['id']
                device_ips.append(deviceip)
                device_uids.append(devid)
            else:
                print(COL_YELLOW + 'Device IP = {0} not present in DNAC... Skipping this Device IP'.format(deviceip) + COL_ENDC)

        self.logger.debug('Avaialble Device IPs = {0}'.format(device_ips))
        self.logger.debug('Available Device UIDs = {0}'.format(device_uids))

        return device_uids, device_ips

    def _get_debug_cmds(self, deviceips):
        """
        Helper function to get the commands to be executed on the devices

        :param deviceips List[str]: List of device IPs on which the commands will be executed

        :return:    List of commands to be exceuted on each corresponding device in the deviceips
        :rtype:     List[List[str]]
        """
        title = 'DNAC Device level debugger'
        options = ['Perform role-based area debugging', 'Execute area debugging commands', 'Manually input specific command(s)']
        choice = self._screen(title, options)
        self.logger.debug('Chosen option = {0}'.format(options[choice]))

        commands = []
        if choice is 0:
            device_roles = self.__get_device_roles(deviceips)
            commands = self.__get_role_based_commands(device_roles)
        elif choice is 1:
            cmds = self.__get_area_cmds()
            commands = [cmds] * len(deviceips)
        elif choice is 2:
            cmds = self.__get_device_cmds()
            commands = [cmds] * len(deviceips)
        
        return commands
    
    def __get_device_cmds(self):
        """
        Utility function to manually input the commands to be executed for device debugging

        :return:    Commands to be executed
        :rtype:     List[str]
        """
        commands = []
        print('\n' + '*'*40 + '\n')
        
        cmds = input('## Enter command(s) (separated by a comma [Eg.: show version, show logs]):\n>> ')
        for cmd in cmds.split(','):
            cmd = cmd.strip(' ')
            commands.append(cmd)
            
        self.logger.debug('Commands to be executed = {0}'.format(commands))
        return commands

    def __get_area_cmds(self):
        """
        Utility function to get area commands for device debugging without role based reference

        :return:    Commands to be executed
        :rtype:     List[str]
        """
        try:
            area_cmds_file = open(AREA_COMMANDS, 'r')
        except Exception as e:
            self.logger.error('area_cmds.yaml file not found')
            self.logger.error(e)
            raise
        try:
            area_cmds = yaml.safe_load(area_cmds_file)
        except Exception as e:
            self.logger.error('Unable to convert the file into a readble yaml file')
            self.logger.error(e)
            raise
        
        title = 'DNAC Device Debugger Area Commands'
        options = list(area_cmds['areas'].keys())
        choice = self._screen(title, options)
        self.logger.debug('Chosen area = {0}'.format(options[choice]))
        return area_cmds['areas'][options[choice]]
        
    def __get_role_based_commands(self, device_roles):
        """
        Utility function to get the commands to be executed based on device roles and the area

        :param device_roles List[str]:  List of device roles for which commands need to be ascertained

        :return:    Commands to be executed for corresponding device role
        :rtype:     List[List[str]]
        """
        try:
            area_cmds_file = open(ROLE_BASED_AREA_COMMANDS, 'r')
        except Exception as e:
            self.logger.error('area_cmds.yaml file not found')
            self.logger.error(e)
            raise
        try:
            area_cmds = yaml.safe_load(area_cmds_file)
        except Exception as e:
            self.logger.error('Unable to convert the file into a readble yaml file')
            self.logger.error(e)
            raise
        title = 'DNAC Device Debugger Areas'
        options = list(area_cmds['areas1'].keys())
        choice = self._screen(title, options)
        area = options[choice]
        self.logger.debug('Chosen area = {0}'.format(area))
        cmds = []
        for role in device_roles:
            commands = []
            for item in area_cmds['areas1'][area]:
                if role in item['role']:
                    commands = item['CLIS']
            self.logger.debug('Device Role = {0}, Commands = {1}'.format(role, commands))
            cmds.append(commands)

        return cmds

    def __get_device_roles(self, deviceips):
        """
        Utility function to find the device roles useing the device IPs

        :param deviceips List[str]: List of Device IPs for which the roles are to be found

        :return:    List of device roles corresponding to each device IP in the deviceips list
        :rtype:     List[str]
        """
        device_roles = []
        
        for deviceip in deviceips:
            url = '/v1/network-device/ip-address/{0}'.format(deviceip)
            self.logger.debug(url)
            success, response = self.__get_response_from_dnac(url)
            if success:
                response = response['response']
                device_roles.append(response['role'])
            else:
                self.logger.error('Failure in getting response from DNAC API')
                self.logger.error('Device IP = {0}, Response = {1}'.format(deviceip, response))
                raise
        
        return device_roles
    
    def __get_response_from_dnac(self, res_path):
        """
        Utility function to perform a GET REST API call to DNAC and return the response

        :param res_path str: Resource path or URL of the GET API call to be made

        :return:    Response succesfully received, Response received
        :rtype:     bool,  Dict[Dict[str]]
        """
        try:
            response = self.dnac.call_api(method = 'GET', resource_path = res_path)
        except Exception as e:
            self.logger.error('Error while getting the response from DNAC API at path = {0}'. format(res_path))
            self.logger.error(e)
            return False, None
        self.logger.debug('GET Response received from DNAC for path = {0}'.format(res_path))
        return True, response

    def __get_task_by_id(self, taskId):
        """
        Utility function to get the response for the task and return it

        :param taskId str:  Id of the task for which response is to  be returned

        :return:    Response for the task
        :rtype:     Dict[Dict[str]]
        """
        url = '/v1/task/{0}'.format(taskId)
        success, res = self.__get_response_from_dnac(url)
        if success is True:
            return res['response']
        else:
            return None
    
    def __is_task_failed(self, task_response):
        """
        Utility function to check whether the task failed to execute successfully

        :param task_response Dict[str]: Response to be checked

        :return:    Return true if error, else return false
        :rtype:     bool
        """
        assert task_response is not None
        return task_response['isError'] is True

    def __is_task_success(self, task_response, error_codes=[]):
        """
        Utility function to check whether the task response is sucess

        :param task_response Dict[str]: Response to be checked
        :param error_codes List[str]:   Error codes

        :return:    Return true if successful, else return false
        :rtype:     bool
        """
        result=True
        assert task_response is not None
        for error_code in error_codes:
            if error_code is not None and hasattr(task_response, 'errorCode') and error_code == task_response['errorCode']:
                return True
        is_not_error = task_response['isError'] is None or task_response['isError'] is False
        is_end_time_present = task_response.get('endTime') is not None
        result = is_not_error and is_end_time_present
        if result:
            self.logger.debug('Task completed with result:{0}'.format(result))
        return result

    def _wait_for_task_complete(self, task_id = None, timeout=120):
        """
        Helper function to wait for the task to be exceuted on the DNAC server

        :param task_id str: ID of the task which is being executed
        :param timeout int: Time interval for max waiting. Default = 120 seconds

        :return:    Response of the task
        :rtype:     Dict[Dict[str]] 
        """ 
        TASK_COMPLETION_POLL_INTERVAL = 2

        assert task_id is not None
        task_completed = False
        import time
        start_time = time.time()
        task_response = None

        while not task_completed:
            if time.time() > (start_time + timeout):
                assert False, ('Task {0} didn\'t complete within {1} seconds'.format(task_response, timeout))
            task_response = self.__get_task_by_id(task_id)
            self.logger.debug(task_response)
            if self.__is_task_success(task_response) or self.__is_task_failed(task_response):
                task_completed = True
            else:
                self.logger.debug('Task not completed yet, waiting:{0}'.format(task_response))
                time.sleep(TASK_COMPLETION_POLL_INTERVAL)
        return task_response

    def __show_cmd_results(self, device_ips, output):
        """
        Utility function to save the device logs into a text file

        :param device_ips List[str]:    List of device IPs on which the commands were executed
        :param output List[Dict[str]]:  List of all commands executed and there responses 
                                        corresponding to the device IP

        :return:    None
        """
        result = []
        result.append('='*80 + '\n')
        for i in range(0, len(device_ips)):
            result.append('Device IP = {0}\n'.format(device_ips[i]))
            result.append('='*80 + '\n')
            res = output[i]
            for key in res['commandResponses'].keys():
                for cmd in res['commandResponses'][key].keys():
                    result.append('>>> Command: {0}, Response = {1}\n'.format(cmd, key))
                    for line in res['commandResponses'][key][cmd].split('\n'):
                        result.append('   ... ' + line + '\n')
                    result.append('   ' + '*'*40 + '\n')
            result.append('\n')
            result.append('='*80 + '\n')
        
        file_name = 'dnac_device_cmd_res.txt'
        try:
            with open('' + file_name, 'w') as f:
                for item in result:
                    f.write(item)
            f.close()
        except Exception as e:
            self.logger.error(e)
            raise
        self.logger.debug('Cmd responses saved as {0}'.format(file_name))
        print(COL_YELLOW + 'Cmd responses saved as {0}'.format(file_name) + COL_ENDC)
        

# add the following as the absolute last block in your testscript
if __name__ == '__main__':
    # control the environment
    # eg, change some log levels for debugging
    deb = DNAC_Debugger(interface_cli=True)
    deb._home()