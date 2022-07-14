import os
import shutil
import json
import logging
import ipaddress
import tarfile
from services.maglev_cli.maglevclihandler import MaglevSystemCommandLine as MSCL

LOGGER = logging.getLogger(__name__)

ROOT_DIR = '.cache/datadog_script'
OLD_ZIP_PATH = 'dnac_debugger/services/datadog_integration/dnac_dd_agent_v0.2.tgz'
NEW_ZIP_NAME = 'dd_agent_deploy'
NEW_ZIP_DIR = '.cache'
DEST_DIR = './'
DEST_FOLDER = 'dnac_dd_agent_v2.0'

class DatadogIntegration:
    """
    Hello World!
    """
    def __init__(self, node_ip=None, port=2222, admin_username="admin", admin_password="Maglev123", 
                username='maglev', password='Maglev123', interface_cli=False, logger = LOGGER, mscl = None):
        """
        Instantiates logger to get logs for the whole script
        """
        self.logger = logger
        self.logger.info('Log started.')
        self.node_ip = node_ip
        self.port = port
        self.username = username
        self.password = password
        self.admin_username = admin_username
        self.admin_password = admin_password
        self.interface_cli = interface_cli
        self.mscl = mscl

        self.root_dir = ROOT_DIR
        self.old_zip_path = OLD_ZIP_PATH
        self.zip_name = NEW_ZIP_NAME
        self.zip_dir = NEW_ZIP_DIR
        self.zipfile_name = self.zip_name + '.zip'
        self.dest_dir = DEST_DIR
        self.folder_name = DEST_FOLDER

        self.unzip_old_script()

        if mscl is None:
            self._login()
        self.logger.debug('Datadog Integration Object created successfully.')
    
    def unzip_old_script(self):
        """
        Utility function to unzip the old script file

        :return:    None
        """
        try:
            file = tarfile.open(self.old_zip_path, 'r')
        except Exception as e:
            self.logger.error('Error while unzipping the old script')
            self.logger.error(e)
            raise
        for f in file:
            try: 
                file.extract(f, self.root_dir)
            except IOError as e:
                os.remove(os.path.join(self.root_dir,f.name))
                file.extract(f, self.root_dir)
            finally:
                os.chmod(os.path.join(self.root_dir, f.name), f.mode)

    def _get_credentials(self):
        """
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

    def get_cluster_details(self, debugger_obj):
        """
        Class instance to get the cluster hostname and IP address to be used for 
        deployment

        :return:    None
        """
        cluster_ip = self._get_cluster_ip(debugger_obj)
        cluster_hostname = self._get_cluster_hostname(debugger_obj)
        
        self.logger.debug('Cluster credentials loaded successfully!')    
        self._modify_dd_deploy(cluster_ip, cluster_hostname)

    def _get_cluster_ip(self, debugger_obj):
        """
        """
        cluster_ips = []
        self.logger.debug('Fetching Cluster IPs')
        # read VIPs
        try:
            json_file = json.loads(self.mscl.send_cmd('maglev cluster network display -o json'))
        except Exception as e:
            self.logger.error(e)
            raise
        self.logger.debug('Cluster network display JSON file imported successfully.')
        try:
            for vip in json_file['cluster_network']['cluster_vip']:
                cluster_ips.append(vip)
        except Exception as e:
            self.logger.error(e)
            raise
        self.logger.debug('Cluster VIPs fetched successfully.')

        # read node-0 IPs
        try:
            json_file = json.loads(self.mscl.send_cmd('maglev cluster node display -o json'))
        except Exception as e:
            self.logger.error(e)
            raise
        self.logger.debug('Cluster node display JSON file imported successfully.')
        try:
            for item in json_file[0]['network']:
                cluster_ips.append(item['inet']['host_ip'])
        except Exception as e:
            self.logger.error(e)
            raise
        self.logger.debug('Cluster Node-0 IPs fetched successfully.')
        
        title = 'Select DNAC cluster IP address to be used in DD tags'
        choice = debugger_obj._screen(title, cluster_ips)
        cluster_ip = cluster_ips[choice]
        self.logger.debug('Selected IP: {}'.format(cluster_ip))
        return cluster_ip

    def _get_cluster_hostname(self, debugger_obj):
        """
        """
        # Set cluster hostname
        cluster_hostnames = []
        self.logger.debug('Fetching Cluster Hostnames')
        # read from cert FQDN
        try:
            json_file = json.loads(self.mscl.send_cmd('maglev cluster network display -o json'))
        except Exception as e:
            self.logger.error(e)
            raise
        self.logger.debug('Cluster network display JSON file imported successfully.')
        try:
            cluster_hostname_cert = json_file['cluster_network']['cluster_hostname']
        except Exception as e:
            self.logger.error(e)
            raise
        self.logger.debug('Cluster Hostname Cert from FQDN: {}'.format(cluster_hostname_cert))
        if cluster_hostname_cert is not '':
                cluster_hostnames.append(cluster_hostname_cert)
        
        # Perform reverse DNS lookup on the selected cluster IP
        self.logger.debug('Performing reverse DNS lookup on the selected cluster IP')
        try:
            cluster_hostname_dig = self.mscl.send_cmd('dig +noall +answer -x {} | awk -F\'\\t\' \'{sub(/.$/,"",$NF); print $NF}\'')
        except Exception as e:
            self.logger.error(e)
            raise
        self.logger.debug('Cluster Hostname dig from reverse DNS lookup: {}'.format(cluster_hostname_dig))  
        if cluster_hostname_dig is not '':
            cluster_hostnames.append(cluster_hostname_dig)
        cluster_hostnames.append('Enter manually')

        title = 'Select DNAC cluster Hostname to be used in DD tags'
        choice = debugger_obj._screen(title, cluster_hostnames)
        cluster_hostname = cluster_hostnames[choice]
        if cluster_hostname is 'Enter manually':
            self.logger.debug('Getting Cluster hostname manually from user')
            cluster_hostname = input('## Set hostname: ')
        self.logger.debug('Selected cluster hostname: {}'.format(cluster_hostname))
        return cluster_hostname
    
    def _modify_dd_deploy(self, cluster_ip, cluster_hostname):
        """
        Class method to modify dd_deploy script to automatically read 
        cluster IP and cluster hostname

        :param cluster_ip str:          IP address to be used for DNAC Cluster
        :param cluster_hostname str:    Hostname to be used for DNAC Cluster

        :return:    None
        """
        self.logger.debug('DD_Deploy script modification function started.')
        cur_dir = os.path.join(self.root_dir, 'dd_deploy.sh')
        try:
            cur_file = open(cur_dir, 'r').read()
        except Exception as e:
            self.logger.error('Can\'t find dd_deploy script')
            self.logger.error(e)
            raise
        new_file = []
        erase = 0
        for line in cur_file.split('\n'):
            if erase is -1:
                new_file.append('cluster_ip=\''+cluster_ip+'\'')
                new_file.append('cluster_hostname=\''+cluster_hostname+'\'')
                erase = 0
            elif line.find('Select Cluster IP') is not -1:
                erase = 1
            elif line.find('Set cluster hostname') is not -1:
                erase = 2
            elif erase > 0:
                if line.find('done') is not -1:
                    if erase is 1:
                        erase = -1
                    else:
                        erase = 0    
            else:
                new_file.append(line)
        
        for i in range(len(new_file)):
            if new_file[i].find('cluster_ip=') is 0:
                new_file[i] = 'cluster_ip='+cluster_ip
            elif new_file[i].find('cluster_hostname=') is 0:
                new_file[i] = 'cluster_hostname='+cluster_hostname
        
        mod_file = new_file[0]
        for i in range(1,len(new_file)):
            mod_file += '\n' + new_file[i]

        change_file = open(cur_dir, 'w')
        change_file.write(mod_file)
        change_file.close()

    def save_and_zip(self):
        """
        Class method to create the zip file with the modified directory

        :return:    None
        """
        self.logger.debug('Archiving the updated folder...')

        if os.path.exists(os.path.join(self.zip_dir, self.zipfile_name)):
            self.logger.debug('Removing pre-exisiting zip file...')
            os.remove(os.path.join(self.zip_dir, self.zipfile_name))
        else:
            self.logger.debug('No zip file pre-exists')
        
        self.logger.debug('Archiving the Datadog agent deployment directory')
        shutil.make_archive(os.path.join(self.zip_dir, self.zip_name), "zip", self.root_dir) # unable to try except
        self.logger.debug('Datadog agent ZIP archive created successfully.')

    def upload_and_deploy(self):
        """
        Class method to upload the deployment zip file and extract
        and execute its deployment script

        :return:    None
        """
        try:
            self.mscl.send_cmd('cd ' + self.dest_dir)
        except Exception as e:
            self.logger.error('Can\'t find destination path')
            self.logger.error(e)
            raise
        
        self.dnac_cleaner()
        # Upload
        self.logger.debug('Copying deployment zip file to DNAC using MSCL.')
        try:
            self.mscl.copy_file_to_dnac(os.path.join(self.zip_dir, self.zipfile_name), self.dest_dir)
        except Exception as e:
            self.logger.error('Couldn\'t upload deployment archive')
            self.logger.error(e)
            raise
        self.logger.debug('ZIP file copied to DNAC successfully!')
        
        # Unzip and deploy
        try:
            self.mscl.send_cmd('mkdir ' + self.folder_name)
        except Exception as e:
            self.logger.error(e)
            raise
        self.logger.debug('{} folder created on the DNAC server'.format(self.folder_name))
        self.mscl.send_cmd('cd ' + self.folder_name)
        try:
            self.mscl.send_cmd('unzip ../' + self.zipfile_name)
        except Exception as e:
            self.logger.error(e)
            raise
        self.logger.debug('Deployment zip file extracted successfully')
        # Activate script and excecute
        try:
            self.mscl.send_cmd('chmod +x dd_deploy.sh')
        except Exception as e:
            self.logger.error(e)
            raise
        self.logger.debug('Datadog deployment script activated and exceution begins...')
        self.mscl.send_cmd('./dd_deploy.sh', timeout = 120)

    def dnac_cleaner(self):
        """
        """
        for files in self.mscl.send_cmd('ls').split():
            if files == self.zipfile_name:
                self.logger.debug('Pre-exisitng zip file found in DNAC')
                self.logger.debug('Deleting the pre-existing zip file')
                try:
                    self.mscl.send_cmd('rm ' + files)
                except Exception as e:
                    self.logger.error('Failed to delete zip file in DNAC')
                    self.logger.error(e)
                    raise
                self.logger.debug('Zip file deleted successfully!')
            if files == self.folder_name:
                self.logger.debug('Pre-exisitng deployment folder found in DNAC')
                self.logger.debug('Deleting the pre-existing deployment folder')
                try:
                    self.mscl.send_cmd('rm -rfv ' + files)
                except Exception as e:
                    self.logger.error('Failed to delete deployment folder in DNAC')
                    self.logger.error(e)
                    raise
                self.logger.debug('Deployment folder deleted successfully!')