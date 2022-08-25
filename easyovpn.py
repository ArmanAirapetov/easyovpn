import sys
import shlex
import subprocess as sproc
import pexpect
import requests
import argparse
from getpass import getpass
from os.path import exists


EASYRSA_RELEASE_URL = ('https://github.com/OpenVPN/easy-rsa/releases/'
                       'download/v3.1.0/EasyRSA-3.1.0.tgz')
EASYRSA_DIR = 'easyrsa'
EASYRSA_EXE = f'{EASYRSA_DIR}/./easyrsa' 
SERVER_CONFIG_NAME = 'server.conf' 
RESULT_OUTPUT = 'result.txt'
CONFS_DIRNAME = 'confs'
CA_PASSWORD = None

#Vars below can be changed without unpredictable behavior by an user.
PATH_OPENVPN_EXE = '/usr/local/sbin/./openvpn'
VPN_SERVER_NAME = 'vpn_server'
SERVER_ADDRESS = '127.0.0.1'
SERVER_CONFIG = '''
#-------------------- 
#VPN port
port 1194   

#VPN over UDP  
proto udp   

# "dev tun" will create a routed IP tunnel 
dev tun 

#Instead of paths to files there will be inline text of keys, certs, etc. into this file
#ca ca.crt
#cert vpn_server.crt
#key vpn_server.key
#tls-crypt-v2 vpn_server.pem
#dh dh.pem

#network for the VPN   
server 10.8.0.0 255.255.255.0 

push "redirect-gateway autolocal" 

# Maintain a record of client <-> virtual IP address 

# associations in this file.  
ifconfig-pool-persist /var/log/openvpn/ipp.txt

# Ping every 10 seconds and assume client is down if 
# it receives no response in 120 seconds. 
keepalive 10 120 

#cryptographic cipher 
cipher AES-256-GCM 

#avoid accessing certain resources on restart 
persist-key 
persist-tun 

#log of current connections  
status /var/log/openvpn/openvpn-status.log 

#log verbose level (0-9) 
verb 4 

# Notify the client when the server restarts 
explicit-exit-notify 1 
#----------------------------------------- 

'''
CLIENT_CONFIG = (
'''
client
proto udp
dev tun
remote {} 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
#user nobody
#group nobody
verb 3
''')

# https://stackoverflow.com/a/287944/13013448
#################################################
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
#################################################
class RuntimeResult:
    msg_main_step_completed = 'Main step has been completed.'
    def __init__(self, filename):
        self.filename = filename

        file_exists = exists(filename)
        open_mode = None

        if file_exists:
            open_mode = 'r+'
        else:
            open_mode = 'w+'
        self.fileinstance = open(filename, open_mode, encoding='utf8')

    def append(self, msg):
        self.fileinstance.write(msg)

    def message(self, success, process):
        if type(process.args) == list or type(process.args) == tuple:
            process.args = ' '.join(process.args)

        msg = (
                f"Success: {success}\n"
                f"Command: {process.args}\n"
        )
        if not success:
            msg += (
                     f"Error code: {process.returncode}\n"
                     f"Stdout message:\n{process.stdout}\n"
                     f"Stderr message:\n{process.stderr}\n"
            )
        msg += '\n'

        self.append(msg)
    
    def is_main_step_completed(self):
        self.fileinstance.seek(0)
        lines = self.fileinstance.readlines()

        if len(lines) == 0:
            return False

        last_line = lines.pop()
        if last_line == self.msg_main_step_completed:
            return True
        else:
            return False
    
def is_cmd_success(completed_proc):
    if completed_proc.returncode != 0:
        return False
    else:
        return True
    
def to_completed_process(args, returncode, stdout=None, stderr=None):
    asdict = {'stdout':stdout,
              'stderr':stderr,
              'args':args,
              'returncode':returncode}
    return type('', (object,), asdict)()

def get_easyrsa_package():
    easyrsa_archive = requests.get(EASYRSA_RELEASE_URL, allow_redirects=True)
    name_easyrsa_archive = 'easyrsa.tgz'

    with open(name_easyrsa_archive, 'wb') as file:
        file.write(easyrsa_archive.content)

    proc_mkdir = sproc.run(['mkdir', f'{EASYRSA_DIR}'], 
                           stdout=sproc.PIPE, 
                           stderr=sproc.PIPE,
                           encoding='utf8',
                           text=True)
    success = is_cmd_success(proc_mkdir)
    if not success:
        return success, proc_mkdir

    cmd = (f'tar zxvf {name_easyrsa_archive} '
           f'-C {EASYRSA_DIR} --strip-components 1')
    cmd = shlex.split(cmd)
    proc_extract_dir = sproc.run(cmd, 
                                 stdout=sproc.PIPE, 
                                 stderr=sproc.PIPE,
                                 encoding='utf8',
                                 text=True)
    success = is_cmd_success(proc_extract_dir)
    if not success:
        return success, proc_extract_dir

    proc_rm_archive = sproc.run(shlex.split(f'rm {name_easyrsa_archive}'), 
                                stdout=sproc.PIPE, 
                                stderr=sproc.PIPE,
                                encoding='utf8',
                                text=True)
    success = is_cmd_success(proc_rm_archive)
    return success, proc_rm_archive

def mkdir_confs():
    completed = sproc.run(['mkdir', CONFS_DIRNAME])
    return is_cmd_success(completed), completed

def init_pki():
    proc_init_pki = sproc.run([EASYRSA_EXE, 'init-pki'], 
                              stdout=sproc.PIPE, 
                              stderr=sproc.PIPE,
                              encoding='utf8',
                              text=True)

    return is_cmd_success(proc_init_pki), proc_init_pki

def build_ca(password, name="CA"):
    with sproc.Popen([EASYRSA_EXE, 'build-ca'], 
                     stdin=sproc.PIPE,
                     stdout=sproc.PIPE,
                     stderr=sproc.PIPE,
                     encoding='utf8', text=True) as proc_build_ca: 

        input_msg = f'{password}\n{password}\n{name}\n'
        stdout, stderr = proc_build_ca.communicate(input=input_msg) 
        proc_build_ca.wait() 

        completed = to_completed_process(proc_build_ca.args, 
                                         proc_build_ca.returncode,
                                         stdout, stderr)
        return is_cmd_success(proc_build_ca), completed 

def __pass_passwords_when_gen_keys(cmd, password, ca_password):
    completed = None
    try:
        child = pexpect.spawn(cmd)
        child.expect('Enter PEM pass phrase:')
        child.sendline(password)
        child.expect('Verifying - Enter PEM pass phrase:')
        child.sendline(password)
        child.expect('Enter pass phrase for')
        child.sendline(ca_password)
    except pexpect.ExceptionPexpect as e:
        completed = to_completed_process(cmd, 
                                         1, 
                                         stdout=sys.stdout, 
                                         stderr=e.value)
    else:
        completed = to_completed_process(cmd, 0)
    
    return completed

def create_serverkey(password, ca_password, server_filename='vpn_server'):
    cmd = f'{EASYRSA_EXE} build-server-full {server_filename}'
    completed = __pass_passwords_when_gen_keys(cmd, password, ca_password)
    return is_cmd_success(completed), completed

def create_clientkey(password, ca_password, client_filename):
    cmd = f'{EASYRSA_EXE} build-client-full {client_filename}'
    completed = __pass_passwords_when_gen_keys(cmd, password, ca_password)
    return is_cmd_success(completed), completed

def sign_serverkey(ca_password, server_filename='vpn_server'):
    cmd = f'{EASYRSA_EXE} sign-req server {server_filename}'
    completed = None

    try:
        child = pexpect.spawn(cmd)
        child.expect('Confirm request details:')
        child.sendline('yes')
        child.expect('Enter pass phrase for')
        child.sendline(ca_password)
    except pexpect.ExceptionPexpect as e:
        completed = to_completed_process(cmd, 1, e.value, stderr=e.value) 
    else:
        completed = to_completed_process(cmd, 0)

    return is_cmd_success(completed), completed

def generate_dh():
    completed = sproc.run([EASYRSA_EXE, 'gen-dh'])
    return is_cmd_success(completed), completed

def whoami():
    completed = sproc.run('whoami', 
                          stdout=sproc.PIPE, 
                          stderr=sproc.PIPE, 
                          text=True)
    return completed.stdout[:-1] 

def change_owner(path, user, sudo_password):
    cmd = f'sudo -S chown {user}:{user} {path}'
    with sproc.Popen(shlex.split(cmd), 
                     stdin=sproc.PIPE,
                     stdout=sproc.PIPE,
                     stderr=sproc.STDOUT,
                     text=True) as proc:
        stdout, _ = proc.communicate(f'{sudo_password}\n')
        proc.wait()


def generate_tls_crypt_v2_server(filename):
    tls_crypt_filepath = f'pki/private/{filename}.pem'
    cmd = [PATH_OPENVPN_EXE, '--genkey', 
           'tls-crypt-v2-server', tls_crypt_filepath]

    completed = sproc.run(cmd, 
                          stdout=sproc.PIPE, 
                          stderr=sproc.PIPE, 
                          text=True)

    return is_cmd_success(completed), completed

def generate_tls_crypt_v2_client(filename):
    tls_crypt_filepath = f'pki/private/{filename}.pem'
    cmd = (f'{PATH_OPENVPN_EXE} '
           f'--tls-crypt-v2 pki/private/{VPN_SERVER_NAME}.pem '
           f'--genkey tls-crypt-v2-client {tls_crypt_filepath}')
    completed = sproc.run(shlex.split(cmd), 
                          stdout=sproc.PIPE, 
                          stderr=sproc.PIPE, 
                          text=True)

    return is_cmd_success(completed), completed

def repeat_until_correct_password(prompt=None):
    while(True):
        first_pass = None
        if prompt is None:
            first_pass = getpass()
        else:
            first_pass = getpass(prompt)

        repeated_pass = getpass('Repeat password:')
        if first_pass != repeated_pass:
            print('Passwords are not the same. Try again.')
        else:
            return first_pass

def get_file_txt(path):
    with open(path, 'r', encoding='utf8') as fl:
        return fl.read()

def surround_with(tag, text):
    return f'<{tag}>\n{text}</{tag}>\n'

def fill_server_conf(conf_str, path):
    ca = f'pki/ca.crt'
    cert = f'pki/issued/{VPN_SERVER_NAME}.crt'
    key = f'pki/private/{VPN_SERVER_NAME}.key' 
    tls_crypt_v2 =  f'pki/private/{VPN_SERVER_NAME}.pem'
    dh = 'pki/dh.pem'
    
    with open(path, 'w+', encoding='utf8') as conf:
        conf.write(conf_str)
        conf.write(surround_with('ca', get_file_txt(ca)))
        conf.write(surround_with('cert', get_file_txt(cert)))
        conf.write(surround_with('key', get_file_txt(key)))
        conf.write(surround_with('tls-crypt-v2', get_file_txt(tls_crypt_v2)))
        conf.write(surround_with('dh', get_file_txt(dh)))
        conf.flush()
    
#    cmd = ['sudo', '-S', 'cp', SERVER_CONFIG_NAME, '/etc/openvpn/server']
#    completed = sproc.run(cmd)
    ok_msg = f'Created a complete server conf "{path}"'
    completed = to_completed_process(ok_msg, 0)

    return is_cmd_success(completed), completed

def conf_firewall():
    print('Need sudo privilege.')
    sudo_password = repeat_until_correct_password()

    cmd = (
            f"sudo -S sh -c "
            f"'"
            f"iptables -A INPUT -i eth0 -m state "
            f"--state NEW -p udp --dport 1194 -j ACCEPT"
            f"iptables -A INPUT -i tun+ -j ACCEPT"
            f"iptables -A FORWARD -i tun+ -j ACCEPT"
            f"iptables -A FORWARD -i tun+ -o eth0 -m state "
            f"--state RELATED,ESTABLISHED -j ACCEPT"
            f"iptables -A FORWARD -i eth0 -o tun+ -m state "
            f"--state RELATED,ESTABLISHED -j ACCEPT"
            f"iptables -t nat -A POSTROUTING "
            f"-s 10.8.0.0/24 -o eth0 -j MASQUERADE"
            f"iptables -A OUTPUT -o tun+ -j ACCEPT"
            f"'")
    
    with sproc.Popen(shlex.split(cmd), 
                     stdin=sproc.PIPE,
                     stdout=sproc.PIPE,
                     stderr=sproc.PIPE,
                     text=True) as proc:
        stdout, stderr = proc.communicate(f'{sudo_password}\n')
        proc.wait()
        completed = to_completed_process(cmd, proc.returncode, stdout, stderr)
        return is_cmd_success(completed), completed

def generate_client_conf(conf_str, path, client_name):
    ca = f'pki/ca.crt'
    cert = f'pki/issued/{client_name}.crt'
    key = f'pki/private/{client_name}.key' 
    tls_crypt_v2 =  f'pki/private/{client_name}.pem'
    dh = 'pki/dh.pem'

    #To add handling exceptions of calls of methods of a file object.
    with open(path, 'w+', encoding='utf8') as conf:
        conf.write(conf_str)
        conf.write(surround_with('ca', get_file_txt(ca)))
        conf.write(surround_with('cert', get_file_txt(cert)))
        conf.write(surround_with('key', get_file_txt(key)))
        conf.write(surround_with('tls-crypt-v2', get_file_txt(tls_crypt_v2)))
        conf.write(surround_with('dh', get_file_txt(dh)))
        conf.flush()
    
    msg = f'Created "{path}" client conf file that has all the needed data.'
    completed = to_completed_process(msg, 0)
    return is_cmd_success(completed), completed

def if_not_succes_print_exit(success, func_result, client_name):
    msg = (f'{bcolors.FAIL}'
           f'Error:\n'
           f'{bcolors.ENDC}'
           f'Client name: {client_name}\n'
           f'Output:\n'
           f'{func_result.stdout}\n'
           f'Description of error:\n' f'{func_result.stderr}\n') 
    if not success: 
        print(msg) 
        sys.exit(1)

def get_client(client_name, client_password):
    success, func_create_client = create_clientkey(client_password, 
                                                   CA_PASSWORD, 
                                                   client_name)
    if_not_succes_print_exit(success, func_create_client, client_name)

    (success, 
    func_gen_tls_file_client) = generate_tls_crypt_v2_client(client_name)
    if_not_succes_print_exit(success, func_gen_tls_file_client, client_name)

    client_filepath = f'{CONFS_DIRNAME}/{client_name}.ovpn'
    (success, 
     func_gen_client_conf) = generate_client_conf(CLIENT_CONFIG, 
                                                  client_filepath, 
                                                  client_name)
    if_not_succes_print_exit(success, func_gen_client_conf, client_name)

    return client_filepath

def main():
    result.fileinstance.truncate(0)

    success, func_package = get_easyrsa_package()
    result.message(success, func_package)
    if not success:
        sys.exit(1)

    print(f'Creating "{CONFS_DIRNAME}" directory')
    success, func_mkdir_confs = mkdir_confs()
    result.message(success, func_mkdir_confs)
    if not success:
        sys.exit(1)

    print('Creating an certification authority.')
    success, func_pki = init_pki()
    result.message(success, func_pki)        
    if not success:
        sys.exit(1) 

    print('Building a ca master key.') 
    ca_password = repeat_until_correct_password() 
    CA_PASSWORD = ca_password 

    success, func_build_ca = build_ca(ca_password)
    result.message(success, func_build_ca)        
    if not success:
        sys.exit(1) 

    print('Generating a key of a server')
    server_password = repeat_until_correct_password()
    success, func_create_server_key = create_serverkey(server_password, 
                                                       ca_password)
    result.message(success, func_create_server_key)
    if not success:
        sys.exit(1)

    print('Signing the key of the server')
    success, func_sign_serverkey = sign_serverkey(ca_password)
    result.message(success, func_sign_serverkey)
    if not success:
        sys.exit(1)

    print('Generating a Diffie-Hellman file')
    success, func_generate_dh = generate_dh()
    result.message(success, func_generate_dh)
    if not success:
        sys.exit(1) 

    print('Generating a tls-crypt-v2 file of the server.')
    (success,
     func_gen_tls_crypt_server) = generate_tls_crypt_v2_server(VPN_SERVER_NAME)
    result.message(success, func_gen_tls_crypt_server)
    if not success:
        sys.exit(1)

    print('Creating a final conf file of the server')
    path_conf_file = f'{CONFS_DIRNAME}/{SERVER_CONFIG_NAME}'
    (success, 
     func_fill_server_conf) = fill_server_conf(SERVER_CONFIG, 
                                               path_conf_file)
    result.message(success, func_fill_server_conf)
    if not success:
        sys.exit(1)

    result.append(RuntimeResult.msg_main_step_completed)
    
def parse_args():
    global CA_PASSWORD, SERVER_ADDRESS, CLIENT_CONFIG
    description = 'Automization of configuring an openvpn server.'
    parser = argparse.ArgumentParser(description=description)
    help_gc = "Generate N profiles of new clients.\n"
    parser.add_argument('--gen-clients', '-gc', 
                        dest='num_clients',
                        action='store',
                        nargs='?', 
                        type=int, 
                        help=help_gc) 

    help_init = ('Init a ca.\n'
                 'Generate a private key, a cert, a dh file, '
                 'a tls-crypt-v2 file of a server.\n'
                 'Make "server.conf" file.\n')
    parser.add_argument('--init', '-i', 
                        dest='init', 
                        action='store_true', 
                        default=False, 
                        help=help_init)

    help_conf_fwall = ('Configure a firewall to work with an openvpn server.\n'
                       'Need sudo privilege.\n')
    parser.add_argument('--conf-fwall', '-cf',
                        dest='conf_fwall',
                        action='store_true',
                        default=False,
                        help=help_conf_fwall)

    help_address = 'Pass an address of an openvpn server.\n'
    parser.add_argument('--address', '-a',
                        dest='address',
                        action='store',
                        default=None,
                        type=str,
                        help=help_address)

    parsed = parser.parse_args(sys.argv[1:])

    if parsed.address is not None:
        SERVER_ADDRESS = parsed.address
    CLIENT_CONFIG = CLIENT_CONFIG.format(SERVER_ADDRESS)

    if parsed.conf_fwall is True:
        conf_firewall()

    if parsed.init is True:
        if result.is_main_step_completed() is False:
            main()
        else:
            print(f'{bcolors.WARNING}CA exists.{bcolors.ENDC}')

    if result.is_main_step_completed():
        if parsed.num_clients is None:
            err_msg = ('Number of new clients has not been passed with '
                       '"--gen-clients/-gc" argument.')
            print(err_msg)
            sys.exit(1)
        else:
            if parsed.num_clients > 0:
                if CA_PASSWORD is None:
                    msg = ('CA authorization is required. Pls, input password.')
                    CA_PASSWORD = getpass(msg)
                print('Creating profiles of openvpn clients.')
                for i in range(0, parsed.num_clients):
                    client_name = input('Write \'clientname\'.\n')
                    msg = ('A new client\'s password:') 
                    client_password = repeat_until_correct_password(msg)
                    get_client(client_name, client_password)
            else:
                print('Number of clients must be a positive integer.')
                sys.exit(1)
    else:
        error = ('The certificate authority has not been created. '
                 'Use a "-i/--init" command.')
        print(error)
        sys.exit(1)

result = RuntimeResult(RESULT_OUTPUT)

if __name__ == '__main__':
    parse_args()
