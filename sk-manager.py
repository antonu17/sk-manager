#!/usr/bin/env python

from Crypto.Cipher import DES, DES3, AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import MD5
from Crypto.Protocol.KDF import PBKDF1
from Crypto.PublicKey import RSA
import argparse
import base64
import ConfigParser
import getpass
import importlib
import logging as log
import os
import re
import string
import sys
import yaml

DEFAULT_CONFIG_FILE_NAME = 'sk-manager.ini'

def error(msg):
    """
    Produces error message.
    """

    log.error(msg)

def warning(msg):
    """
    Produces warning message.
    """

    log.warning(msg)

def info(msg):
    """
    Produces informational message.
    """

    log.info(msg)

def debug(msg):
    """
    Produces debug message. Only debug messages should be logged from functions.
    """

    log.debug(msg)

def gen_safe_key(length):
    """
    Generates safe secret of given length, suitable to use in cryptography.
    """

    debug("Generating safe secret key")

    chars = string.ascii_letters + string.digits + '!@#$%^&*()_+-='
    random_bytes = os.urandom(length)
    key = ''

    for i in range(0, length):
        key += chars[ord(random_bytes[i]) % len(chars)]

    return key;

def encrypt_string(key, str):
    """
    Encrypts string 'str' with RSA public key 'key'.
    """

    try:
        rsa_key = RSA.importKey(key)
        pkcs1_cipher = PKCS1_OAEP.new(rsa_key)
        return base64.b64encode(pkcs1_cipher.encrypt(str))
    except:
        debug("Failed to encrypt shared secret, possibly public key is invalid or wrong size")
        return None

def decrypt_string(key, str):
    """
    Decrypts string 'str' with RSA private key 'key'.
    """

    try:
        rsa_key = RSA.importKey(key)
        pkcs1_cipher = PKCS1_OAEP.new(rsa_key)
        return pkcs1_cipher.decrypt(base64.decodestring(str))
    except:
        debug('Failed to decrypt shared secret, possibly private key is wrong or invalid')
        return None

def decrypt_pem(pem_data, passphrase):
    """
    Decrypts PKCS#8 or PKCS#1 private key stored in 'pem_data' using 'passphrase'.
    """

    # Verify valid PEM boundaries
    data = pem_data.strip()
    r = re.compile("^-----BEGIN (.*)-----\n")
    if not r.match(data):
        debug('Private key has wrong format')
        return None

    r = re.compile("\n-----END (.*)-----$")
    if not r.search(data):
        debug('Private key has wrong format')
        return None

    # Remove all spaces and split into lines
    lines = data.replace(' ', '').split()

    if lines[1].startswith('Proc-Type:4,ENCRYPTED'):
        # Encrypted PEM, decrypt it
        debug('Decrypting private key')
        if not passphrase:
            debug("PEM is encrypted, but no passphrase specified")
            return None
        dek_info = lines[2].split(':')
        if dek_info[0] != 'DEK-Info' or len(dek_info)!=2:
            debug("Unknown private key encryption algorithm")
            return None
        algo, salt = dek_info[1].split(',')
        salt = salt.decode('hex')

        # Create decryption object, depending on algorithm
        if algo == "DES-CBC":
            key = PBKDF1(passphrase, salt, 8, 1, MD5)
            decrypt_object = DES.new(key, DES.MODE_CBC, salt)
        elif algo == "DES-EDE3-CBC":
            key = PBKDF1(passphrase, salt, 16, 1, MD5)
            key += PBKDF1(key + passphrase, salt, 8, 1, MD5)
            decrypt_object = DES3.new(key, DES3.MODE_CBC, salt)
        elif algo == "AES-128-CBC":
            key = PBKDF1(passphrase, salt[:8], 16, 1, MD5)
            decrypt_object = AES.new(key, AES.MODE_CBC, salt)
        else:
            debug("Unsupported PEM encryption algorithm")
            return None

        # Cut extra text data and leave encrypted private key only
        lines = lines[3:-1]

    else:
        # Not encrypted PEM
        debug('Not decrypting private key')
        decrypt_object = None
        # Cut extra text data and leave unencrypted private key only
        lines = lines[1:-1]

    data = base64.b64decode(''.join(lines))

    # Do actual decrypt now if necessary
    if not decrypt_object is None:
        try:
            data = decrypt_object.decrypt(data)
        except:
            debug('Failed to decrypt private key, possibly passphrase is wrong')

        # Unpad data - warning here! (pkcs#7)
        pad_len = ord(data[-1])
        if pad_len<1 or pad_len>decrypt_object.block_size:
            debug('Wrong private key padding, possibly passphrase is wrong')
            return None
        else:
            data = data[:-pad_len]

    # Reformat private key data to unencrypted PEM format and return it
    return '-----BEGIN RSA PRIVATE KEY-----\n' + base64.encodestring(data) + '\n-----END RSA PRIVATE KEY-----'

def lookup_configuration_file():
    """
    Search for configuration file in environment variable and known locations.
    """

    if 'SK_MANAGER_CONFIG' in os.environ:
        debug('Using environment variable to get configuration file location')
        return os.environ['SK_MANAGER_CONFIG']
    elif os.path.exists(DEFAULT_CONFIG_FILE_NAME):
        debug('Using configuration file found in current working directory')
        return DEFAULT_CONFIG_FILE_NAME
    elif os.path.exists(os.path.join(os.path.dirname(os.path.realpath(__file__)), DEFAULT_CONFIG_FILE_NAME)):
        debug('Using configuration file found in script directory')
        return os.path.join(os.path.dirname(os.path.realpath(__file__)), DEFAULT_CONFIG_FILE_NAME)
    else:
        debug("Could not find configuration file in known locations")
        return None

def init_directory_plugin(plugin_name, config):
    """
    Load and instantiate directory plugin.
    """

    try:
        directory_plugin = importlib.import_module(plugin_name)
        DirectoryPlugin = getattr(directory_plugin, 'DirectoryPlugin')
    except Exception as e:
        debug("Directory plugin load failure: " + e.message)
        return None
    return DirectoryPlugin(config, debug)

def init_userlist_plugin(plugin_name, config):
    """
    Load and instantiate userlist plugin.
    """

    try:
        userlist_plugin = importlib.import_module(plugin_name)
        UserlistPlugin = getattr(userlist_plugin, 'UserlistPlugin')
    except Exception as e:
        debug("Userlist plugin load failure: " + e.message)
        return None
    return UserlistPlugin(config, debug)

def get_private_key(private_key_path):
    """
    Load private key and decrypt it if necessary.
    """

    if not os.path.exists(private_key_path):
        debug("Private key file does not exists (" + private_key_path + ")")
        return None

    private_key_data = open(private_key_path, 'r').read()
    if 'ENCRYPTED' in private_key_data:
        debug("Looks like private key is encrypted, request passphrase from user")
        # Input key passphrase from user
        passphrase = getpass.getpass('Enter secret key password: ', sys.stderr)
    else:
        passphrase = None

    return decrypt_pem(private_key_data, passphrase)

def get_public_keys(userid, directory_plugin, no_cache):
    """
    Looks for user public keys.
    """
    return directory_plugin.get_keys(userid)

def load_vault(path):
    """
    Loads vault from file.
    """
    debug("Loading vault from " + path)
    try:
        stream = open(path, 'r')
        return yaml.load(stream)
    except Exception as e:
        debug("Failed to load vault: " + e.message)
        return {}

def save_vault(path, vault):
    """
    Saves vault into file.
    """
    try:
        with open(path, 'w') as vaultfile:
            yaml.dump(vault, vaultfile, default_flow_style=False, indent=4)
    except Exception as e:
        debug("Failed to save vault: " + e.message)
        return False
    return True

def main():
    """
    Main entrypoint.
    """

    # Initialize command line parser
    parser = argparse.ArgumentParser(description='shared key manager')
    parser.add_argument('--config', '-c', action='store', help='configuration file path')
    parser.add_argument('action', choices=['init', 'update', 'show'])
    parser.add_argument('--verbose', '-v', action='count', help='verbosity level', default=0)
    parser.add_argument('--no-cache', '-n', action='store_true', help='do not use cache for public keys', default=False)
    args = parser.parse_args(sys.argv[1:])

    # Initialize global logging according to desired verbosity level
    if args.verbose == 0:
        log_level = log.WARNING
    elif args.verbose == 1:
        log_level = log.INFO
    else:
        log_level = log.DEBUG

    log.basicConfig(format="%(levelname)s: %(message)s", level=log_level)

    # Find configuration file
    if args.config != None:
        debug("Using configuration file specified in command line options")
        config_path = args.config
    else:
        debug("Trying to find configuration file")
        config_path = lookup_configuration_file()

    # Parse configuration file if it is there
    config = ConfigParser.ConfigParser()
    if config_path is None or not os.path.isfile(config_path):
        error("Configuration file not found!")
        # Well, that looks fatal
        sys.exit(1)
    else:
        info("Reading configuration file " + config_path)
        try:
            config.read(config_path)
        except Exception as e:
            error("Configuration file read failure: " + e.msg)
            # Well, that looks fatal
            sys.exit(1)

    # Get script and configuration file locations for future use
    script_dir = os.path.dirname(os.path.realpath(__file__))
    config_dir = os.path.dirname(os.path.realpath(config_path))

    # Load directory plugin
    info("Loading directory plugin")
    sys.path.append(os.path.join(script_dir, 'plugins', 'directory'))
    directory_plugin_name = config.get('plugins', 'directory')
    if config.has_section(directory_plugin_name):
        directory_plugin_config = config.items(directory_plugin_name)
    else:
        directory_plugin_config = []
    directory_plugin_config.append(('config_dir', config_dir))
    directory_plugin = init_directory_plugin(directory_plugin_name, directory_plugin_config)
    if directory_plugin is None:
        error("Failed to load directory plugin")
        # Well, that looks fatal
        sys.exit(1)

    # Load userlist plugin
    info("Loading userlist plugin")
    sys.path.append(os.path.join(script_dir, 'plugins', 'userlist'))
    userlist_plugin_name = config.get('plugins', 'userlist')
    if config.has_section(userlist_plugin_name):
        userlist_plugin_config = config.items(userlist_plugin_name)
    else:
        userlist_plugin_config = []
    userlist_plugin_config.append(('config_dir', config_dir))
    userlist_plugin = init_userlist_plugin(userlist_plugin_name, userlist_plugin_config)
    if userlist_plugin is None:
        error("Failed to load userlist plugin")
        # Well, that looks fatal
        sys.exit(1)

    # Create empty dictionary for user public keys
    public_keys = {}

    # We need to read and decrypt private key if we want to show or update PSK
    if args.action == 'show' or args.action == 'update':
        my_private_key = get_private_key(os.path.abspath(os.path.join(config_dir, os.path.expanduser(config.get('global', 'my_private_key')))))
        if my_private_key is None:
            error("Failed to load private key")
            # Well, that looks fatal
            sys.exit(1)

    # We need to get user list and appropriate public keys if we want to initialize or update vault
    if args.action == 'init' or args.action == 'update':
        users = userlist_plugin.get_user_list()
        if len(users)==0:
            error("Userlist plugin didn't return any users")
            # Well, that looks fatal
            sys.exit(1)

        for user in users:
            user_keys = get_public_keys(user, directory_plugin, args.no_cache)
            if len(user_keys)==0:
                warning("Couldn't find any keys for user " + user)
            else:
                public_keys[user] = user_keys

    # For almost everything we need your username
    if config.get('global', 'username_mode') == 'env' and config.get('global', 'username') in os.environ:
        my_username = os.environ[config.get('global', 'username')]
    elif config.get('global', 'username_mode') == 'config':
        my_username = config.get('global', 'username')
    else:
        my_username = ''

    # Now fail if we could not get username at all, or it is there but empty
    if len(my_username)==0:
        error("Could not get your username")
        # Well, that looks fatal
        sys.exit(1)

    # Get vault file path
    vault_path = os.path.abspath(os.path.join(config_dir, os.path.expanduser(config.get('global', 'vault'))))

    if args.action == 'init':
        # Generate a new safe secret
        secret = gen_safe_key(config.getint('global', 'secret_length'))
    elif args.action == 'show' or args.action == 'update':
        # Load secret from vault

        # Load vault first
        vault = load_vault(vault_path)
        if len(vault)==0:
            error("Vault file is missing or corrupted. You probably should re-init it.")
            # Well, that looks fatal
            sys.exit(1)

        if not my_username in vault:
            error("I don't see you in vault file. Probably username is wrong.")
            # Well, that looks fatal
            sys.exit(1)

        # Now, get secret from vault
        found_secret = False
        for chunk in vault[my_username]:
            s = decrypt_string(my_private_key, chunk['data'])
            if not s is None:
                found_secret = True
                secret = s
        if not found_secret:
            error("Could not find secret in vault file.")
            # Well, that looks fatal
            sys.exit(1)

    # Now, do the stuff
    if args.action == 'show':
        print(secret)
    elif args.action == 'init' or args.action == 'update' :
        if not my_username in public_keys:
            warning("I don's see you in list of users. You are very unlikely to update or read generated vault file.")

        # Reset vault, and fill it with updated values
        vault = {}
        for user in public_keys:
            info("Encrypting secret for " + user)
            vault[user] = []
            for key in public_keys[user]:
                encrypted_secret = encrypt_string(key, secret)
                vault[user].append({ 'key': key, 'data': encrypted_secret })

        # Finally, save vault
        info("Saving vault to " + vault_path)
        if not save_vault(vault_path, vault):
            error("Failed to save vault!")
            # Well, that looks fatal
            sys.exit(1)

if __name__ == "__main__":
    main()
