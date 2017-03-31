#!/usr/bin/env python

import os
import yaml

# from pyasn1.codec.der import encoder
# from pyasn1.type import univ
# import base64
# import rsa
# import struct

class DirectoryPlugin:
    def __init__(self, plugin_config, debug_callback):
        # Initialize plugin
        self.pluginname = os.path.basename(__file__)
        self.debug = debug_callback
        self.debug(self.pluginname + " says hello!")

        # Initialize configuration
        self.config = {}
        for (i,j) in plugin_config:
            self.config[i] = j

        # Initialize keys directory
        self.keys = {}

    def parse_hf_users(self, path):
        # Walkthrough and extract ssh public keys from hf-users directory structure. Called only once.
        self.debug(self.pluginname + " gathering hf-users ssh keys")

        for root, dirs, files in os.walk(path):
            if os.path.basename(root).startswith('users-'):
                for file in files:
                    filename = os.path.join(root, file)
                    try:
                        if os.path.isfile(filename) and not os.path.islink(filename):
                            stream = open(filename, 'r')
                            yamldata = yaml.load_all(stream)
                            for yamlobject in yamldata:
                                for (username,userdata) in yamlobject.items():
                                    if 'keys' in userdata:
                                        for key in userdata['keys']:
                                            if not username in self.keys:
                                                self.keys[username] = []
                                            self.keys[username].append(key['key'])
                    except:
                        self.debug(self.pluginname + " failed to read user data from " + file)

        self.debug(self.pluginname + " finished gathering hf-users ssh keys")

    def get_keys(self, userid):
        # Main plugin method, called from parent script

        self.debug(self.pluginname + " retrieving keys for " + userid)

        if len(self.keys) == 0:
            # First call to function, need to fill key database
            hf_users_dir = os.path.abspath(os.path.join(self.config['config_dir'], os.path.expanduser(self.config['path'])))
            self.parse_hf_users(hf_users_dir)

        user_keys = []

        if not userid in self.keys:
            self.debug(self.pluginname + " user '" + userid + "' is not in database")
        else:
            for key in self.keys[userid]:
                if key.split(None)[0] == 'ssh-rsa':

                    # As far as pycrypto-2.6.1 is installed, we don't need to do heavy lifting here.

                    user_keys.append(key)

                    # keydata = base64.b64decode(key.split(None)[1])
                    # parts = []
                    #
                    # while keydata:
                    #     dlen = struct.unpack('>I', keydata[:4])[0]
                    #     data, keydata = keydata[4:dlen+4], keydata[4+dlen:]
                    #     parts.append(data)
                    #
                    # e = eval('0x' + ''.join(['%02X' % struct.unpack('B', x)[0] for x in parts[1]]))
                    # n = eval('0x' + ''.join(['%02X' % struct.unpack('B', x)[0] for x in parts[2]]))
                    #
                    # pkcs1_seq = univ.Sequence()
                    # pkcs1_seq.setComponentByPosition(0, univ.Integer(n))
                    # pkcs1_seq.setComponentByPosition(1, univ.Integer(e))
                    #
                    # encoded_string = base64.encodestring(encoder.encode(pkcs1_seq))
                    # pem_data = ('-----BEGIN RSA PUBLIC KEY-----\n{0}\n-----END RSA PUBLIC KEY-----').format(encoded_string)

                    # user_keys.append(pem_data)

        return user_keys
