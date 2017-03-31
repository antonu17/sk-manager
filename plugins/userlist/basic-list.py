#!/usr/bin/env python

import os

class UserlistPlugin:
    def __init__(self, plugin_config, debug_callback):
        # Initialize plugin
        self.pluginname = os.path.basename(__file__)
        self.debug = debug_callback
        self.debug(self.pluginname + " says hello!")

        # Initialize configuration
        self.config = {}
        for (i,j) in plugin_config:
            self.config[i] = j

    def get_user_list(self):
        # Main plugin method, called from parent script
        if 'users' in self.config:
            self.debug(self.pluginname + " producing userlist from configuration")
            return self.config['users'].split(',')
        else:
            self.debug(self.pluginname + " 'users' option is not found in configuration")
            return []
