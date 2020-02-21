#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020 Chip Copper <chip.copper@broadcom.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: brocade_initial_pw_setup
short_description: This module changes the default passwords after a clean install or firmware upgrade
description:
    - After certain levels of FOS upgrades or with new switch installations,
    - it is mandatory that the default passwords for the admin, user,
    - and optionally the root accounts be changed.  This module
    - accomplishes that task.  It should only be used under these circumstances
    - and cannot be used as a general password management module.
    - The module will attempt to log into a switch using the default accounts and
    - passwords.  If this login is not successful, the module will fail
    - indicating that the passwords have already been changed from the
    - factory defaults and so the operation is not necessary.
    - Before this module can be used to change the root password, the admin
    - account must be used to enable root access.  This can be accomplished
    - by using the commands:
    -     userconfig --change root -e yes
    -     rootaccess --set all
    - This is illustrated in the example playbook below using the
    - brocade_fos_command module.
    - If the root_only flag is not set, the new_admin_password and new_user_password
    - variable values are mandatory.  If root_only is not set, only the
    - new_root_password variable value is necessary.
version_added: "1.0"
author: "Chip Copper (chip.copper@broadcom.com)""
options:

    switch_address:
        description:
            - IP address or logical name of the switch to be managed.
        required: True
    new_admin_password:
        description:
            - New password for the admin account.
        required: False
    new_user_password:
        description:
            - New password for the user account.
        required: False
    new_root_password:
        description:
            - New password for the root account.
        required: False
    root_only:
        description:
            - Boolean flag indicating that the root password is to be changed rather than admin and user.
        required: False
    global_timeout:
        description:
            - Overall expected timeout value for the CLI session in seconds.
        required: False
        default: 15
'''

EXAMPLES = '''
    - name: change admin and root default password
      brocade_initial_pw_setup:
        switch_address: "{{fos_ip_addr}}"
        new_admin_password: "{{new_admin_password}}"
        new_user_password: "{{new_user_password}}"

    - name: enable root command using a different module included for reference
      brocade_fos_command:
        switch_login: "admin"
        switch_password: "{{new_admin_password}}"
        switch_address: "{{fos_ip_addr}}"
        command_set:
          - command: userconfig --change root -e yes
          - command: rootaccess --set all
            prompts:
            - question: Please confirm to proceed
              response: "yes"

    - name: change root default password
      brocade_initial_pw_setup:
        switch_address: "{{fos_ip_addr}}"
        new_root_password: "{{new_root_password}}"
        root_only: True

'''

RETURN = '''
messages:
    description: Log of the terminal session.
    returned: always
    type: list
    sample: 
    - "Enter new password: ",
    - "Re-type new password: ",
    - "passwd: all authentication tokens updated successfully",
    - "Please change passwords for switch default accounts now.",
    - "for user - user",
    - "Changing password for user",
    - "Enter new password: ",
    - "Re-type new password: ",
    - "passwd: all authentication tokens updated successfully",
    - "Saving passwords to stable storage.",
    - "Passwords saved to stable storage successfully",


'''
import sys
import time
import socket
import paramiko
from ansible.module_utils.basic import AnsibleModule

def open_shell(module, ip_address, username, password, hostkeymust, messages, globaltimeout):
    changed = False
    failed = False
    messages.append("")
    messages.append("SSH into " + ip_address)
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    if not hostkeymust:
        ssh.set_missing_host_key_policy(paramiko.client.WarningPolicy())
    try:
        ssh.connect(ip_address, username=username, password=password, timeout=globaltimeout)
    except paramiko.ssh_exception.AuthenticationException as e:
        messages.append("invalid name/password")
        messages.append("Skipping due to error: " +  str(e))
        failed = True
        module.fail_json(msg="Invalid login credentials.", messages=messages)
    except Exception as e:
        messages.append("Skipping due to error: " +  str(e))
        failed = True
        module.fail_json(msg="Login error.", messages=messages)
    shell = ssh.invoke_shell()
    shell.settimeout(globaltimeout)
    return ssh, shell, changed, failed


def close_session(ssh_session):
    ssh_session.close()
    return

def send_characters(module, messages, shell, the_characters):
    try:
        shell.send(the_characters)
    except Exception as e:
        messages.append("Exiting due to send error: " +  str(e))
        failed = True
        module.fail_json(msg="Send module failed", messages=messages, failed=failed)
    return

def receive_until_match(module, messages, shell, match_array, exit_array):
    response_buffer = ""
    index = -1

    found = False
    closed = False
    exited = False

    while not found and not closed and not exited:
        try:
            temp_buffer = str(shell.recv(9999))
        except socket.timeout as e:
            messages.append("Exiting due to error: " +  str(e))
            failed = True
            messages.append(response_buffer.split("\r\n"))
            module.fail_json(msg="Receive timeout.", messages=messages, failed=failed)
        response_buffer += str(temp_buffer)
        if len(temp_buffer) == 0:
            closed = True
        for i in range(len(exit_array)):
            if exit_array[i] in response_buffer:
                exited = True
    return index, response_buffer, exited

def cleanup_response(response_buffer):
    response_lines = response_buffer.split("\r\n")
    return response_lines

def main(argv):
    argument_spec = dict(
        switch_password=dict(type='str'),
        switch_address=dict(type='str'),
        new_admin_password=dict(type='str', default="password"),
        new_user_password=dict(type='str', default="password"),
        new_root_password=dict(type='str', default="fibranne"),
        root_only=dict(type='bool', default=False),
        global_timeout=dict(type='int', default=15),
        hostkeymust=dict(type='bool', default=False),
    )
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)
    warnings = list()
    messages = list()

    changed = False
    failed = False

    # Wrangle out the variables
    switch_address = module.params['switch_address']
    new_admin_password = module.params['new_admin_password']
    new_user_password = module.params['new_user_password']
    new_root_password = module.params['new_root_password']
    root_only = module.params['root_only']
    hostkeymust = module.params['hostkeymust']
    global_timeout = module.params['global_timeout']

    # Checks to be sure that the playbook is not supplying defaults again or has missing parameters
    if root_only and (new_root_password == "fibranne"):
            messages.append("The root_only flag is set but the new root password is either missing or has the default value.")
            module.fail_json(msg="Root password missing or default.", messages=messages, failed=failed)

    if not root_only and ((new_admin_password == "password") or (new_user_password == "password")):
            messages.append("The new admin and/or user password is either missing or has the default value.")
            module.fail_json(msg="Admin/user password missing or default.", messages=messages, failed=failed)

    if root_only:
      switch_login = "root"
      switch_password = "fibranne"
    else:
      switch_login = "admin"
      switch_password = "password"

    result = {}
    ssh, shell, changed, failed = open_shell(module, switch_address, switch_login, switch_password,
                                             hostkeymust, messages, global_timeout)

    # If login did not fail, then the login name is indeed the default

    collected_responses = ""
    command_state = {'changed': False, 'failed': False}
    shell.settimeout(global_timeout)
    questions = []
    exit_array = ["Enter old password:", "Enter new password:", "Re-type new password:"]

    prompt_index, response_buffer, exited = receive_until_match(module, messages, shell, questions, exit_array)
    if not root_only:
        # admin password change
        send_characters(module, messages, shell,"password\n")
        prompt_index, response_buffer, exited = receive_until_match(module, messages, shell, questions, exit_array)
        collected_responses += response_buffer
        send_characters(module, messages, shell, new_admin_password + "\n")
        prompt_index, response_buffer, exited = receive_until_match(module, messages, shell, questions, exit_array)
        collected_responses += response_buffer
        send_characters(module, messages, shell, new_admin_password + "\n")
        prompt_index, response_buffer, exited = receive_until_match(module, messages, shell, questions, exit_array)
        collected_responses += response_buffer
        # user password change
        send_characters(module, messages, shell, new_user_password + "\n")
        prompt_index, response_buffer, exited = receive_until_match(module, messages, shell, questions, exit_array)
        collected_responses += response_buffer
        send_characters(module, messages, shell, new_user_password + "\n")
    else:
        # root password change
        send_characters(module, messages, shell,"fibranne\n")
        prompt_index, response_buffer, exited = receive_until_match(module, messages, shell, questions, exit_array)
        collected_responses += response_buffer
        send_characters(module, messages, shell, new_root_password + "\n")
        prompt_index, response_buffer, exited = receive_until_match(module, messages, shell, questions, exit_array)
        collected_responses += response_buffer
        send_characters(module, messages, shell, new_root_password + "\n")
    exit_array.append("Passwords saved to stable storage successfully")
    prompt_index, response_buffer, exited = receive_until_match(module, messages, shell, questions, exit_array)
    collected_responses += response_buffer

    if command_state['changed'] is True:
        changed = True
    if command_state['failed'] is True:
        failed = True
    messages = cleanup_response(collected_responses)
    close_session(ssh)
    #result['stdout'] = show_stdout
    #result['stderr'] = show_stderr
    result['changed'] = changed
    result['failed'] = failed
    result['messages'] = messages
    result['warnings'] = warnings
    # Debugging returns
    #result['command_set'] = command_set
    module.exit_json(**result)

if __name__ == "__main__":
    main(sys.argv[1:])
