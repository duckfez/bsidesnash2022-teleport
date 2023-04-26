#!/usr/bin/python3

"""
docstring
"""

import sys
import os
import logging
import pwd
import subprocess

USERADD='/usr/sbin/useradd'
ID='/usr/bin/id'
GPASSWD='/usr/bin/gpasswd'

# Users that this script should ignore
USERS_TO_SKIP = [ 'root', 'centos', 'ec2-user', 'ubuntu' ]

# Teleport roles are mapped to unix groups
ROLES_TO_GROUPS_MAP = {
    "access"     : [ "teleport" ],
    "group_wheel" : [ "teleport", "wheel" ],
}

ALL_GROUPS = []
for k in ROLES_TO_GROUPS_MAP.keys():
    for item in ROLES_TO_GROUPS_MAP.get(k):
        if item not in ALL_GROUPS:
            ALL_GROUPS.append(item)


def create_user(username):
    """
    Create the user using native OS tools, if the user does not exist already.
    Returns the username if the user already existed or was created.
    Returns None on the event of an error during useradd
    """
    try:
        pwd.getpwnam(username)
    except KeyError:
        logging.debug('user %s does not exist',username)
        result = subprocess.run([ USERADD, "-m", username ],
                                check=False,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        logging.debug("useradd result code=%d", result.returncode)
        if result.returncode != 0:
            logging.error("useradd for %s failed with rc=%d", username, result.returncode)
            logging.debug("useradd stdout: %s", result.stdout.decode('utf-8', errors='replace'))
            logging.debug("useradd stderr: %s", result.stderr.decode('utf-8', errors='replace'))
            return None

    return username


def get_groups_for_user(username):
    """
    Get the list of supplemental groups for a given user.  Uses native OS tools (id) as a
    child instead of trying to deal with all of the complexities of sssd and etc
    """

    result = subprocess.run([ID, "-Gn", username],
                            check=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    logging.debug("id result code=%d", result.returncode)
    if result.returncode == 0:
        groupstring = result.stdout.decode('utf-8', errors='replace')
        grouplist = groupstring.split()

        result = subprocess.run([ID, "-gn", username],
                                 check=True,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        if result.returncode == 0:
            pgrp = result.stdout.decode('utf-8', errors='replace').split()[0]
        else:
            pgrp = ''

        grouplist =  [ x for x in grouplist if x != pgrp ]
        logging.debug("groups for %s = %s", username, repr(grouplist))
        return grouplist
    else:
        return []

def add_groups_to_user(username,groups):
    """
    Adds group(s) to user, shelling out to gpasswd
    """

    for g in groups:
        logging.debug("Adding user=%s to group=%s", username, g)
        result = subprocess.run([ GPASSWD, "-a", username, g],
                                check=False,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        logging.debug("gpasswd rc=%d", result.returncode)
        if result.returncode != 0:
            logging.error("Error calling gpasswd - %s",
                        result.stdout.decode('utf-8', errors='replace'))

def remove_groups_from_user(username,groups):
    """
    Removed groups from user, shelling out to gpasswd
    """

    for g in groups:
        logging.debug("Removing user=%s from group=%s", username, g)
        result = subprocess.run([ GPASSWD, "-d", username, g],
                                check=False,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        logging.debug("gpasswd rc=%d", result.returncode)
        if result.returncode != 0:
            logging.error("Error calling gpasswd - %s",
                        result.stdout.decode('utf-8', errors='replace'))

def dump_env_vars():
    """
    Debug - dump all of the env variables related to teleport
    """
    env_vars={k:v for (k,v) in os.environ.items() if k.startswith('TELEPORT')}
    message='\n'.join(['Teleport environment variables:'] +
                      [ "   "+x+"="+env_vars.get(x) for x in env_vars.keys() ])
    logging.debug(message)


if __name__ == "__main__":
    logging.basicConfig(filename='/var/log/teleport-pam.log',
                        format='%(asctime)s %(process)d %(levelname)s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        level=logging.DEBUG)

    logging.info("Starting teleport_acct")

    dump_env_vars()

    teleport_username=os.environ.get('TELEPORT_LOGIN')
    if teleport_username is None:
        logging.fatal('TELEPORT_LOGIN is not set')
        sys.exit(1)

    if teleport_username in USERS_TO_SKIP:
        logging.debug('Skipping %s because in users_to_skip',teleport_username)
        sys.exit(0)


    teleport_user_roles=os.environ.get('TELEPORT_ROLES','').split()
    logging.debug("TELEPORT_ROLES=%s",repr(teleport_user_roles))
    groups_user_should_have=[]
    for r in teleport_user_roles:
        for g in ROLES_TO_GROUPS_MAP.get(r,[]):
            if g not in groups_user_should_have:
                groups_user_should_have.append(g)

    logging.debug("based on roles, user should have these groups: %s",
                repr(groups_user_should_have))


    # Not sure if this should be a fatal error or not.  Probably should be because
    # if useradd failed to add the user, then there's no telling the current
    # state of the system.
    if create_user(teleport_username) is None:
        sys.exit(1)

    current_groups = set(get_groups_for_user(teleport_username))
    teleport_groups = set(groups_user_should_have)

    groups_to_add = teleport_groups - current_groups
    groups_to_remove = (set(ALL_GROUPS) - groups_to_add - teleport_groups) & current_groups

    logging.debug("all_teleport_groups = %s",set(ALL_GROUPS))
    logging.debug("current_unix_groups = %s", current_groups)
    logging.debug("groups_to_add = %s",groups_to_add)
    logging.debug("groups_to_remove = %s",groups_to_remove)

    add_groups_to_user(teleport_username,groups_to_add)
    remove_groups_from_user(teleport_username,groups_to_remove)

    # TODO:  Add a `chage` call so we can fix password expirations

    sys.exit(0)
