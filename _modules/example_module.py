"""
# Details
Version: 0.2
Purpose: This module runs CLOC on a desired github repository
Last updated: 01/04/2022
By: Michael Roberts

# Background
CLOC counts blank lines, comment lines, and physical lines of source code in many
programming languages. Given two versions of a code base, CLOC can compute differences
in blank, comment, and source lines. It is written entirely in Perl with no dependencies
outside the standard distribution of Perl v5.6 and higher (code from some external
modules is embedded within CLOC) and so is quite portable. CLOC is known to run on
many flavors of Linux. More info on CLOC here: http://cloc.sourceforge.net/

# Usage
## What is accomplished by this module?
This function returns how many lines of code there are in the github repository
of your choosing and outputs the data to a file locally on the salt minion. This
is both a standalone module and a module that can be linked to others.

## What is the expected outcome of this module
This module will pull down the github repo and run cloc against it. The output is in json
format and can be found locally on the minion at /tmp/cloc/<github_repo_name>/<date>.json

This module may take a while to run depending on the size of the repository you
are running CLOC against. You should expect it to take up to 5 minutes before the
json data is saved. This module is compatible with both soarcast and CLI salt interactions.

# Preflight
This module depends on the example_module salt state to be run first.
"""


import logging, sys, os, json, datetime, subprocess, platform

log = logging.getLogger(__name__)

def __virtual__():
    """
    Verify all python dependencies and OS requirements are met
    """
    modules = ['logging','sys','os','json','subprocess','platform']
    HAS_DEPS = False
    if all(mod in str(sys.modules) for mod in modules):
        HAS_DEPS = True
    if HAS_DEPS==False:
        log.error('Missing Python dependencies.')
        return False
    if platform.system()!='Linux':
        log.error('Minion OS does not match module specifications')
        return False
    return True


def run(github_repo_name=None):
    """
    This function downloads a specified github repo and runs it through CLOC
    saving the output as a JSON file in /tmp/cloc/<github_repo_name>/<date>.json

    Pillar Example:
        github_repo_name:   'https://github.com/kubernetes/autoscaler'

    CLI Example:
        *With pillars set:
        salt <minion_name> example_module.run

        *Without pillars set:
        salt <minion_name> example_module.run <github_repo_name>
    """

    # Initialize pillar parameters
    github_repo_name = github_repo_name or __pillar__.get('github_repo_name')

    # Create save filename and ensure that path exists
    folder_name = github_repo_name.split(':')[1].replace('/','').replace('.com','-')
    clock_path = "/tmp/cloc/{}/".format(folder_name)
    save_file_name = clock_path + datetime.datetime.now().strftime('%m-%d-%y') + '.json'
    _ensure_dir_exists(clock_path)

    # Download git repo
    try:
        output = subprocess.check_output(['git', 'clone', github_repo_name, 'git_repo'])
    except Exception as e:
        log.error("Could not clone git repo from {}. \n{}".format(github_repo_name, e))

    # Use CLOC on github repo and save output as /tmp/cloc/<github_repo_name>/<date>.json
    cloc_dir = clock_path + 'git_repo'
    try:
        os.system('cloc ' + cloc_dir + ' --json --out=' + save_file_name + ' --quiet')
    except Exception as e:
        log.error("Could run cloc on dirrectory {}. \n{}".format(cloc_dir, e))

    _validate_json(save_file_name)
    return True


def _ensure_dir_exists(directory_to_check):
    """
    This function creates a directory if it does not already exist and changes
    the working directory to it
    """
    try:
        os.makedirs(directory_to_check, exist_ok=True)
        os.chdir(directory_to_check)
    except Exception as e:
        log.error("Could not create directory {}. \n{}".format(directory_to_check, e))


def _validate_json(jsonData):
    """
    This function validates that anyfile input is formatted correctly in json.
    """
    try:
        json.loads(jsonData)
    except Exception as e:
        log.error("Could not validate json file {}. \n{}".format(jsonData, e))
