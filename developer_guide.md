# Soarcast Developer Guide
_Created by: Michael Roberts_
_Last updated: 01/05/2022_

Creating modules for Soarcast to use in salt is straight forward and this guide will help you along the way to create your own. This documentation will cover standards for the module's functions and readiness state. We will also give you some guidance on how to understand local file structures, scripts and logging when working in salt to alleviate some common salt headaches. If you are familiar with scripting in python, we will be applying the following changes to your script to make it a fully functional Soarcast module.

- Turning your script into properly formatted run(), \_\_virtual\_\_(), and "helper" functions
- Creating a readiness state that ensures all prerequisites are met for your module

# **Functions**
Functions in Soarcast salt modules are split into three groups. The \_\_virtual\_\_() function, which is run automatically by salt before any other function in the module. This ensures that base conditions are met like python libraries, specific OS types, and logging configurations. The run() function gets called from the master and is the central part of the module. Then there are the helper functions which are optional, used locally in the module, and can not be called from outside the module.

\*Note: see _modules/example_module.py to see the whole example module being referenced in this section.

## **module doc string, imports, logging, and the \_\_virtual()\_\_ function**
Before we go and write our Soarcast modules we need to setup the module doc string, imports, logging, and the \_\_virtual\_\_ function. These in conjunction with the readiness state will ensure the module's prerequisites are met before execution of the module.

### module doc string
The module doc string is meant to give the end user an idea of what your module does and how to use it. This doc string is located at the top of the module before any imports. This doc string should be split into details, background, usage, and preflight. The **details** give information on version, date last updated, and who last updated it. The version number is arbitrary, just make sure that it increases on each commit. The **background** gives the end user an understanding of the tool that your module is harnessing. **Usage** explains what is accomplished by the module and what the expected outcomes of the module are. The goal for the Usage section is for the end user to understand how to use this module in conjunction with other modules without getting bogged down in the details. **Preflight** is a list of items to accomplish before trying to run the module. This list will include at a minimum the readiness state for your module. Here is an example of a module doc string:

```
"""
# Details
Version: 0.2
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
```
\*Note: make sure to use '#' to denote each major section and '##' for the minor sections. This is necessary for Soarcast to parse out this doc string for the end user in the app.

### Imports
This is standard python importing nothing fancy. Be sure to put all imported modules together at the beginning. Here's an example:
```
import logging, sys, os, json, datetime, subprocess, platform
```

### Logging
It is necessary to setup logging for Soarcast modules so that the module error handling is caught by the salt minion logs. (These logs can be found on the minion at /var/log/salt/minion and they are picked up by Soarcast) If setup properly, this logging should give feedback to the end user on the status of their module executions. This is especially useful for long running modules. Here's an example:
```
log = logging.getLogger(__name__)
```
\*Note: Python logging integrations like Sentry and Loggly do not interfere with salt logging.
### \_\_virtual\_\_() function
This function can be empty but we recommend that you add in both python module and OS verification. This function is also a good place to setup logging integration if you are using an outside logging solution like Sentry or Loggly. Note that either way you will **need to have this function return true for salt to execute the rest of the module**. A doc string for this function is completely optional. Here's an example:
```
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
```

## **run() function**

### Input Variables
For the input variables in your run() function **be sure to set them as None**. They are set to 'None' so that these values can be pulled in either as positional arguments or as pillars. This ensures the module can be run both as a stand alone salt module and a Soarcast module. Here's an example:
```
def run(github_repo_name=None):
```

### Doc string
Make sure to include a detailed doc string for your run() function. You want to include the full functionality of the module, pillar examples, and how to use it both with and without pillars from the CLI. Here's an Example:
```
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
```

### Pillar definition
In salt, pillars allow confidential, targeted data to be securely sent to specific minions. We make sure that every soarcast module is pillar enabled and able to run both with positional arguments and pillars. Here is an example of how a pillar can be pulled in by a module if it exists:
```
github_repo_name = github_repo_name or __pillar__.get('github_repo_name')
```
\*Note: more information on pillars can be found at https://docs.saltproject.io/en/latest/topics/tutorials/pillar.html


### Error handling
For Soarcast modules we add error handling to each section of the module. This gives the end user information on what failed and where it failed. **Adding a 'return False' statement here will stop the module** and the rest of the module will not run. **This is to be avoided if you are running cleanup scripts at the end of the module**. Here is an example:
```
try:
    output = subprocess.check_output(['git', 'clone', github_repo_name, 'git_repo'])
except Exception as e:
    log.error("Could not clone git repo from {}. \n{}".format(github_repo_name, e))
```

## **_helper functions**
These functions are optional. Helper functions are only accessible from within the module so they cannot be called separately by salt. The doc string for these functions can be minimal. The main thing to keep in mind is to add an underscore "_" before the function name. Here is an example of a helper function:
```
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
```

## **Readiness state**
The readiness state is a salt state that functions as your preflight check for your module. This is a salt state that will ensure all apt packages and python modules are setup properly before your module is run. If you have experience working with YAML files this part will come more naturally to you, but if you follow these guidelines you will be good to write your own readiness state in no time.

### folder structure
The folder structure is pretty rigid when it comes to salt so be sure to follow these rules. All the modules that we create for Soarcast are found in the _modules directory. Make sure to only put modules in this directory. When creating a readiness state, you will create a folder named after the module that your state is supporting. In our example we have a module named 'example_module.py' so we have created a folder named 'example_module'. Inside of this folder we need to create two files: 'init.sls' and 'prereqs.sls'. Here is an example of the expected file structure:


```
salt/
├── README.md
├── _modules                    # the folder for all Soarcast modules
│   └── example_module.py       # our example module
├── developer_guide.md          # this developer_guide.md
└── example_module              # our readiness state folder
    ├── init.sls                # our readiness state init.sls file
    └── prereqs.sls             # our readiness state prereqs.sls file
```

### init.sls state
When either Soarcast or salt runs the readiness state, salt looks at the 'init.sls' file to collect all the salt states need to run. Once these states are collected salt will run them automatically. These states that are referenced in the 'init.sls' state ensure all prerequisites are met for your module. For the example below only the 'prereqs.sls' file is called but you might want to call multiple states and this is where you would define those such that they are called during the readiness state.
```
include:
  - .prereqs
```

### prereq.sls state
The 'prereqs.sls' state ensures that all apt packages and python modules are installed. Below is an example of installing 'apt' packages. If you wanted to install python modules through pip you would change the 'pkg.installed' to 'pip.installed'

Sets up apt packages and pip modules
```
python3-pip:                # apt package to install
  pkg.installed             # command to install it if it does not already exist

cloc:                       # apt package to install
  pkg.installed             # command to install it if it does not already exist

git:                        # apt package to install
  pkg.installed             # command to install it if it does not already exist
```

## Congratulations!
At this point in the documentation you should have everything you need to create your own Soarcast module and readiness state. Below are some helpful tips for understanding salt but the are not required to be able to make your first Soarcast module. If you have any questions please send an email to mroberts@isystematics.com

Happy coding!

## **Salt Notes**

### understanding local file structures and scripts
  - code is synced from git to master
  - master then will sync modules to salt minion
  - files that are created by the module will exist on minion
  - any scripts referenced by the module will need to be synced over using a prereq state to the desired location on the minion
  - any file restrictions on the minion will affect file creation and modification. Take this into consideration while creating/modifying your modules
  - suggested locations for intermediary files would be in the temp folder on the minion under a folder named after your module's name.  Example: /tmp/your_module_name/*


## Roadmap:
1. Redis integration:
  - why
  - what methods?
  - setup in virtual function?
  - redis enabled module functionality (easy for use)
  - mapping is more complicated
2. Misc installation through script and other salt state capabilities
3. Add unit testing common practices and framework
