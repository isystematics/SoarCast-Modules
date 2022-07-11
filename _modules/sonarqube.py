# SoarCast is open source software that enables you to automate security testing and analysis.
# To learn more about SoarCast visit:
# https://www.soarcast.io


#from bs4 import BeautifulSoup
import logging
import json
import os
import requests
import shutil
import subprocess
import urllib.parse
import xml.etree.ElementTree as ET
import tarfile
import time
import traceback

from datetime import date
log = logging.getLogger(__name__)

def prereq():
    """
    Install NodeJS which is needed to run SonarQube.
    """
    try:
        subprocess.run("curl -sL https://deb.nodesource.com/setup_16.x -o /tmp/nodesource_setup.sh", shell=True)
        subprocess.run("bash /tmp/nodesource_setup.sh", shell=True)
        subprocess.run("apt update", shell=True)
        __salt__["pkg.install"]("nodejs")
        __salt__["pkg.install"]("python3-pip")
        __salt__["pip.install"]("redis==3.5.3")
        __salt__["pip.install"]("sentry_sdk")
        __salt__["pip.install"]("beautifulsoup4")
        __salt__["pip.install"]("lxml")

        return ""
    except:
        error = traceback.format_exc()
        return error


# END LOGGING INITIALIZTION #

class SaltWrapper(object):

    def __init__(self):
        self.salt = __salt__
        self.pillar = __pillar__


def _backup_file(file_name):
    """Helper function to create a backup of a file"""

    if os.path.exists(file_name):
        shutil.copyfile(file_name, file_name + '.bak')
        # os.rename(file_name, file_name + '.bak')


def _revert_backup_file(file_name):
    """Helper to revert a backup file to its original file name"""

    if os.path.exists(file_name + '.bak'):
        if os.path.exists(file_name):
            os.remove(file_name)
        os.rename(file_name + '.bak', file_name)


def _clean_up(clean_up, file_dir):
    """Helper to remove all traces of file_dir

       Parameters:
         clean_up: Boolean value determining whether clean up is necessary
         file_dir: Full path to the directory that needs to be deleted
    """

    if clean_up:
        try:
            shutil.rmtree(file_dir)
        except Exception as e:
            log.error('Could not delete source code directory {} from minion. {}'.format(file_dir, e))
            _check_sentry()


def _run_linux(token, sonar_url, software_dir, clean_up):
    """Execute a scan for a new SonarQube project on a Linux minion. Assumes the project is
       built and ready to be scanned
    """

    salt_wrapper = SaltWrapper()

    # Initialize necessary variables for the new code project
    project_name = salt_wrapper.pillar.get('sonarqube_project', None) or os.path.basename(software_dir)
    sonar_scanner_dir = '/opt/sonar-scanner'
    props_file = os.path.join(sonar_scanner_dir, 'conf/sonar-scanner.properties')
    scanner_file = os.path.join(sonar_scanner_dir, 'bin/sonar-project.properties')

    # Backup existing files if necessary
    _backup_file(props_file)
    _backup_file(scanner_file)

    # Create Sonar scanner files to scan the project source code
    # Property file parameters - https://docs.sonarqube.org/latest/analysis/analysis-parameters/
    with open(props_file, 'w') as f:
        f.write('sonar.host.url={}\nsonar.login={}'.format(sonar_url, token))

    # Scanner project file parameters - https://docs.sonarqube.org/latest/analysis/scan/sonarscanner/
    with open(scanner_file, 'w') as f:
        f.write('sonar.projectKey={}\nsonar.projectBaseDir={}'.format(project_name, software_dir))

    # Execute

    process = subprocess.run(['/opt/sonar-scanner/bin/sonar-scanner', '-Dsonar.projectKey={}'.format(project_name),
                              '-Dsonar.projectBaseDir={}'.format(software_dir)], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

    # Conduct clean up activities
    _revert_backup_file(props_file)
    _revert_backup_file(scanner_file)
    _clean_up(clean_up, software_dir)

    return {project_name: {'Built': True}}


def _edit_sonar_analysis_xml(sonar_file, url, token):
    """Helper to edit the SonarQube.Analysis.xml file used for MSBuild on a Windows host"""

    try:
        tree = ET.parse(sonar_file)
        root = tree.getroot()
        for elem in root:
            if elem.get('Name') == 'sonar.host.url':
                elem.text = url
            elif elem.get('Name') == 'sonar.login':
                elem.text = token
        tree.write(sonar_file, encoding='utf-8', xml_declaration=True)
    except Exception as e:
        log.error('Error writing SonarQube.Analysis.xml for MSBuild. {}'.format(e))
        _check_sentry()
        raise e


def get_solution_files(project_dir, solution=None, clean_up=True):
    """Find the C#/.NET Visual Studio Solution files in a source code directory to build the project

       Parameters:
           solution:    Name of the Solution to search for
           project_dir: The source code directory that the solution(s) should be present in
           clean_up:    Boolean value decides whether source code directory is deleted if no
                        solution files are found
    """

    if solution:
        if not os.path.isfile(solution):
            if not solution.endswith('.sln'):
                solution = solution + '.sln'
            solution_files = __salt__['data.get_files'](project_dir, file_name=solution, first=True)
        else:
            solution_files = [solution]
    else:
        solution_files = __salt__['data.get_files'](root_dir=project_dir, suffix='.sln')

    if not solution_files:
        _clean_up(clean_up, project_dir)
        log.error('Could not find any C# solution files in {}'.format(project_dir))
        _check_sentry()
        raise ValueError('Could not find any C# solution files in {}'.format(project_dir))

    return solution_files


def _run_windows(token, sonar_url, software_dir, clean_up,
                 solution_file=None, sonar_scanner_dir='C:\sonar-scanner', ):
    """Execute a SonarQube scan on a Windows minion for .NET/C# projects that require MSBuild

    """

    # Create the SonarQube.Analysis.xml file for the SonarScanner.MSBuild.exe
    if not os.path.exists(sonar_scanner_dir):
        log.error(
            'Please run the sonar state to get Sonar-Scanner for MSBuild in the proper place on the minion, defaults to C:\\sonar-scanner.')
        _check_sentry()
        raise FileNotFoundError('Please run the sonar state to get Sonar-Scanner for MSBuild ' \
                                'in the proper place on the minion, defaults to C:\\sonar-scanner')
    sonar_analysis_file = os.path.join(sonar_scanner_dir, 'SonarQube.Analysis.xml')
    _backup_file(sonar_analysis_file)
    _edit_sonar_analysis_xml(sonar_analysis_file, sonar_url, token)

    # Get location of the MSBuild.exe file from Visual Studio, in case not in path
    msbuild = __salt__['data.get_files'](root_dir='C:\\Program Files (x86)\\Microsoft Visual Studio',
                                         file_name='MSBuild.exe',
                                         first=True,
                                         )[0]
    if not msbuild:
        log.error('You need to install MSBuild for Visual Studio to run this module.')
        _check_sentry()
        raise OSError('You need to install MSBuild for Visual Studio to run this module.')

    # Gather C# solution file locations to pass to MSBuild
    solution_files = get_solution_files(software_dir, solution_file, clean_up)

    # Execute the Sonar batch script for each solution desired file
    sonar_script = 'salt://sonar/run_sonar.bat'
    status = {}
    for solution in solution_files:
        log.info('Running MSBuild batch script for SonarQube on {}.'.format(solution))
        project_key = os.path.splitext(solution.split('\\')[-1])[0]
        status[project_key] = {}
        script = __salt__['cmd.script'](source=sonar_script,
                                        args='{} {} "{}"'.format(project_key, solution, msbuild),
                                        cwd=sonar_scanner_dir,
                                        )
        if script.get('retcode') == 0:
            log.info('Successfully build {} for SonarQube scan'.format(solution))
            status[project_key]['Built'] = True
        else:
            log.error('Failed to build {} for SonarQube scan'.format(solution))
            status[project_key]['Built'] = False
    _revert_backup_file(sonar_analysis_file)
    _clean_up(clean_up, software_dir)
    _check_sentry()
    return status


def run(token=None, sonar_url=None, software_dir=None,
        redis_write_key=None, redis_url=None, redis_tls_host=None, redis_tls_port=None, redis_tls_password=None, solution_name=None, clean_up_source=False, clean_up_sonar=False):
    """Execute a new SonarQube scan

       Parameters:
           token:           The SonarQube authentication token used to create this project on the SonarQube server
           sonar_url:       The URL of the SonarQube server where scan results are sent,
                            defaults to https://sonar.example.com
           project_name:    The name to call the project to be scanned. For example, if you name the project
                            SQ-APP1-030321, this will create a JSON results file with this name.

           s3_filename:     The name of a source code archive to be downloaded from an Amazon S3 bucket

           s3_key_id:       AWS Access Key ID for downloading the code.

           s3_key:          AWS Secret Access Key for downloading the code.

           s3_bucket:       The bucket to download the source code archive from.

           redis_write_key: This is a randomly generated key sent by Mission Control which is used to update Redis cache for runbooks.

           redis_url:       Use this variable if you are not using Redis with TLS. The redis url is in the format of this
           example: redis://127.0.0.1:6379. If you are using TLS, leave this variable blank.

           redis_tls_host: The hostname or IP address of the Redis host. Used only for TLS connections.

           redis_tls_port: The port on which Redis runs to connect to. Used only for TLS connections.

           redis_tls_password: The password of the Redis host. Used only for TLS connections.

           solution_name:   Name of a C# solution file to base a scan on. Only used on Windows and only necessary
                            if there are multiple solution files within the software_dir
                            and you want to scan just one of them
           clean_up_source: Delete source code from the Minion after processing
           clean_up_minion: Gather scan results from SonarQube and delete the SonarQube project

       CLI Example:
           salt '<minion_id>' sonarqube.run

       Running with sonar state:
           salt '<minion_id>' state.apply sonar pillar='{"software_dir": "<software_dir_path>"}'
    """

    errorMessage = prereq()
    if errorMessage:
        return errorMessage


    import redis
    import sentry_sdk
    from sentry_sdk.integrations.logging import LoggingIntegration

    sentry_logging = LoggingIntegration(
        level=logging.INFO,  # Capture info and above as breadcrumbs
        event_level=logging.INFO  # Send errors as events
    )
    sentry_sdk.init(dsn='https://555mykey555@sentry.io/123456',
                    shutdown_timeout=20, debug=False, traces_sample_rate=1.0, max_breadcrumbs=0)
    salt_wrapper = SaltWrapper()

    # Initialize parameters, allow use of pillars for flexibility if calling from Sonar Salt State
    token = token or salt_wrapper.pillar.get('token')
    sonar_url = sonar_url or salt_wrapper.pillar.get('sonar_url', 'https://sonar.example.com')
    software_dir = software_dir or salt_wrapper.pillar.get('software_dir')
    redis_write_key = redis_write_key or salt_wrapper.pillar.get('redis_write_key')
    redis_url = redis_url or salt_wrapper.pillar.get('redis_url')
    redis_tls_host = redis_tls_host or salt_wrapper.pillar.get('redis_tls_host')
    redis_tls_port = redis_tls_port or salt_wrapper.pillar.get('redis_tls_port', 6379)
    redis_tls_password = redis_tls_password or salt_wrapper.pillar.get('redis_tls_password')
    clean_up_source = clean_up_source or salt_wrapper.pillar.get('clean_up_source', False)
    clean_up_sonar = clean_up_sonar or salt_wrapper.pillar.get('clean_up_sonar', False)

    if not software_dir or not os.path.exists(software_dir):
        log.error("The provided directory does not exist on the minion.")
        _check_sentry()
        return "The provided directory does not exist on the minion."


    if token is not None and sonar_url is not None and software_dir is not None and redis_write_key is not None:

        # Establish a connection with the Redis server.
        try:
            if redis_tls_host and redis_tls_port and redis_tls_password:
                r = redis.Redis(host=redis_tls_host, port=redis_tls_port, password=redis_tls_password, ssl=True, ssl_cert_reqs=None, health_check_interval=30)
            else:
                r = redis.Redis.from_url(redis_url)

            # Test Redis connection to make sure it is valid. This will throw an error if invalid.
            r.smembers(redis_write_key)
        except Exception as e:
            log.error("Could not connect to Redis. Make sure that all redis variables are correct. {}".format(e))
            _check_sentry()
            return "Could not connect to Redis. Make sure that all redis variables are correct. {}".format(e)

        # Determine code requirements based on Operating System of the Minion used
        if __grains__.get('kernel').lower() == 'windows':
            solution_name = solution_name or salt_wrapper.pillar.get('solution_name', None)
            status = _run_windows(token=token,
                                  sonar_url=sonar_url,
                                  clean_up=clean_up_source,
                                  software_dir=software_dir,
                                  solution_file=solution_name,
                                  )
        else:
            status = _run_linux(token=token,
                                sonar_url=sonar_url,
                                software_dir=software_dir,
                                clean_up=clean_up_source,
                                )

        # Gather results from SonarQube for each project and then delete them as necessary
        for proj in status.keys():
            # get_results raises exception if results not found
            if not status[proj].get('Built'):
                continue

            #try:
            if clean_up_sonar:
                result, issues_file = get_results(key=proj,
                                                      token=token,
                                                      sonar_url=sonar_url,
                                                      remove_project=True,
                                                      )
            else:
                result, issues_file = get_results(key=proj,
                                                      token=token,
                                                      sonar_url=sonar_url,
                                                      remove_project=False,
                                                      )
            #except:
                #result = None

            # Save result for solution file(s) and return to user
            if result:
                status[proj]['Gathered From SonarQube'] = True
                r.sadd(redis_write_key, issues_file)

            else:
                status[proj]['Gathered From SonarQube'] = False
                _check_sentry()

        return status
    else:
        log.error("Some of the variables necessary to run this module are not set.")
        _check_sentry()
        return "Some of the variables necessary to run this module are not set."


def _delete_project_from_sonar(token, url, key):
    """Helper to delete project history from the SonarQube server"""

    api = urllib.parse.urljoin(url, 'api/projects/delete')
    payload = {'project': key}

    try:

        req = __salt__['http.query'](url=api,
                                 method='POST',
                                 data=payload,
                                 username=token,
                                 password=''
                                 )
    except Exception as e:
        log.error("An error occured when connecting to the SonarQube API.")
        _check_sentry()
        return "An error occured when connecting to the SonarQube API."
    return req


def get_results(key, token=None, sonar_url=None, remove_project=False):
    """Gather scan results for a project from the SonarQube API

       key:            The SonarQube project key/name to search for on the SonarQube server
       token:          An authentication token with privileges to access the project key on
                        the SonarQube server
       sonar_url:      The URL of the SonarQube server where scan results are sent,
                        defaults to https://sonar.example.com
       remove_project: Attempt to delete the project from the SonarQube server, the token
                        provided must have Administer permission to the project

       CLI Example:
           salt '<minion_id>' sonarqube.get_results [remove_project=True]
    """

    salt_wrapper = SaltWrapper()

    # Gather variables for HTTP Query
    auth_token = token or salt_wrapper.pillar.get('token')
    sonar_url = sonar_url or salt_wrapper.pillar.get('sonar_url', 'https://sonar.example.com')
    api = urllib.parse.urljoin(sonar_url, 'api/issues/search')
    params = {'componentKeys': key, 'ps': 500, 'p': 1}

    time.sleep(60)

    # Query the API to get total number of results
    try:
        get_issues = __salt__['http.query'](url=api,
                                        method='GET',
                                        params=params,
                                        username=auth_token,
                                        password=''
                                        )
    except Exception as e:
        log.error("An error occured when connecting to the SonarQube API.")
        _check_sentry()
        return "An error occured when connecting to the SonarQube API.", None

    if get_issues.get('status') == 401:
        log.error('SonarQube authentication token {}, does not have permission ' \
                  'to {} on {}.'.format(auth_token, key, api)
                  )
        _check_sentry()
        raise ValueError('SonarQube authentication token {}, does not have permission ' \
                         'to {} on {}.'.format(auth_token, key, api)
                         )
    issues = json.loads(get_issues.get('body'))
    total = issues.get('total', 0)
    issues = issues.get('issues', [])

    if total == 0:
        log.error('No SonarQube results for {} on {}.'.format(key, api))
        _check_sentry()
        results = '{ "issues": [], '

    else:
        results = '{ "issues": ['

        results = _build_issues_string(issues, auth_token, results, sonar_url)

        if total > 500:  # maximum page size for SonarQube API
            # Continue to query API until all issues have been retrieved
            while params['p'] < 20:
                params['p'] += 1
                try:
                    get_next_issues = __salt__['http.query'](url=api,
                                                            method='GET',
                                                            params=params,
                                                            username=auth_token,
                                                            password=''
                                                            )
                except Exception as e:
                    log.error("An error occured when connecting to the SonarQube API.")
                    _check_sentry()
                    return "An error occured when connecting to the SonarQube API.", None
                issues = json.loads(get_next_issues.get('body')).get('issues', None)
                if issues:
                    # Add issues on current page to total issues
                    results = _build_issues_string(issues, auth_token, results, sonar_url)
                else:
                    break
        results = results[:-2]
        results += '], '

    # Get Security Hotspots
    params = {'projectKey': key, 'ps': 500, 'p': 1}

    try:
        hotspots = requests.get('{}/api/hotspots/search'.format(sonar_url), params=params,
                            auth=(auth_token, ''))
    except Exception as e:
        log.error("An error occured when connecting to the SonarQube API.")
        _check_sentry()
        return "An error occured when connecting to the SonarQube API.", None


    hotspots = hotspots.json()

    total = hotspots['paging']['total']

    if total == 0:
        results = results[:-2]
        results += "}"

    elif total > 0:

        results += '"hotspots": ['

        hotspots = hotspots['hotspots']

        results = _build_issues_string(hotspots, auth_token, results, sonar_url, True)

        if total >= 500:
            while params['p'] < 20:
                params['p'] += 1
                try:
                    hotspots = requests.get('{}/api/hotspots/search'.format(sonar_url), params=params,
                                            auth=(auth_token, ''))
                except Exception as e:
                    log.error("An error occured when connecting to the SonarQube API.")
                    _check_sentry()
                    return "An error occured when connecting to the SonarQube API.", None
                hotspots = hotspots.json()
                hotspots = hotspots['hotspots']
                if hotspots:
                # Add issues on current page to total issues
                    results = _build_issues_string(hotspots, auth_token, results, sonar_url, True)
                else:
                    break
        results = results[:-2]
        results += "]}"

    tmp = __salt__['data.get_temp_path']()

    # Write results to file
    issues_file = os.path.join(tmp, 'SQ-{}-{}.json'.format(key, date.today().strftime("%m%d%y")))
    with open(issues_file, 'w') as f:
        f.write(results)

    if remove_project:
        delete = _delete_project_from_sonar(auth_token, sonar_url, key)
        log.warning('Attempted to delete project {} from {}. HTTP Query returned ' \
                    '{}'.format(key, sonar_url, delete))
        _check_sentry()
    return True, issues_file


def _build_issues_string(issues, auth_token, results, sonar_url, hotspots=False):
    from bs4 import BeautifulSoup

    for issue in issues:
        hasSnippet = True
        issueKey = issue['key']
        try:
            line = issue['line']
        except Exception as e:
            try:
                textRange = issue['textRange']
                line = textRange['startLine']
            except Exception as e:
                hasSnippet = False
        component = issue['component']
        if hotspots:
            params = {'hotspot': issueKey}
            success = False
            while not success:
                try:
                    data = requests.get('{}/api/hotspots/show'.format(sonar_url), params=params,
                                    auth=(auth_token, ''))
                    success = True
                except Exception as e:
                    time.sleep(5)
            data = data.json()
            if 'rule' in data:
                rule = data['rule']
                if 'name' in rule:
                    name = rule['name']
                else:
                    name = 'None'
                if 'riskDescription' in rule:
                    riskDescription = rule['riskDescription']
                else:
                    riskDescription = 'None'
                # soup = BeautifulSoup(riskDescription, 'lxml')
                # riskDescription = soup.get_text()
                if 'vulnerabilityDescription' in rule:
                    vulnerabilityDescription = rule['vulnerabilityDescription']
                else:
                    vulnerabilityDescription = 'None'
                # soup = BeautifulSoup(vulnerabilityDescription, 'lxml')
                # vulnerabilityDescription = soup.get_text()
                if 'fixRecommendations' in rule:
                    fixRecommendations = rule['fixRecommendations']
                else:
                    fixRecommendations = 'None'
                # soup = BeautifulSoup(fixRecommendations, 'lxml')
                # fixRecommendations = soup.get_text()

                issue.update({'name': name})
                issue.update({"riskDescription": riskDescription})
                issue.update({"vulnerabilityDescription": vulnerabilityDescription})
                issue.update({"fixRecommendations": fixRecommendations})
        else:
            rule = issue['rule']
            params = {'key': rule}
            success = False
            while not success:
                try:
                    data = requests.get('{}/api/rules/show'.format(sonar_url), params=params,
                                    auth=(auth_token, ''))
                    success = True
                except Exception as e:
                    time.sleep(5)
            data = data.json()
            if 'htmlDesc' in data['rule']:
                description = data['rule']['htmlDesc']
            else:
                description = "No Description Available."
            issue.update({"description": description})
        if hasSnippet:
            params = {'issueKey': issueKey}
            success = False
            while not success:
                try:
                    data = requests.get('{}/api/sources/issue_snippets'.format(sonar_url), params=params,
                                    auth=(auth_token, ''))
                    success = True
                except Exception as e:
                    time.sleep(5)
            try:
                data = data.json()
                data = data[component]
                sources = data['sources']
                fullSnippet = []
                for source in sources:
                    try:
                        line = source['line']
                        code = source['code']
                        soup = BeautifulSoup(code, 'lxml')
                        code = soup.get_text()
                        lineSnippet = {"line": line, "code": code}
                        fullSnippet.append(lineSnippet)
                    except Exception as e:
                        error = traceback.format_exc()
                        log.error(error)
                issue.update({"snippet": fullSnippet})
            except Exception as e:
                error = traceback.format_exc()
                log.error(error)
        results += json.dumps(issue)
        results += ", "
    return results

def get_all_results(sonar_url=None, auth_token=None):
    """Gather scan results for all projects on a running SonarQube instance.

           token:          An authentication token with privileges to access the project key on
                            the SonarQube server
           sonar_url:      The URL of the SonarQube server where scan results are sent,
                            defaults to https://sonar.example.com

           CLI Example:
               salt '<minion_id>' sonarqube.get_all_results token https://sonar.example.com
        """
    import sentry_sdk
    from sentry_sdk.integrations.logging import LoggingIntegration

    sentry_logging = LoggingIntegration(
        level=logging.INFO,  # Capture info and above as breadcrumbs
        event_level=logging.INFO  # Send errors as events
    )
    sentry_sdk.init(dsn='https://555key555@sentry.io/123456',
                    shutdown_timeout=20, debug=False, traces_sample_rate=1.0, max_breadcrumbs=0)
    salt_wrapper = SaltWrapper()

    auth_token = auth_token or salt_wrapper.pillar.get('auth_token')
    sonar_url = sonar_url or salt_wrapper.pillar.get('sonar_url', 'https://sonar.example.com')
    if auth_token is None or sonar_url is None:
        log.error("The auth token and/or sonar URL must be provided in order for this module to run.")
        _check_sentry()
        return "The auth token and/or sonar URL must be provided in order for this module to run."


    api = urllib.parse.urljoin(sonar_url, 'api/components/search')

    params = {'qualifiers': 'TRK', 'ps': 500, 'p': 1}

    try:
        response = requests.get(api, params=params,
                                auth=(auth_token, ''))
    except Exception as e:
        pass
        log.error("An error occured when connecting to the SonarQube API.")
        _check_sentry()
        return "An error occured when connecting to the SonarQube API."

    response = response.json()

    total = response['paging']['total']

    components = response['components']

    global keys
    keys = []

    for component in components:
        keys.append(component['key'])

    if total > 500:
        while True:
            params['p'] += 1
            try:
                response = requests.get(api, params=params,
                                        auth=(auth_token, ''))
            except Exception as e:
                log.error("An error occured when connecting to the SonarQube API.")
                _check_sentry()
                return "An error occured when connecting to the SonarQube API."
            response = response.json()
            components = response['components']
            if not components:
                break
            for component in components:
                keys.append(component['key'])

    global project_dir

    tmp = __salt__['data.get_temp_path']()

    try:
        os.mkdir(os.path.join(tmp, 'projects'))
    except Exception as e:
        pass
    project_dir = os.path.join(tmp, 'projects')

    for key in keys:

        api = urllib.parse.urljoin(sonar_url, 'api/issues/search')
        params = {'componentKeys': key, 'ps': 500, 'p': 1}
        # Query the API to get total number of results
        try:
            get_issues = __salt__['http.query'](url=api,
                                            method='GET',
                                            params=params,
                                            username=auth_token,
                                            password=''
                                            )
        except Exception as e:
            log.error("An error occured when connecting to the SonarQube API.")
            _check_sentry()
            return "An error occured when connecting to the SonarQube API."

        if get_issues.get('status') == 401:
            log.error('SonarQube authentication token {}, does not have permission ' \
                    'to {} on {}.'.format(auth_token, key, api)
                    )
            _check_sentry()
            raise ValueError('SonarQube authentication token {}, does not have permission ' \
                            'to {} on {}.'.format(auth_token, key, api)
                            )
        issues = json.loads(get_issues.get('body'))
        total = issues.get('total', 0)
        issues = issues.get('issues', [])

        if total == 0:
            log.error('No SonarQube results for {} on {}.'.format(key, api))
            _check_sentry()
            #raise Exception('No SonarQube results for {} on {}.'.format(key, api))
            continue

        results = '{ "issues": ['

        results = _build_issues_string(issues, auth_token, results, sonar_url)

        if total > 500:  # maximum page size for SonarQube API
            # Continue to query API until all issues have been retrieved

            while params['p'] < 20:
                params['p'] += 1
                try:
                    get_next_issues = __salt__['http.query'](url=api,
                                                            method='GET',
                                                            params=params,
                                                            username=auth_token,
                                                            password=''
                                                            )
                except Exception as e:
                    log.error("An error occured when connecting to the SonarQube API.")
                    _check_sentry()
                    return "An error occured when connecting to the SonarQube API."

                issues = json.loads(get_next_issues.get('body')).get('issues', None)
                if issues:
                    # Add issues on current page to total issues
                    results = _build_issues_string(issues, auth_token, results, sonar_url)
                else:
                    break
        results = results[:-2]
        results += '], '

        # Get Security Hotspots
        params = {'projectKey': key, 'ps': 500, 'p': 1}

        try:
            hotspots = requests.get('{}/api/hotspots/search'.format(sonar_url), params=params,
                                auth=(auth_token, ''))
        except Exception as e:
            log.error("An error occured when connecting to the SonarQube API.")
            _check_sentry()
            return "An error occured when connecting to the SonarQube API."

        hotspots = hotspots.json()

        total = hotspots['paging']['total']

        if total == 0:
            results = results[:-2]
            results += "}"

        elif total > 0:

            results += '"hotspots": ['

            hotspots = hotspots['hotspots']

            for hotspot in hotspots:
                results += json.dumps(hotspot)
                results += ", "

            if total >= 500:
                while params['p'] < 20:
                    params['p'] += 1
                    try:
                        hotspots = requests.get('{}/api/hotspots/search'.format(sonar_url), params=params,
                                                auth=(auth_token, ''))
                    except Exception as e:
                        log.error("An error occured when connecting to the SonarQube API.")
                        _check_sentry()
                        return "An error occured when connecting to the SonarQube API."
                    hotspots = hotspots.json()
                    hotspots = hotspots['hotspots']
                    if not hotspots:
                        break
                    for hotspot in hotspots:
                        results += json.dumps(hotspot)
                        results += ", "
            results = results[:-2]
            results += "]}"

        # Write results to file
        issues_file = os.path.join(project_dir, '{}.json'.format(key))
        with open(issues_file, 'w') as f:
            f.write(results)

    tar_file = os.path.join(tmp, 'projects.tar.gz')

    with tarfile.open(tar_file, "w:gz") as tar:
        tar.add(project_dir, arcname=os.path.basename(project_dir))

    return "All Data Extracted Successfully!"

def get_all_results_per_project(sonar_url=None, auth_token=None, bucket=None, source_key_id=None, source_key=None):
    """Gather scan results for all projects on a running SonarQube instance.

           token:          An authentication token with privileges to access the project key on
                            the SonarQube server
           sonar_url:      The URL of the SonarQube server where scan results are sent,
                            defaults to https://sonar.example.com

           CLI Example:
               salt '<minion_id>' sonarqube.get_all_results token https://sonar.example.com
        """
    import sentry_sdk
    from sentry_sdk.integrations.logging import LoggingIntegration

    sentry_logging = LoggingIntegration(
        level=logging.INFO,  # Capture info and above as breadcrumbs
        event_level=logging.INFO  # Send errors as events
    )
    sentry_sdk.init(dsn='https://555mykey555@sentry.io/123445',
                    shutdown_timeout=20, debug=False, traces_sample_rate=1.0, max_breadcrumbs=0)

    salt_wrapper = SaltWrapper()

    auth_token = auth_token or salt_wrapper.pillar.get('auth_token')
    sonar_url = sonar_url or salt_wrapper.pillar.get('sonar_url', 'https://sonar.example.com')
    bucket = bucket or salt_wrapper.pillar.get('bucket')
    if auth_token is None or sonar_url is None:
        log.error("The auth token and/or sonar URL must be provided in order for this module to run.")
        _check_sentry()
        return "The auth token and/or sonar URL must be provided in order for this module to run."


    api = urllib.parse.urljoin(sonar_url, 'api/components/search')

    params = {'qualifiers': 'TRK', 'ps': 500, 'p': 1}

    try:
        response = requests.get(api, params=params,
                                auth=(auth_token, ''))
    except Exception as e:
        pass
        log.error("An error occured when connecting to the SonarQube API.")
        _check_sentry()
        return "An error occured when connecting to the SonarQube API."

    response = response.json()

    total = response['paging']['total']

    components = response['components']

    global keys
    keys = []

    for component in components:
        keys.append(component['key'])

    if total > 500:
        while True:
            params['p'] += 1
            try:
                response = requests.get(api, params=params,
                                        auth=(auth_token, ''))
            except Exception as e:
                log.error("An error occured when connecting to the SonarQube API.")
                _check_sentry()
                return "An error occured when connecting to the SonarQube API."
            response = response.json()
            components = response['components']
            if not components:
                break
            for component in components:
                keys.append(component['key'])

    global project_dir

    tmp = __salt__['data.get_temp_path']()

    try:
        os.mkdir(os.path.join(tmp, 'projects'))
    except Exception as e:
        pass
    project_dir = os.path.join(tmp, 'projects')

    for key in keys:

        api = urllib.parse.urljoin(sonar_url, 'api/issues/search')
        params = {'componentKeys': key, 'ps': 500, 'p': 1}
        # Query the API to get total number of results
        try:
            get_issues = __salt__['http.query'](url=api,
                                            method='GET',
                                            params=params,
                                            username=auth_token,
                                            password=''
                                            )
        except Exception as e:
            log.error("An error occured when connecting to the SonarQube API.")
            _check_sentry()
            return "An error occured when connecting to the SonarQube API."

        if get_issues.get('status') == 401:
            log.error('SonarQube authentication token {}, does not have permission ' \
                    'to {} on {}.'.format(auth_token, key, api)
                    )
            _check_sentry()
            raise ValueError('SonarQube authentication token {}, does not have permission ' \
                            'to {} on {}.'.format(auth_token, key, api)
                            )
        issues = json.loads(get_issues.get('body'))
        total = issues.get('total', 0)
        issues = issues.get('issues', [])

        if total == 0:
            log.error('No SonarQube results for {} on {}.'.format(key, api))
            _check_sentry()
            #raise Exception('No SonarQube results for {} on {}.'.format(key, api))
            continue

        results = '{ "issues": ['

        results = _build_issues_string(issues, auth_token, results, sonar_url)

        if total > 500:  # maximum page size for SonarQube API
            # Continue to query API until all issues have been retrieved

            while params['p'] < 20:
                params['p'] += 1
                try:
                    get_next_issues = __salt__['http.query'](url=api,
                                                            method='GET',
                                                            params=params,
                                                            username=auth_token,
                                                            password=''
                                                            )
                except Exception as e:
                    log.error("An error occured when connecting to the SonarQube API.")
                    _check_sentry()
                    return "An error occured when connecting to the SonarQube API."

                issues = json.loads(get_next_issues.get('body')).get('issues', None)
                if issues:
                    # Add issues on current page to total issues
                    results = _build_issues_string(issues, auth_token, results, sonar_url)
                else:
                    break
        results = results[:-2]
        results += '], '

        # Get Security Hotspots
        params = {'projectKey': key, 'ps': 500, 'p': 1}

        try:
            hotspots = requests.get('{}/api/hotspots/search'.format(sonar_url), params=params,
                                auth=(auth_token, ''))
        except Exception as e:
            log.error("An error occured when connecting to the SonarQube API.")
            _check_sentry()
            return "An error occured when connecting to the SonarQube API."

        hotspots = hotspots.json()

        total = hotspots['paging']['total']

        if total == 0:
            results = results[:-2]
            results += "}"

        elif total > 0:

            results += '"hotspots": ['

            hotspots = hotspots['hotspots']

            for hotspot in hotspots:
                results += json.dumps(hotspot)
                results += ", "

            if total >= 500:
                while params['p'] < 20:
                    params['p'] += 1
                    try:
                        hotspots = requests.get('{}/api/hotspots/search'.format(sonar_url), params=params,
                                                auth=(auth_token, ''))
                    except Exception as e:
                        log.error("An error occured when connecting to the SonarQube API.")
                        _check_sentry()
                        return "An error occured when connecting to the SonarQube API."
                    hotspots = hotspots.json()
                    hotspots = hotspots['hotspots']
                    if not hotspots:
                        break
                    for hotspot in hotspots:
                        results += json.dumps(hotspot)
                        results += ", "
            results = results[:-2]
            results += "]}"

        # Write results to file
        issues_file = os.path.join(project_dir, '{}.json'.format(key))
        with open(issues_file, 'w') as f:
            f.write(results)
        success = __salt__['data.send_to_s3'](local_path=issues_file, s3_bucket=bucket, s3_keyid=source_key_id, s3_key=source_key)
        if not success:
            log.error("Could not upload file {} to S3.".format(issues_file))
            return "Could not upload file {} to S3.".format(issues_file)
    return "Success!"

def delete_all_projects(sonar_url=None, auth_token=None):
    """Gather scan results for all projects on a running SonarQube instance.

           token:          An authentication token with privileges to access the project key on
                            the SonarQube server
           sonar_url:      The URL of the SonarQube server where scan results are sent,
                            defaults to https://sonar.example.com

           CLI Example:
               salt '<minion_id>' sonarqube.get_all_results token https://sonar.example.com
        """

    import sentry_sdk
    from sentry_sdk.integrations.logging import LoggingIntegration

    sentry_logging = LoggingIntegration(
        level=logging.INFO,  # Capture info and above as breadcrumbs
        event_level=logging.INFO  # Send errors as events
    )
    sentry_sdk.init(dsn='https://555key555@sentry.io/123456',
                    shutdown_timeout=20, debug=False, traces_sample_rate=1.0, max_breadcrumbs=0)

    salt_wrapper = SaltWrapper()

    auth_token = auth_token or salt_wrapper.pillar.get('auth_token')
    sonar_url = sonar_url or salt_wrapper.pillar.get('sonar_url', 'https://sonar.example.com')
    if auth_token is None or sonar_url is None:
        log.error("The auth token and/or sonar URL must be provided in order for this module to run.")
        _check_sentry()
        return "The auth token and/or sonar URL must be provided in order for this module to run."


    api = urllib.parse.urljoin(sonar_url, 'api/components/search')

    params = {'qualifiers': 'TRK', 'ps': 500, 'p': 1}

    try:
        response = requests.get(api, params=params,
                                auth=(auth_token, ''))
    except Exception as e:
        pass
        log.error("An error occured when connecting to the SonarQube API.")
        _check_sentry()
        return "An error occured when connecting to the SonarQube API."

    response = response.json()

    total = response['paging']['total']

    components = response['components']

    global keys
    keys = []

    for component in components:
        keys.append(component['key'])

    if total > 500:
        while True:
            params['p'] += 1
            try:
                response = requests.get(api, params=params,
                                        auth=(auth_token, ''))
            except Exception as e:
                log.error("An error occured when connecting to the SonarQube API.")
                _check_sentry()
                return "An error occured when connecting to the SonarQube API."
            response = response.json()
            components = response['components']
            if not components:
                break
            for component in components:
                keys.append(component['key'])

    global project_dir

    tmp = __salt__['data.get_temp_path']()

    try:
        os.mkdir(os.path.join(tmp, 'projects'))
    except Exception as e:
        pass
    project_dir = os.path.join(tmp, 'projects')

    for key in keys:
        api = urllib.parse.urljoin(sonar_url, 'api/projects/delete')

        params = {'project': key}

        try:
            requests.post(api, params=params,
                                    auth=(auth_token, ''))
        except Exception as e:
            pass
            log.error("An error occured when connecting to the SonarQube API.")
            _check_sentry()
            return "An error occured when connecting to the SonarQube API."

    return "Successfully deleted all projects!"

def _check_sentry():
    import sentry_sdk
    if sentry_sdk.Hub.current.client.transport._worker._queue.qsize() > 0:
        sentry_sdk.flush(timeout=10)
