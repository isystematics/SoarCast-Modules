import os


class SaltWrapper(object):

    def __init__(self):
        self.salt = __salt__
        self.pillar = __pillar__


def run(pillar):
    """
        This function is a test module used to test Mission Control functionality. It takes in a filename and file content as strings
        stored in pillar variables and appends the file content to the file.

        Parameters:
        filename: File name in the format filename.ext
        content: Text to be appended to a file in string format.

        Pillar Example:
            filename: textfile.txt
            content: 'example text.'

        CLI Example:
            *With pillars set:
            salt <minion_name> mission_control_test.run

    """

    # Initialize pillar parameters

    salt_wrapper = SaltWrapper()

    filename = pillar.get('filename') or salt_wrapper.pillar.get('filename')
    content = pillar.get('content') or salt_wrapper.pillar.get('content')

    if filename is not None and content is not None:

        file_path = os.path.join('/tmp', filename)

        with open(file_path, 'a') as f:
            f.write(content)
        return "Content appended to file successfully."
    else:
        return "One or both of the pillar values are not set."
