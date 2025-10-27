import subprocess
import logging

logger = logging.getLogger(__name__)


class VerificationAgent:
    """Agent that executes the patched binary and checks for a success signal."""

    def __init__(self, openrouter_agent):
        """
        Initialize the Verification Agent with the Orchestrating Agent.

        :param openrouter_agent: Instance of the Orchestrating Agent.
        """
        self.openrouter_agent = openrouter_agent

    def verify_patch(self, patched_binary_path, original_binary_path):
        """
        Verify the patched binary by executing it and checking the output.

        :param patched_binary_path: Path to the patched binary file.
        :param original_binary_path: Path to the original binary file.
        :return: Verification result as a string.
        """
        try:
            process = subprocess.Popen([patched_binary_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                stdout, stderr = process.communicate(input=b'wrongpassword\n', timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                logger.error("Verification timed out after 10 seconds")
                return "VERIFICATION_TIMEOUT"
            if 'success' in stdout.decode('utf-8'):
                return "CRACK SUCCESSFUL"
            else:
                return "CRACK FAILURE"
        except Exception as e:
            logger.error(f"Error during verification: {e}")
            return None

