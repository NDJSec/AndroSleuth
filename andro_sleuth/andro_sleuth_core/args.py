from argparse import ArgumentParser, Namespace
from shlex import split
from typing import Optional, Sequence


class InlineArgumentError(Exception):
    def __init__(self, status: int = 0, message: str = None):
        self.status = status
        self.message = message


class InlineArgumentParser(ArgumentParser):
    def parse_args_inline(self, args: Optional[Sequence[str]] = None, namespace: Namespace = None) -> Optional[Namespace]:
        try:
            if type(args) is str:
                args = split(args)

            return self.parse_args(args, namespace)
        except InlineArgumentError as error:
            message = error.message

            print(message if message else '')

    def exit(self, status: int = 0, message: str = None) -> None:
        """
        Stops parsing and raises an error rather than exiting the program

        :param status: A non-zero status code indicates something went wrong
        :param message: A message associated with the exit behaviour
        :returns: None
        :raises InlineArgumentError: The arguments could not be parsed
        """
        raise InlineArgumentError(status, message)

