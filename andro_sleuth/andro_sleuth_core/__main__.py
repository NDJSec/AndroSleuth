import argparse
import sys

from loguru import logger

from andro_sleuth.andro_sleuth_core.andro_sleuth import AndroSleuth

logger.remove()
logger.level("ARGS INFO", no=22, color="<white>")
logger.add(sys.stdout, level="ARGS INFO")


def _parseargs():
    parser = argparse.ArgumentParser(description="Analyse Android Apps for cryptographic misuse.")

    args = parser.parse_args()

    return args


def main():
    _args = _parseargs()
    logger.log("ARGS INFO", "AndroSleuth Started")

    AndroSleuth().cmdloop()


if __name__ == "__main__":
    main()
