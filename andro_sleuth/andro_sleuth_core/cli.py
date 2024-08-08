from cmd import Cmd


class BaseCli(Cmd):
    def emptyline(self) -> bool:
        return True
