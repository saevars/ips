class ModuleInterface(object):
    """This is only an abstract class for all modules,
    that want to subscripe too the IPS, to implement."""
    def analyse(self, message):
        raise NotImplementedError("Every module should override the analyse method")

    def update(self, message):
        self.analyse(message)