from django.core.management.base import NoArgsCommand
from django.conf import settings
from django.utils.importlib import import_module



class Command(NoArgsCommand):
    def handle_noargs(self, verbosity, **options):
        warn_count = 0

        for func_path in settings.SECURE_CHECKS:
            mod_name, func_name = func_path.rsplit(".", 1)
            module = import_module(mod_name)
            func = getattr(module, func_name)

            if verbosity:
                self.stdout.write("Running %s...\n" % func_path)
            for warn_code in func():
                warn_count += 1
                msg = getattr(func, "messages", {}).get(warn_code, warn_code)
                self.stderr.write(self.style.ERROR(msg) + "\n")

        if verbosity and not warn_count:
            self.stdout.write("All clear!")
