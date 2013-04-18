from os.path import join, dirname

from setuptools import setup, find_packages

here = dirname(__file__)

long_description = (open(join(here, "README.rst")).read() + "\n\n" +
                    open(join(here, "CHANGES.rst")).read() + "\n\n" +
                    open(join(here, "TODO.rst")).read())

def get_version():
    fh = open(join(here, "djangosecure", "__init__.py"))
    try:
        for line in fh.readlines():
            if line.startswith("__version__ ="):
                return line.split("=")[1].strip().strip('"')
    finally:
        fh.close()

setup(
    name="django-secure",
    version=get_version(),
    description="Utilities and a 'linter' to help you make your Django site more secure.",
    long_description=long_description,
    author="Carl Meyer",
    author_email="carl@oddbird.net",
    url="https://github.com/carljm/django-secure/",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
        "Framework :: Django",
    ],
    zip_safe=False,
    install_requires=["Django>=1.4.2"],
    test_suite="runtests.runtests"
)
