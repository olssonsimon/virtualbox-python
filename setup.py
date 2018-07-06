# Copyright 2018 Seth Michael Larson (sethmichaellarson@protonmail.com)
# Copyright 2013 Michael Dorman (mjdorma@gmail.com)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
from setuptools import setup, find_packages


base_dir = os.path.dirname(os.path.abspath(__file__))

about = {}
with open(os.path.join(base_dir, "src", "virtualbox", "__about__.py")) as f:
    exec(f.read(), about)

with open("README.rst") as f:
    readme = f.read()

with open("CHANGELOG.rst") as f:
    changelog = f.read()


setup(
    name=about["__name__"],
    version=about["__version__"],
    packages=find_packages("src"),
    author=about["__author__"],
    author_email=about["__author_email__"],
    maintainer=about["__maintainer__"],
    maintainer_email=about["__maintainer_email__"],
    url=about["__url__"],
    description="VirtualBox API implementation for Python",
    long_description=readme + "\n\n" + changelog,
    license=about["__license__"],
    zip_safe=False,
    platforms=["cygwin", "win", "linux"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Natural Language :: English",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: Microsoft",
        "Operating System :: POSIX",
        "Operating System :: MacOS",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: Implementation :: CPython",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Visualization",
        "Topic :: System :: Clustering",
        "Topic :: System :: Distributed Computing",
        "Topic :: System :: Emulators",
        "Topic :: Software Development :: Testing",
    ],
    install_requires=["six", "attrs"],
    python_requires=[">=3.6"]
)
