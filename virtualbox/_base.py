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

import six
import copy
import enum
import inspect
import time
import platform
import os
import sys
import multiprocessing
import contextlib


_MANAGERS = {}
_SYSTEM = platform.system()


@contextlib.contextmanager
def import_vboxapi():
    """This import is designed to help when loading vboxapi inside of
    alternative Python environments (virtualenvs etc).
    :rtype: vboxapi module
    """
    try:
        import vboxapi
    except ImportError:
        major, minor = sys.version_info[:2]
        packages = ["vboxapi"]

        if _SYSTEM == "Windows":
            packages.extend(
                ["win32com", "win32", "win32api", "pywintypes", "win32comext"]
            )
            search = [
                "C:\\Python%s%s\\Lib\\site-packages" % (major, minor),
                "C:\\Python%s%s\\Lib\\site-packages\\win32" % (major, minor),
                "C:\\Python%s%s\\Lib\\site-packages\\win32\\lib" % (major, minor),
                "C:\\Program Files\\Oracle\\VirtualBox\\sdk\\install",
                "C:\\Program Files (x86)\\Oracle\\VirtualBox\\sdk\\install",
            ]

            for x in ["", major]:
                search.extend(
                    [
                        "C:\\Anaconda%s\\Lib\\site-packages" % x,
                        "C:\\Anaconda%s\\Lib\\site-packages\win32" % x,
                        "C:\\Anaconda%s\\Lib\\site-packages\win32\\lib" % x,
                    ]
                )

        elif _SYSTEM == "Linux":
            search = [
                "/usr/lib/python%s.%s/dist-packages" % (major, minor),
                "/usr/lib/python%s.%s/site-packages" % (major, minor),
                "/usr/share/pyshared",
            ]

        elif _SYSTEM == "Darwin":
            search = ["/Library/Python/%s.%s/site-packages" % (major, minor)]
        else:
            # No idea where to look...
            search = []

        # Generates a common prefix from sys.executable in the
        # case that vboxapi is installed in a virtualenv.
        # This will also help with when we don't know where
        # to search because of an unknown platform.
        # These paths also help if the system Python is installed
        # in a non-standard location.
        #
        # NOTE: We don't have to worry if these directories don't
        # exist as they're checked below.
        prefix = os.path.dirname(os.path.dirname(sys.executable))
        search.extend(
            [
                os.path.join(prefix, "Lib", "site-packages"),
                os.path.join(prefix, "Lib", "site-packages", "win32"),
                os.path.join(prefix, "Lib", "site-packages", "win32", "lib"),
                os.path.join(prefix, "lib", "site-packages"),
                os.path.join(prefix, "lib", "dist-packages"),
            ]
        )

        packages = set(packages)
        original_path = copy.copy(sys.path)
        for path in search:
            if not os.path.isdir(path):
                continue

            listing = set([os.path.splitext(f)[0] for f in os.listdir(path)])
            if packages.intersection(listing):
                sys.path.append(path)
            packages -= listing
            if not packages:
                break

        else:
            # After search each path we still failed to find
            # the required set of packages.
            raise

        import vboxapi

        try:
            yield vboxapi

        finally:
            sys.path = original_path
    else:
        yield vboxapi


class Manager(object):

    def __init__(self, mtype=None, mparams=None):
        pid = multiprocessing.current_process().ident
        if _MANAGERS is None:
            raise RuntimeError(
                "Can't create a new VirtualBox manager following a system exit."
            )

        if pid not in _MANAGERS:
            with import_vboxapi() as vboxapi:
                self.manager = vboxapi.VirtualBoxManager(mtype, mparams)

    @property
    def manager(self):
        if _MANAGERS is None:
            raise RuntimeError("Can not get the manager following a system exit.")

        return _MANAGERS[multiprocessing.current_process().ident]

    @manager.setter
    def manager(self, value):
        pid = multiprocessing.current_process().ident
        if _MANAGERS is None:
            raise RuntimeError("Can not set the manager following a system exit.")

        if pid not in _MANAGERS:
            _MANAGERS[pid] = value
        else:
            raise Exception("Manager already set for pid %s" % pid)

    def get_virtualbox(self):
        from ._xidl import VirtualBox
        return VirtualBox(interface=self.manager.getVirtualBox())

    def get_session(self):
        if hasattr(self.manager, "mgr"):
            manager = getattr(self.manager, "mgr")
        else:
            manager = self.manager
        from ._xidl import Session
        return Session(interface=manager.getSessionObject(None))

    def cast_object(self, interface_object, interface_class):
        name = interface_class.__name__
        i = self.manager.queryInterface(interface_object._interface, name)
        return interface_class(interface=i)

    @property
    def bin_path(self):
        return self.manager.getBinDir()


_VIRTUALBOX_EXCEPTIONS = {}


class VirtualBoxExceptionMeta(type):

    def __init__(cls, *_):
        if cls.value != -1:
            _VIRTUALBOX_EXCEPTIONS[cls.value] = cls


@six.add_metaclass(VirtualBoxExceptionMeta)
class VirtualBoxException(Exception):
    name = "undefined"
    value = -1
    message = ""

    def __init__(self, exc, errno, message):
        self.exc = exc
        self.errno = errno
        self.message = message


class Interface(object):

    def __init__(self, interface=None):
        if isinstance(interface, Interface):
            manager = Manager()
            self._interface = manager.cast_object(interface, self.__class__)._interface
        else:
            self._interface = interface

    def __nonzero__(self):
        return bool(self._interface)

    def _cast_to_value_type(self, value):

        def cast_to_value_type(value):
            if isinstance(value, Interface):
                return value._interface

            elif isinstance(value, enum.Enum):
                return int(value.value)

            else:
                return value

        if isinstance(value, list):
            return [cast_to_value_type(x) for x in value]

        else:
            return cast_to_value_type(value)

    def _search_property(self, name, prefix=None):
        property_names = [name]
        if prefix is not None:
            property_names.append(prefix + name[0].upper() + name[1:])
        for _ in range(3):
            for prop_name in property_names:
                prop = getattr(self._interface, prop_name, self)
                if prop is not self:
                    break

            else:
                time.sleep(0.1)
                continue

            break

        else:
            raise AttributeError("Failed to find attribute %s in %s" % (name, self))

        return prop

    def _get_property(self, name):
        attr = self._search_property(name, prefix="get")
        if inspect.isfunction(attr) or inspect.ismethod(attr):
            return self._call_method_internal(attr)

        else:
            return attr

    def _set_property(self, name, value):
        prop = self._search_property(name, prefix="set")
        if inspect.isfunction(prop) or inspect.ismethod(prop):
            return self._call_method_internal(prop, value)

        else:
            if isinstance(value, enum.Enum):
                value = int(value)
            return setattr(self._interface, name, value)

    def _call_method(self, name, *params):
        method = self._search_property(name)
        if inspect.isfunction(method) or inspect.ismethod(method):
            return self._call_method_internal(method, *params)

        else:
            return method

    def _call_method_internal(self, method, *params):
        params = [self._cast_to_value_type(param) for param in params]
        try:
            ret = method(*params)
        except Exception as exc:
            errno = getattr(exc, "errno", getattr(exc, "hresult", -1))
            errno &= 0xFFFFFFFF

            message = None
            if _SYSTEM == "Windows":
                if hasattr(exc, "args"):
                    message = exc.args[2][2]

            errcls = _VIRTUALBOX_EXCEPTIONS.get(errno, VirtualBoxException)
            errobj = errcls()
            errobj.message = message
            errobj.exc = exc
            errobj.errno = errno
            raise errobj

        return ret
