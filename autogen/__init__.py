# Copyright 2018 Seth Michael Larson (sethmichaellarson@protonmail.com)
# Copyright 2013 Michael Dorman (mjdorma@gmail.com)
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import re
import sys
import shutil
import tarfile
import requests
from lxml import etree
from autogen.render import (
    EnumRender, EnumValueRender, InterfaceRender, MethodRender, PropertyRender
)


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XIDL_HEADER = """# Copyright 2018 Seth Michael Larson (sethmichaellarson@protonmail.com)
# Copyright 2013 Michael Dorman (mjdorma@gmail.com)
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import enum
from ._base import Interface
"""

XIDL_FOOTER = """
class VirtualBox(VirtualBox):
    def __init__(self, interface=None, manager=None):
        if interface is not None:
            super(VirtualBox, self).__init__(interface)
        elif manager is not None:
            self._interface = manager.get_virtualbox()._interface
        else:
            from ._base import Manager
            manager = Manager()
            self._interface = manager.get_virtualbox()._interface
"""


def download_master(downloads):
    print("Downloading master")
    for dest, code in downloads:
        url = "http://www.virtualbox.org/svn/vbox/trunk/%s" % code
        with open(dest, "wb") as f:
            with requests.get(url, stream=True) as r:
                for chunk in r.iter_content(16384):
                    f.write(chunk)


def download_stable(downloads):
    with requests.get("https://www.virtualbox.org/wiki/Downloads") as r:
        page = r.content

    if isinstance(page, bytes) and not isinstance(page, str):
        page = page.decode("utf-8")

    match = re.search(
        "https?://download\.virtualbox\.org/virtualbox/([0-9.]+)/VirtualBox-([0-9.]+).tar.bz2",
        page,
    )
    if not match:
        raise RuntimeError("Failed to find source tarball url")

    sourceurl = page[match.start():match.end()]
    bzname = sourceurl.split("/")[-1]
    tarname = os.path.splitext(bzname)[0]

    print("Downloading %s" % bzname)
    with open(bzname, "wb") as f:
        f.truncate()
        with requests.get(sourceurl, stream=True) as r:
            for chunk in r.iter_content(1024 * 1024 * 10):
                f.write(chunk)

    print("Extracting %s" % bzname)
    tar = tarfile.open(bzname, "r:bz2")
    tar.extractall()
    source_dir = os.path.splitext(tarname)[0]
    shutil.rmtree(source_dir)

    for dest, code in downloads:
        shutil.copy(os.path.join(BASE_DIR, source_dir, code), dest)


def main():
    downloads = [
        (os.path.join(BASE_DIR, os.path.basename(filename)), filename)
        for filename in ["Config.kmk", "src/VBox/Main/idl/VirtualBox.xidl"]
    ]
    if sys.argv[1] == "local":
        pass
    elif sys.argv[1] == "master":
        download_master(downloads)
    else:
        download_stable(downloads)

    with open(os.path.join(BASE_DIR, "VirtualBox.xidl"), "rb") as f:
        xml = etree.parse(f)

    renders = []

    for el in xml.iter():
        if el.tag == "enum":
            enum_reader_desc = None
            value_renders = []
            for value in el.getchildren():
                if value.tag == "const":
                    enum_value_desc = None
                    for subvalue in value.getchildren():
                        if subvalue.tag == "desc":
                            enum_value_desc = subvalue.text
                            break

                    value_renders.append(
                        EnumValueRender(
                            value.get("name"),
                            value.get("value"),
                            enum_value_desc,
                        )
                    )
                elif value.tag == "desc":
                    enum_reader_desc = value.text
            enum_render = EnumRender(
                el.get("name"), enum_reader_desc, value_renders
            )
            renders.append(enum_render)

        elif el.tag == "interface":
            if el.get('name') == 'IVirtualBox':
                print('!!!')
                should_break = False
                for r in renders:
                    if hasattr(r, 'name') and r.name == el.get('name'):
                        should_break =True
                        break
                if should_break:
                    continue

            extends = el.get("extends")
            if extends is None or extends == "$unknown" or extends == "$errorinfo":
                extends = "Interface"
            elif extends.startswith("I"):
                extends = extends[1:]

            desc = None
            property_renders = []
            method_renders = []

            for child in el.getchildren():
                if child.tag == "desc":
                    desc = child.text.strip()
                elif child.tag == "attribute":
                    property_desc = None
                    for child_desc in child.getchildren():
                        if child_desc.tag == "desc" and child_desc.text is not None:
                            property_desc = child_desc.text.strip()
                    property_type = child.get("type")
                    if property_type == "$unknown":
                        property_type = "IInterface"
                    property_renders.append(
                        PropertyRender(
                            name=child.get("name"),
                            desc=property_desc,
                            type_=property_type,
                            safearray=child.get("safearray") == "yes",
                            read_only=child.get("readonly") in [None, "yes"],
                        )
                    )
                elif child.tag == "method":
                    params_in = []
                    params_out = []
                    param_return = None

                    for param in child.getchildren():
                        if param.tag == "param":
                            param_desc = None
                            for param_el in param.getchildren():
                                if param_el.tag == "desc" and param_el.text is not None:
                                    param_desc = param_el.text.strip()
                            param_type = param.get("type")
                            if param_type == "$unknown":
                                param_type = "Interface"
                            param_tuple = (
                                param.get("name"),
                                param_type,
                                param.get("safearray") == "yes",
                                param_desc,
                            )
                            if param.get("dir") == "in":
                                params_in.append(param_tuple)
                            elif param.get("dir") == "out":
                                params_out.append(param_tuple)
                            elif param.get("dir") == "return":
                                param_return = param_tuple

                    if param_return is not None:
                        params_out.insert(0, param_return)

                    method_renders.append(
                        MethodRender(
                            name=child.get("name"),
                            desc=child.get("desc"),
                            params_in=params_in,
                            params_out=params_out,
                        )
                    )

            interface_render = InterfaceRender(
                name=el.get("name")[1:],
                desc=desc,
                inherit=extends,
                property_renders=property_renders,
                method_renders=method_renders,
            )
            renders.append(interface_render)

    with open(os.path.join(BASE_DIR, "virtualbox", "_xidl.py"), "w") as f:
        f.truncate()
        f.write(XIDL_HEADER)
        for render in renders:
            for l in render.render():
                f.write(l + "\n")
            f.write("\n")
        f.write(XIDL_FOOTER)
