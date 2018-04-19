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

import re
import os
import builtins
import typing


BASE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EXTENSION_DIR = os.path.join(BASE_DIR, "codegen", "extensions")
HEX_REGEX = re.compile(r"^0x[0-9A-Fa-f]+$")
BASIC_TYPES = {"bytes", "int", "str", "bool"}


def pythonic_name(name: str) -> str:
    """Changes a name which is implemented in camelCase into a python_name
    """
    s1 = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    name = re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1).lower()
    if "v_box" in name:
        name = name.replace("v_box", "virtualbox")
    if hasattr(builtins, name) or name in ["global", "file"]:
        name += "_"
    if "_std_" in name or name.startswith("std"):
        name = name.replace("std_", "std")
    if "dn_d_" in name:
        name = name.replace("dn_d_", "drag_and_drop_")
    if name.startswith("hw"):
        name = "Hardware" + name[2:]
    for ipv in ["4", "6"]:
        if "_ip%s" % ipv in name:
            name = name.replace("ip%s" % ipv, "ipv%s" % ipv)
        elif "i_pv%s" % ipv in name:
            name = name.replace("i_pv%s" % ipv, "ipv%s" % ipv)
        elif "_rules%s" % ipv in name:
            name = name.replace("_rules%s" % ipv, "_rules_ipv%s" % ipv)
    if name == "i_sipv6":
        name = "is_ipv6"
    if "usbhid" in name:
        name = name.replace("usbhid", "usb_hid")
    if "3_d_" in name:
        name = name.replace("3_d_", "_3d_")
    if "2_d_" in name:
        name = name.replace("2_d_", "_2d_")
    return name


def python_type(type_: str, safearray: bool) -> str:
    """Changes a VirtualBox.xidl type into a Python type.
    """
    if type_ == "octet":
        pytype = "bytes"
    elif type_ in [
        "unsigned long", "long", "long long", "short", "octet", "unsigned short"
    ]:
        return "int"

    elif type_ in ["wstring", "uuid"]:
        pytype = "str"
    elif type_ == "boolean":
        pytype = "bool"
    elif type_.startswith("I"):
        pytype = class_type(type_[1:])

    elif type_[0].upper() == type_[0]:
        pytype = class_type(type_)

    else:
        raise ValueError(f"Unknown type: {type_}")

    if safearray:
        return f"typing.List[{pytype}]"

    return pytype


def class_type(type_: str) -> str:
    if "Dhcp" in type_:
        type_ = type_.replace("Dhcp", "DHCP")
    return type_


def error_type(type_: str) -> str:
    new_type = []
    to_cap = True
    for c in type_:
        if c == "_":
            to_cap = True
        elif to_cap:
            new_type.append(c.upper())
            to_cap = False
        else:
            new_type.append(c.lower())
    return "".join(new_type)


class ErrorRender(object):

    def __init__(self, name, value, desc):
        self.name = name
        self.value = value
        self.desc = desc

    def render(self):
        return [
            f"class {error_type(self.name.replace('VBOX_E_', ''))}(VirtualBoxException):",
            f'    """{self.desc}"""',
            f"    name = {self.name!r}",
            f"    value = {hex(self.value).upper().replace('X', 'x')}",
        ]

    def __repr__(self):
        return f"<ErrorRender name={self.name} value={hex(self.value)}"


class EnumRender(object):

    def __init__(self, name, desc, value_renders):
        self.name = name
        self.desc = desc
        self.value_renders = value_renders

    def render(self) -> typing.List[str]:
        data = [f"class {class_type(self.name)}(enum.Enum):"]
        if self.desc is not None:
            data.append(f'    """{self.desc}')
        else:
            data.append(f'    """')
        for value_render in self.value_renders:
            if value_render.desc is not None:
                data.append(
                    f"     .. describe:: {pythonic_name(value_render.name).upper().rstrip('_')} {value_render.desc}"
                )
        data.append('    """')

        for value_render in self.value_renders:
            data.extend(value_render.render())
        return data

    def __repr__(self):
        return f"<EnumRender name={self.name} values={self.value_renders}>"


class EnumValueRender(object):

    def __init__(self, name, value, desc):
        self.name = name
        if HEX_REGEX.match(value):
            value = int(value[2:], 16)
        elif value.isdigit():
            value = int(value)
        self.value = value
        self.desc = desc

    def render(self) -> typing.List[str]:
        return [f"    {pythonic_name(self.name).upper().rstrip('_')} = {self.value!r}"]

    def __repr__(self):
        return f"<EnumValueRender name={self.name} value={self.value}>"


class MethodRender(object):

    def __init__(self, name, desc, params_in, params_out):
        self.name = name
        self.desc = desc
        self.params_in = params_in  # type: typing.List[typing.Tuple[str, str, bool, str]]
        self.params_out = params_out

    def render(self) -> typing.List[str]:
        # Determines the parameters of the function and create the function definition.
        pythonic_params = [pythonic_name(p) for p, _, _, _ in self.params_in]

        if len(pythonic_params) > 0:
            def_params = ", " + ", ".join(pythonic_params)
        else:
            def_params = ""
        data = [
            f"    def {pythonic_name(self.name)}(self{def_params}):",
            f'        """{self.desc}',
        ]

        # Creates the descriptions for each parameter.
        for name, type_, safearray, desc in self.params_in:
            data.append(
                f"        :param {python_type(type_, safearray)} {pythonic_name(name)}:"
            )
            if desc is not None:
                data.append(f"            {desc}")

        # If there's a return type (or tuple) then we need to add to the description.
        if len(self.params_out) > 0:

            # If there's only one then we don't return a tuple, just a single value.
            if len(self.params_out) == 1:
                _, type_, safearray, desc = self.params_out[0]
                data.append(f"        :rtype: {python_type(type_, safearray)}")
                if desc is not None:
                    data.extend(["        :returns:", "            " + desc])

            # More than one value then it's either a single tuple or a list of tuples.
            else:
                # List of tuples.
                if all(x[2] for x in self.params_out):
                    data.append(
                        f"        :rtype: typing.List[typing.Tuple[%s]]"
                        % (
                            ", ".join(
                                [
                                    python_type(type_, False)
                                    for _, type_, _, _ in self.params_out
                                ]
                            )
                        )
                    )

                # Single tuple.
                else:
                    data.append(
                        "        :rtype: typing.Tuple[%s]"
                        % (
                            ", ".join(
                                [
                                    python_type(type_, safearray)
                                    for _, type_, safearray, _ in self.params_out
                                ]
                            )
                        )
                    )

        # End of the docstring.
        data.append('        """')

        # Creates parameters for the _call_method() method.
        call_method_params = ", ".join([pythonic_name(p[0]) for p in self.params_in])
        if len(self.params_in) > 0:
            call_method_params = ", " + call_method_params

        if len(self.params_out) > 1:
            unpacked_tuple = ", ".join(pythonic_name(p[0]) for p in self.params_out)
            data.append(
                f"        {unpacked_tuple} = self._call_method('{self.name}'{call_method_params})"
            )
            for param_out_name, param_out_type, _, _ in self.params_out:
                param_out_type = python_type(param_out_type, False)
                if param_out_type.startswith("typing.List"):
                    param_out_type = "list"
                if param_out_type not in BASIC_TYPES:
                    data.append(
                        f"        {pythonic_name(param_out_name)} = {param_out_type}({pythonic_name(param_out_name)})"
                    )
            data.append(f"        return {unpacked_tuple}")
        elif len(self.params_out) == 1:
            _, param_out_type, _, _ = self.params_out[0]
            param_out_type = python_type(param_out_type, False)
            if param_out_type.startswith("typing.List"):
                param_out_type = "list"
            data.extend(
                [
                    f"        ret = {param_out_type}(self._call_method('{self.name}'{call_method_params}))",
                    "        return ret",
                ]
            )
        else:
            data.append(
                f"        self._call_method('%s'%s)" % (self.name, call_method_params)
            )
        return data

    def __repr__(self):
        return f"<MethodRender name={self.name} in={self.params_in} out={self.params_out}>"


class PropertyRender(object):

    def __init__(self, name, desc, type_, safearray, read_only):
        self.name = name
        self.desc = desc
        self.type_ = type_
        self.safearray = safearray
        self.read_only = read_only

    def render(self) -> typing.List[str]:
        data = [
            "    @property",
            f"    def {pythonic_name(self.name)}(self):",
            f'        """{self.desc}',
            f"        :rtype: {python_type(self.type_, self.safearray)}",
            '        """',
        ]

        rtype = python_type(self.type_, False)
        if self.safearray:
            if rtype in BASIC_TYPES:
                data.append(f"        return list(self._get_property('{self.name}'))")
            else:
                data.append(
                    f"        return [{rtype}(obj) for obj in self._get_property('{self.name}')]"
                )
        else:
            if rtype in BASIC_TYPES:
                data.append(f"        return self._get_property('{self.name}')")
            else:
                data.append(
                    f"        return {rtype}(self._get_property('{self.name}'))"
                )

        if not self.read_only:
            data.extend(
                [
                    "",
                    f"    @{pythonic_name(self.name)}.setter",
                    f"    def {pythonic_name(self.name)}(self, value):",
                    f'        """:type value: {python_type(self.type_, self.safearray)}',
                    '        """',
                    f"        self._set_property('{self.name}', value)",
                ]
            )

        return data

    def __repr__(self):
        return f"<PropertyRender name={self.name} type={self.type_} array={self.safearray} read_only={self.read_only}>"


class InterfaceRender(object):

    def __init__(self, name, desc, inherit, property_renders, method_renders):
        self.name = name
        self.desc = desc
        self.inherit = inherit
        self.property_renders = property_renders
        self.method_renders = method_renders

    def load_extension(self):
        ext_path = os.path.join(EXTENSION_DIR, self.name.lower()) + ".py"
        if os.path.isfile(ext_path):
            past_license = False
            data = []
            with open(ext_path) as f:
                for line in f:
                    if not past_license:
                        if line.startswith("#"):
                            continue

                        else:
                            data.append(line)
                            past_license = True
                    else:
                        data.append(line)
            return "".join(data).strip().replace("(object):", "(_%s):" % self.name)

        else:
            return ""

    def render(self) -> typing.List[str]:
        data = []
        extension_code = self.load_extension()
        if self.inherit:
            data.append("class %s(%s):" % (class_type(self.name), self.inherit))
        else:
            data.append("class %s(Interface):" % class_type(self.name))
        if extension_code:
            data[0] = data[0].replace("class ", "class _")

        if self.desc:
            data.extend(['    """%s' % self.desc, '    """'])

        for method_render in self.method_renders:
            data.extend(method_render.render())
            data.append("")
        for property_render in self.property_renders:
            data.extend(property_render.render())
            data.append("")

        if extension_code:
            data.append(extension_code)

        if len(data) == 1:
            data.append("    pass")

        return data

    def __repr__(self):
        return f"<InterfaceRender name={self.name} extends={self.inherit} properties={self.property_renders} methods={self.method_renders}>"
