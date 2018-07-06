class MachineCPUs(object):
    @property
    def count(self) -> int:
        """Number of virtual CPUs in the VM.
        :rtype: int
        """
        return int(self._get_property('CPUCount'))

    @property
    def hot_plugging_enabled(self) -> bool:
        """This setting determines whether VirtualBox allows CPU
        hotplugging for this machine.
        :rtype: bool
        """
        return bool(self._get_property('CPUHotPlugEnabled'))

    @property
    def cycle_usage_limit(self) -> int:
        """Means to limit the number of CPU cycles a guest can use. The unit
        is percentage of host CPU cycles per second. The valid range
        is 1 - 100. 100 (the default) implies no limit.
        :rtype: int
        """
        return int(self._get_property('CPUExecutionCap'))

    @property
    def portability_level(self) -> int:
        """Virtual CPUID portability level, the higher number the fewer newer
        or vendor specific CPU feature is reported to the guest (via the CPUID
        instruction).  The default level of zero (0) means that all virtualized
        feautres supported by the host is pass thru to the guest.  While the
        three (3) is currently the level supressing the most features.

        Exactly which of the CPUID features are left out by the VMM at which
        level is subject to change with each major version.
        :rtype: int
        """
        return int(self._get_property('CPUIDPortabilityLevel'))

    def get_cpu_property(self, property_):
        """Returns the virtual CPU boolean value of the specified property.
        :param CPUPropertyType property_:
            Property type to query.
        :rtype: bool
        :returns:
            Property value.
        """
        ret = bool(self._call_method('getCPUProperty', property_))
        return ret

    def set_cpu_property(self, property_, value):
        """Sets the virtual CPU boolean value of the specified property.
        :param CPUPropertyType property_:
            Property type to query.
        :param bool value:
            Property value.
        """
        self._call_method('setCPUProperty', property_, value)

    def get_cpuid_leaf_by_ordinal(self, ordinal):
        """Used to enumerate CPUID information override values.
        :param int ordinal:
            The ordinal number of the leaf to get.
        :rtype: typing.Tuple[int, int, int, int, int, int]
        """
        idx, idx_sub, val_eax, val_ebx, val_ecx, val_edx = self._call_method('getCPUIDLeafByOrdinal', ordinal)
        return idx, idx_sub, val_eax, val_ebx, val_ecx, val_edx

    def get_cpuid_leaf(self, idx, idx_sub):
        """Returns the virtual CPU cpuid information for the specified leaf.

        Currently supported index values for cpuid:
        Standard CPUID leaves: 0 - 0x1f
        Extended CPUID leaves: 0x80000000 - 0x8000001f
        VIA CPUID leaves:      0xc0000000 - 0xc000000f

        See the Intel, AMD and VIA programmer's manuals for detailed information
        about the CPUID instruction and its leaves.
        :param int idx:
            CPUID leaf index.
        :param int idx_sub:
            CPUID leaf sub-index (ECX).  Set to 0xffffffff (or 0) if not applicable.
        :rtype: typing.Tuple[int, int, int, int]
        """
        val_eax, val_ebx, val_ecx, val_edx = self._call_method('getCPUIDLeaf', idx, idx_sub)
        return val_eax, val_ebx, val_ecx, val_edx

    def set_cpuid_leaf(self, idx, idx_sub, val_eax, val_ebx, val_ecx, val_edx):
        """Sets the virtual CPU cpuid information for the specified leaf. Note that these values
        are not passed unmodified. VirtualBox clears features that it doesn't support.

        Currently supported index values for cpuid:
        Standard CPUID leaves: 0 - 0x1f
        Extended CPUID leaves: 0x80000000 - 0x8000001f
        VIA CPUID leaves:      0xc0000000 - 0xc000000f

        The subleaf index is only applicable to certain leaves (see manuals as this is
        subject to change).

        See the Intel, AMD and VIA programmer's manuals for detailed information
        about the cpuid instruction and its leaves.

        Do not use this method unless you know exactly what you're doing. Misuse can lead to
        random crashes inside VMs.
        :param int idx:
            CPUID leaf index.
        :param int idx_sub:
            CPUID leaf sub-index (ECX).  Set to 0xffffffff (or 0) if not applicable.
          The 0xffffffff causes it to remove all other subleaves before adding one
          with sub-index 0.
        :param int val_eax:
            CPUID leaf value for register eax.
        :param int val_ebx:
            CPUID leaf value for register ebx.
        :param int val_ecx:
            CPUID leaf value for register ecx.
        :param int val_edx:
            CPUID leaf value for register edx.
        """
        self._call_method('setCPUIDLeaf', idx, idx_sub, val_eax, val_ebx, val_ecx, val_edx)

    def remove_cpuid_leaf(self, idx, idx_sub):
        """Removes the virtual CPU cpuid leaf for the specified index
        :param int idx:
            CPUID leaf index.
        :param int idx_sub:
            CPUID leaf sub-index (ECX).  Set to 0xffffffff (or 0) if not applicable.
          The 0xffffffff value works like a wildcard.
        """
        self._call_method('removeCPUIDLeaf', idx, idx_sub)

    def remove_all_cpuid_leaves(self):
        """Removes all the virtual CPU cpuid leaves
        """
        self._call_method('removeAllCPUIDLeaves')