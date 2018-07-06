class MachineSnapshots(object):
    def __init__(self, interface):
        self._interface = interface

    @property
    def current_snapshot(self):
        """Current snapshot of this machine. This is @c null if the machine
        currently has no snapshots. If it is not @c null, then it was
        set by one of
        :rtype: Snapshot
        """
        return Snapshot(self._get_property('currentSnapshot'))

    def get_snapshot(self, name_or_id):
        """Returns a snapshot of this machine with the given name or UUID.

        Returns a snapshot of this machine with the given UUID.
        A @c null argument can be used to obtain the first snapshot
        taken on this machine. To traverse the whole tree of snapshots
        starting from the root, inspect the root snapshot's
        :param str name_or_id:
            What to search for. Name or UUID of the snapshot to find
        :rtype: Snapshot
        :returns:
            Snapshot object with the given name.
        """
        ret = Snapshot(self._call_method('findSnapshot', name_or_id))
        return ret

    def take_snapshot(self, name, description, pause):
        """Saves the current execution state
        and all settings of the machine and creates differencing images
        for all normal (non-independent) media.
        See
        :param str name:
            Short name for the snapshot.
        :param str description:
            Optional description of the snapshot.
        :param bool pause:
            Whether the VM should be paused while taking the snapshot. Only
          relevant when the VM is running, and distinguishes between online
          (@c true) and live (@c false) snapshots. When the VM is not running
          the result is always an offline snapshot.
        :rtype: typing.Tuple[Progress, str]
        """
        progress, id_ = self._call_method('takeSnapshot', name, description, pause)
        progress = Progress(progress)
        return progress, id_

    def delete_snapshot(self, id_):
        """Starts deleting the specified snapshot asynchronously.
        See
        :param str id_:
            UUID of the snapshot to delete.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('deleteSnapshot', id_))
        return ret

    def delete_snapshot_and_all_children(self, id_):
        """Starts deleting the specified snapshot and all its children
        asynchronously. See
        :param str id_:
            UUID of the snapshot to delete, including all its children.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('deleteSnapshotAndAllChildren', id_))
        return ret

    def delete_snapshot_range(self, start_id, end_id):
        """Starts deleting the specified snapshot range. This is limited to
        linear snapshot lists, which means there may not be any other child
        snapshots other than the direct sequence between the start and end
        snapshot. If the start and end snapshot point to the same snapshot this
        method is completely equivalent to
        :param str start_id:
            UUID of the first snapshot to delete.
        :param str end_id:
            UUID of the last snapshot to delete.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('deleteSnapshotRange', start_id, end_id))
        return ret

    def restore_snapshot(self, snapshot):
        """Starts resetting the machine's current state to the state contained
        in the given snapshot, asynchronously. All current settings of the
        machine will be reset and changes stored in differencing media
        will be lost.
        See
        :param Snapshot snapshot:
            The snapshot to restore the VM state from.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('restoreSnapshot', snapshot))
        return ret
