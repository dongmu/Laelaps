from os.path import abspath

class MemoryRange(object):
    """
    This class represents a MemoryRange which can be mapped in one of
    Avatar-Targets.

    :ivar address:      The load-address of the memory range
    :ivar size:         The size of the memory range
    :ivar name:         User-defined name for the memory range
    :ivar permissions:  The permisions of the range, represented as textual
                        unix file permission (rwx)
    :ivar file:         A file used for backing the memory range
    :ivar forwarded:    Enable or disable forwarding for this range
    :ivar forwarded_to: List of targets this range should be forwarded to
    """

    def __init__(self, address, size, name=None, permissions='rwx',
                 file=None, forwarded=False, forwarded_to=None, alias = False, **kwargs):
        self.address = address
        self.size = size
        self.name = (
            name
            if name is not None else
            "mem_range_0x{:08x}_0x{:08x}".format(address, address+size))
        self.permissions = permissions
        self.file = abspath(file) if file is not None else None
        self.forwarded = forwarded
        self.forwarded_to = forwarded_to
        self.alias = alias
        self.__dict__.update(kwargs)
