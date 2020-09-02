from intervaltree import IntervalTree


class AvatarPeripheral(object):
    def __init__(self, name, address, size, **kwargs):
        self.name = name
        self.address = address
        self.size = size
        self.read_handler = IntervalTree()
        self.write_handler = IntervalTree()


    def shutdown(self):
        """
        Some peripherals will require to be shutdowned when avatar exits.
        In those cases, this method should be overwritten.
        """
        pass

    def write_memory(self, address, size, value, pc, regs):
        offset = address - self.address
        # intervals = self.write_handler[offset:offset + size - 1]
        intervals = self.write_handler[offset:offset + size]
        if intervals == set():
            raise Exception("No write handler for peripheral %s at offset %d \
                            (0x%x)" % (self.name, offset,
                                       address))
        if len(intervals) > 1:
            raise Exception("Multiple write handler for peripheral %s\
                            at offset %d" % (self.name, offset))
        f = intervals.pop().data
        return f(offset, size, value, pc, regs)
        # return intervals.pop().data(offset, size, value, pc, regs)

    def read_memory(self, address, size, pc, regs):
        offset = address - self.address
        # intervals = self.read_handler[offset:offset + size - 1]
        intervals = self.read_handler[offset:offset + size]
        if intervals == set():
            raise Exception("No read handler for peripheral %s at offset %d \
                            (0x%x)" % (self.name, offset,
                                       address))
        if len(intervals) > 1:
            raise Exception("Multiple read handler for peripheral %s\
                            at offset %d" % (self.name, offset))
        f = intervals.pop().data
        return f(offset, size, pc, regs)
        # return intervals.pop().data(offset, size, pc, regs)
