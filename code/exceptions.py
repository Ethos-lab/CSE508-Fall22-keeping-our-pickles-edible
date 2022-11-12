
class BaseCustomException(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __repr__(self):
        return self.msg


class PickleBinEnd(BaseCustomException):
    def __init__(self, byte_pos, message="Pickle binary has reached the data part"):
        self.byte_pos_prev = byte_pos
        self.message = message
        super.__init__(self.message)
