from json import dumps, loads


class JsonEncoder(object):
    @classmethod
    def dumps(cls, var):
        return dumps(var, sort_keys=True, separators=(',', ':')).encode('utf8')

    @classmethod
    def loads(cls, var):
        return loads(var)
