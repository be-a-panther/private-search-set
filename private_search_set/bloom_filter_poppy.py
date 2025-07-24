import poppy
from private_search_set.bloom_filter_base import BloomFilterBase

class BloomFilterPoppy(BloomFilterBase):
    _formats = ['dcso-v1', 'poppy-v2']
    def __init__(self, parameters):
        super().__init__(parameters)
        if "path" in parameters.keys():
            self.bf = poppy.load(parameters['path'])
        elif parameters['format'] == 'dcso-v1':
            self.bf = poppy.BloomFilter.with_version(1,parameters['capacity'], parameters['fp-probability'])
        elif parameters['format'] == 'poppy-v2':
            self.bf = poppy.BloomFilter(parameters['capacity'], parameters['fp-probability'])
        if "matchCount" in parameters.keys():
            self._matchCount = int(parameters['matchCount'])

    def add(self, data):
        return self.bf.insert_bytes(data)

    def check(self, data):
        return self.bf.contains_bytes(data)

    # requires a path
    def load(self, path):
        try:
            self.bf = poppy.load(path)
        except:
            raise Exception("Bloom filter read failed for: ", path)
            return False
        else:
            self.loaded = True
            return True
        

    # requires a path
    def write(self, path):
        try:
            self.bf.save(path)
        except:
            raise Exception("Bloom filter write failed for: ", path)
            return False
        else:
            return True
