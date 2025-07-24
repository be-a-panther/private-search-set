import json 
import os
import glob
import sys
import time
import hashlib
import base64
#import uuid #uuidv7 since 3.14
import uuid_utils as uuid
from blake3 import blake3
import hmac
from private_search_set.bloom_filter_poppy import BloomFilterPoppy
from private_search_set.bloom_filter_dcso import BloomFilterDCSO

class UUIDEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, uuid.UUID):
            return str(obj)
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)

class PrivateSearchSet:
    def __init__(self, algorithm, canonicalization_format, description, generated_timestamp, keyid, misp_attribute_types, version, bloomfilter = None, filters=None, key_storage=None):

        self.algorithm = algorithm
        if version == 1:
            self.bloomfilter = bloomfilter
        elif version == 2:
            if bloomfilter != None:
                self.filters['bloomfilter'] = (bloomfilter)
            else:
                self.filters = filters
        self.canonicalization_format = canonicalization_format
        self.description = description
        if generated_timestamp is None:
            self.generated_timestamp = int(time.time())
        else:
            self.generated_timestamp = int(generated_timestamp)
        if version == 1:
            self.keyid = keyid
        elif version == 2:
            if keyid is None:
                self.keyid = uuid.uuid7(self.generated_timestamp)
            else:
                try:
                    self.keyid = uuid.UUID(str(keyid))
                except:
                    raise ValueError("UUID not decodable: ", keyid)
            if key_storage is None:
                self.key_storage = "infected"
            else:
                try:
                    self.key_storage = base64.b64decode(key_storage).decode()
                except:
                    raise ValueError("Base64 not decodable: ", key_storage)

        self.misp_attribute_types = misp_attribute_types
        self.version = version

    def print_private_search_set(private_search_set):
        print("Algorithm:", private_search_set.algorithm)
        if private_search_set.version == 1:
            print("Bloomfilter:", private_search_set.bloomfilter)
        elif private_search_set.version == 2:
            print("Filters:", private_search_set.filters)
        print("Canonicalization Format:", private_search_set.canonicalization_format)
        print("Description:", private_search_set.description)
        print("Generated Timestamp:", private_search_set.generated_timestamp)
        print("Key ID:", private_search_set.keyid)
        print("MISP Attribute Types:", private_search_set.misp_attribute_types)
        print("Version:", private_search_set.version)
        if private_search_set.version == 1:
          print("Key:", private_search_set._key)
        elif private_search_set.version == 2:
          print("HexKey:", private_search_set._key.hex())
        if hasattr(private_search_set, 'key_storage'):
            print("Key storage:", private_search_set.key_storage)
        if hasattr(private_search_set, '_timeseries'):
            print("Timeseries entries", len(private_search_set._timeseries))

    def load_from_json_specs(json_file, userpassword, debug):
        with open(json_file) as file:
            json_data = json.load(file)
            data = {k.replace('-', '_'): v for k, v in json_data.items()}
            pss = PrivateSearchSet(**data)  # Create an instance of the PrivateSearchSet class
        if set(data.keys()) == set(pss.__dict__.keys()):
            pss.init_filter_and_set()
            if userpassword is None:
                if pss.version == 1:
                    pss.init_key(data['keyid'])
                elif pss.version == 2:
                    pss.init_key()
            else:
                pss.init_key(userpassword)
                pss.key_storage = None
            if debug:
                if not data["generated_timestamp"]:
                    print("WARN new timestamp generated.", file=sys.stderr)
                PrivateSearchSet.print_private_search_set(pss)
            return pss
        else:
            raise ValueError("JSON file does not match the expected format.")
    
    def load_from_pss_home(pss_home, userpassword, debug):
        if os.path.exists(pss_home):
            file_path = os.path.join(pss_home, 'private-search-set.json')
            if os.path.exists(file_path):
                pss = PrivateSearchSet.load_from_json_specs(file_path, userpassword, False)
            else:
                raise ValueError("No JSON file found in the PSS home.")
        else:
            raise ValueError("PSS home does not exist.")
        file_path = os.path.join(pss_home, 'private-search-set.bloom')
        pss.load_bf_from_file(file_path) 
        file_path = os.path.join(pss_home, 'private-search-set.pss')
        pss._ps = pss.load_pss_from_file(file_path)
        pss.load_timeseries_from_path(pss_home)
        if debug:
            PrivateSearchSet.print_private_search_set(pss)
        return pss
    
    def load_bf_from_file(self, file_path):
        if os.path.exists(file_path):
            if self.version == 1:
                with open(file_path, 'rb') as f:
                    self._bf.load(f)
            elif self.version == 2:
                self._bf.load(file_path)
    
    def load_timeseries_from_path(self, path):
        self._timeseries = []
        if os.path.exists(path):
            for elem in glob.glob(path + "/private-search-set_*.bloom"):
                #elem.split("private-search-set_")[-1].split(".")[0]
                date = os.path.splitext((os.path.split(elem)[1].split("private-search-set_")[1]))[0]
                self._timeseries.append( (date, BloomFilterPoppy({'path' : elem})) )
 
    def load_pss_from_file(self, file_path):
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                return set(f.read().splitlines())
        else:
            return None
    
    def init_filter_and_set(self):
        # init bloom filter
        if self.version == 1:
          if self.bloomfilter['format'] in BloomFilterDCSO._formats:
              self._bf = BloomFilterDCSO(self.bloomfilter)
          else:
              raise ValueError("Bloomfilter format not supported.")
        elif self.version == 2:
            if self.filters['bloomfilter']['format'] in BloomFilterPoppy._formats:
                self._bf = BloomFilterPoppy(self.filters['bloomfilter'])
            else:
                raise ValueError("Bloomfilter format not supported.")
        
        # init the private search set
        self._ps = set()
  
    # default use of uuid V7 for random salt in combination with password
    # or use direct key material
    def init_key(self, key=None):
        if self.version == 1:
            if key is None:
                self.set_key('infected')
            else:
                self.set_key(key)
        elif self.version == 2:
            try:
               tmp = uuid.UUID(str(self.keyid))
            except:
                raise ValueError("UUID not decodable: ", self.keyid)
            else:
                if tmp.version == 7:
                    if key is None:
                        password = self.key_storage.encode()
                    else:
                        password=key.encode()
                        #TODO decrypt
                    self.set_key(hashlib.scrypt(password=password, salt=self.keyid.node.to_bytes(16), n=2048, r=8, p=1))
                elif tmp.version == 8:
                    self.set_key(key)
                    # possible place to call resolve_keyid function
                else:
                    raise ValueError("UUID not usuable")
    
    def set_key(self, key):
        self._key = key

    def get_key_storage(self):
        if self.key_storage != None:
            return self.key_storage

    def query_generator(self, data):
        if self.version == 1:
            if self.algorithm == 'Blake2':
                 hashed_string = hashlib.blake2b(data, key=self._key.encode()).hexdigest()
            else:
                raise ValueError("HMAC algorithm not supported.")
            return hashed_string
        elif self.version == 2:
            if self.algorithm == 'blake2b':
                hashed_string = hashlib.blake2b(data, \
                    key=self._key[0:63], \
                    salt=self._key[64:79], \
                    person=self._key[80:95]).hexdigest()
            elif self.algorithm == 'blake3':
                hashed_string = blake3(data,\
                        key=self._key[0:32]).hexdigest()
            elif self.algorithm == 'hmac-sha256':
                hashed_string = hmac.new(msg=data,\
                        key=self._key[0:32], digestmod=hashlib.sha256).hexdigest()
            elif self.algorithm == 'hmac-sha512':
                hashed_string = hmac.new(msg=data,\
                        key=self._key[0:32], digestmod=hashlib.sha512).hexdigest()
            else:
              raise ValueError("HMAC algorithm not supported.")
            return hashed_string
        return

    def ingest_stdin(self, bf, timeseries, debug):
        #create a new timestamp Bloom filter
        if timeseries:
            if not hasattr(self, '_timeseries'):
                self._timeseries = [(int(time.time()),BloomFilterPoppy(self.filters['bloomfilter']))]
            else:
                self._timeseries.append((int(time.time()),BloomFilterPoppy(self.filters['bloomfilter'])))
        # Read bytes from stdin
        for line in sys.stdin.buffer.read().splitlines():
            if self.canonicalization_format:
                line = eval(str(line)+"."+self.canonicalization_format, {"__builtins__":None, "line": line}, {})
            self.ingest(line, bf, timeseries, debug)
 
    def ingest(self, data, bf, timeseries, debug):
        hashed_string = self.query_generator(data)
        hashed_bytes = hashed_string.encode()

        # add the string digest to the private search set
        if debug:
            print(f"Ingesting in private search set: {hashed_string}")
        # check hashset in priority if available
        notKnown = False
        if self._bf != None and not self._bf.check(hashed_bytes):
          notKnown = True
        if self._ps != None and not bf:
            if notKnown:
                self._ps.add(hashed_string)
            elif not hashed_string in self._ps:
                self._ps.add(hashed_string)
        # add the utf8 encoded bytes representation of the hexdigest to the bloom filter
        if self.version == 1:
            if debug:
                print(f"Ingesting in bloom filter:     {hashed_bytes}")
            if notKnown:
                self._bf.add(hashed_bytes)
        elif self.version == 2:
            if self.filters["bloomfilter"]['format'] in self._bf._formats:
                if debug:
                    print(f"Ingesting in bloom filter:     {hashed_bytes}")
                if notKnown:
                    self._bf.add(hashed_bytes)
        if timeseries and self.version == 2:
            self._timeseries[-1][1].add(hashed_bytes)
            if debug:
                print(f"Ingesting in timeseries:     {hashed_bytes}")

    def check_stdin(self, bf, timeseries, debug):
        # Read bytes from stdin
        
        matchCounter = 0
        for line in sys.stdin.buffer.read().splitlines():
            if self.canonicalization_format:
                line = eval(str(line)+"."+self.canonicalization_format, {"__builtins__":None, "line": line}, {})
            resultLine = []
            # check hashset in priority
            if self._ps != None and bf == False:
                if debug:
                    print(f"Checking against private search set: {line}")
                if self.check_pss(line):
                    resultLine = [line]
                    matchCounter += 1
            elif self._bf.loaded:
                if debug:
                    print(f"Checking against bloom filter: {line}")
                if self.check_bf(line):
                    resultLine = [line]
                    matchCounter += 1
            else:
                raise ValueError("No private search set or bloom filter loaded.")
            if timeseries and resultLine:
                result = self.check_timeseries(line)
                for elem in result:
                    if elem is None:
                        if debug:
                            resultLine.append("--- --- -- --:--:-- ----")
                    else:
                        resultLine.append(time.asctime(time.gmtime(int(elem))))
            if resultLine:
                if debug:
                    print(resultLine, sep='\t')
                else:
                    print(resultLine)
        if self._bf._matchCount != 1 and self._bf._matchCount > matchCounter:
            print("MatchCount (", self._bf._matchCount ,") not reached!", matchCounter, file=sys.stderr)
 
    def check_pss(self, data):
        hashed_string = self.query_generator(data)
        if hashed_string in self._ps:
            return True
        else:
            return False
 
    def check_bf(self, data):
        hashed_bytes = self.query_generator(data).encode()
        if self.version == 1:
            if self.bloomfilter['format'] in BloomFilterDCSO._formats:
                return self._bf.check(hashed_bytes)
            else:
                raise ValueError("Bloomfilter format not supported.")
        elif self.version == 2:
            if self.filters['bloomfilter']['format'] in BloomFilterPoppy._formats:
                return self._bf.check(hashed_bytes)
            else:
                raise ValueError("Bloomfilter format not supported.")

    def check_timeseries(self, data):
        hashed_bytes = self.query_generator(data).encode()
        result = []
        if self.version == 2 and hasattr(self, '_timeseries'):
            for elem in self._timeseries:
                if elem[1].check(hashed_bytes):
                    result.append(elem[0])
                else:
                    result.append(None)
        return result
 
        
    def write_to_files(self, pss_home, bfonly = False):
        if not os.path.exists(pss_home):
            os.makedirs(pss_home)
        # Write the bloom filter
        PrivateSearchSet.print_private_search_set(self)
        file_path = os.path.join(pss_home, 'private-search-set.bloom')
        if self.version == 1:
            with open(file_path, 'wb') as f:
                self._bf.write(f)
        elif self.version == 2:
            self._bf.write(file_path)
            if hasattr(self, '_timeseries'):
                file_path = os.path.join(pss_home, 'private-search-set_' + str(self._timeseries[-1][0]) + '.bloom')
                self._timeseries[-1][1].write(file_path)
        # Write the JSON file
        file_path = os.path.join(pss_home, 'private-search-set.json')
        with open(file_path, 'w') as f:
            export = {k: v for k, v in self.__dict__.items() if k.startswith('_') != True}
            if self.version == 2 and export['key_storage']:
                export['key_storage'] = base64.b64encode(self.key_storage.encode()).decode('utf-8')
            f.write(json.dumps(export, cls=UUIDEncoder))
        if not bfonly:
            # Write the private search file
            file_path = os.path.join(pss_home, 'private-search-set.pss')
            with open(file_path, 'w') as f:
                for ps in self._ps:
                    f.write(f"{ps}\n")
