import numpy as np
from random import randrange
from copy import deepcopy
import pickle
import json
import base64
import socketio

class SecAggregator:
    def __init__(self, common_base, common_mod, dimensions, weights):
        self.secretkey = randrange(common_mod)
        self.base = common_base
        self.mod = common_mod
        self.pubkey = (self.base ** self.secretkey) % self.mod
        self.sndkey = randrange(common_mod)
        self.dim = dimensions
        self.weights = weights
        self.keys = {}
        self.id = ''

    def public_key(self):
        return self.pubkey

    def set_weights(self, wghts, dims):
        self.weights = wghts
        self.dim = dims

    def configure(self, base, mod):
        self.base = base
        self.mod = mod
        self.pubkey = (self.base ** self.secretkey) % self.mod

    def generate_weights(self, seed):
        np.random.seed(seed)
        return np.float32(np.random.rand(self.dim[0], self.dim[1]))

    def prepare_weights(self, shared_keys, myid):
        self.keys = shared_keys
        self.id = myid
        wghts = deepcopy(self.weights)
        for sid in shared_keys:
            if sid > myid:
                wghts += self.generate_weights((shared_keys[sid] ** self.secretkey) % self.mod)
            elif sid < myid:
                wghts -= self.generate_weights((shared_keys[sid] ** self.secretkey) % self.mod)
        wghts += self.generate_weights(self.sndkey)
        return wghts

    def reveal(self, keylist):
        wghts = np.zeros(self.dim)
        for each in keylist:
            if each < self.id:
                wghts -= self.generate_weights((self.keys[each] ** self.secretkey) % self.mod)
            elif each > self.id:
                wghts += self.generate_weights((self.keys[each] ** self.secretkey) % self.mod)
        return -1 * wghts

    def private_secret(self):
        return self.generate_weights(self.sndkey)


class SecAggClient:
    def __init__(self, serverhost, serverport):
        self.sio = socketio.Client()
        self.aggregator = SecAggregator(3, 100103, (10, 10), np.full((10, 10), 3, dtype=np.float32))
        self.id = ''
        self.keys = {}
        self.serverhost = serverhost
        self.serverport = serverport

    def start(self):
        self.register_handles()
        print("Starting")
        self.sio.connect(f"http://{self.serverhost}:{self.serverport}")
        self.sio.wait()

    def configure(self, b, m):
        self.aggregator.configure(b, m)

    def set_weights(self, wghts, dims):
        self.aggregator.set_weights(wghts, dims)

    def weights_encoding(self, x):
        return base64.b64encode(pickle.dumps(x)).decode()

    def weights_decoding(self, s):
        return pickle.loads(base64.b64decode(s))

    def register_handles(self):
        @self.sio.event
        def connect():
            print("Connected")

        @self.sio.event
        def disconnect():
            print("Disconnected")

        @self.sio.on('send_public_key')
        def on_send_pubkey(msg):
            self.id = msg['id']
            pubkey = {
                'key': self.aggregator.public_key()
            }
            self.sio.emit('public_key', pubkey)

        @self.sio.on('public_keys')
        def on_sharedkeys(keydict):
            self.keys = json.loads(keydict)
            print("KEYS RECEIVED: ", self.keys)
            weight = self.aggregator.prepare_weights(self.keys, self.id)
            weight = self.weights_encoding(weight)
            resp = {
                'weights': weight
            }
            self.sio.emit('weights', resp)

        @self.sio.on('send_secret')
        def on_send_secret(msg):
            secret = self.weights_encoding(-1 * self.aggregator.private_secret())
            resp = {
                'secret': secret
            }
            self.sio.emit('secret', resp)

        @self.sio.on('send_there_secret')
        def on_reveal_secret(keylist):
            resp = {
                'rvl_secret': self.weights_encoding(self.aggregator.reveal(keylist))
            }
            self.sio.emit('rvl_secret', resp)

if __name__ == "__main__":
    s = SecAggClient("127.0.0.1", 2019)
    s.set_weights(np.zeros((10, 10)), (10, 10))
    s.configure(2, 100255)
    s.start()
    print("Ready")
