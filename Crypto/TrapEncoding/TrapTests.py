from Crypto.Random import random
import string
import time
import numpy

debug_level = 0

def correctness(TE):
    for i in range(10):
        debug(2, "Getting random string...")
        to_test = rand_string(300)
        debug(1, "Testing encoding/decoding {0} of 10".format(i))
        if encode_decode(TE, to_test) == False:
            return False
    print("[+] Passed correctness!")
    return True

def encode_decode(TE, message):
    (index, cipherchunks) = TE.encode(message)
    if TE.verify(cipherchunks, index) == False:
        print("[x] Failed encoding: Problem with trap bits for {0}"
              .format(message)) 
        return False
    new_text = TE.decode(cipherchunks, index)
    if new_text != message:
        print("[x] Failed decoding: Expected {0} but got {1}"
              .format(new_text, message))
        return False

def rand_string(length=5):
    chars = list(string.ascii_uppercase + string.digits)
    ret = []
    for i in range(length):
        ret += [random.choice(chars)]
    return ''.join(ret)

def debug(level, msg):
    if level <= debug_level:
        print(msg)

########### PERFORMANCE ############
def vary_message_size(TE, min_bytes, max_bytes):
    print("Testing performance of strings from {0} to {1} kilobytes."
          .format(min_bytes/1000, max_bytes/1000))
    print("Size\tAvg Time\tAvg time per kB\tAvg kB/second")
    i = 0
    while min_bytes * (2 ** i) <= max_bytes:
        test_message_size(TE, min_bytes * (2 ** i))
        i += 1
    print("Done!")

def test_message_size(TE, total_bytes, trials=10):
    times = []
    for trial in range(trials):
        message = rand_string(total_bytes)
        times += [speed_encode_msg(TE, message)]
    print("{0}\t{1}\t{2}\t{3}"
          .format(total_bytes / 1000,
                  numpy.mean(times),
                  numpy.mean(times) / total_bytes / 1000,
                  total_bytes / 1000 / numpy.mean(times)))
    return total_bytes / 1000 / numpy.mean(times)

def speed_encode_msg(TE, message):
    start = time.time()
    TE.encode(message)
    stop = time.time()
    return stop - start
