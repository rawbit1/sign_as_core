import ctypes

# Load the shared library
lib = ctypes.CDLL('./libsign.so')

# Define the argument types of the function
lib.find_low_r_signature_wrapper.argtypes = [ctypes.c_char_p, ctypes.c_char_p]

# Define the return type of the function
lib.find_low_r_signature_wrapper.restype = None

# Call the function
priv_key_hex = 'a8188b5621448098ae66fec001acff97b7b5dcfbe371b433455135794daec37a'
msg_hash_hex = '81fdf78421e2395807c9e41fa0b5ef2b587e5096d5eec43605fd669be824a872'

lib.find_low_r_signature_wrapper(priv_key_hex.encode(), msg_hash_hex.encode())
