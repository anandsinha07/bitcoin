from ecdsa import SECP256k1
from ecdsa.keys import SigningKey, VerifyingKey
import hashlib
import random
import binascii
import hmac
import os

# to work with EC points
def get_point_from_pubkey(pubkey):
    """ Will return the EC point from a compressed public key """
    vk = VerifyingKey.from_string(bytes.fromhex(pubkey), curve=SECP256k1)
    return vk.pubkey.point

def get_compressed_pubkey_from_point(point):
    """ retruning the compressed public key from EC point """
    x_bytes = point.x().to_bytes(32, byteorder='big')
    y_bytes = point.y().to_bytes(32, byteorder='big')
    
    prefix = 0x02 if point.y() % 2 == 0 else 0x03  # Even or odd y coordinate
    return bytes([prefix]) + x_bytes  # 33 bytess

# Round 1: Each user generates a private key, nonce, and commitment since musig2 reuires 2 rounds
def generate_nonce_and_commitment(private_key_hex, index=0):
    """ Generate nonce and commitment for a user (using deterministic nonce generation so we get same key everytime) """
    private_key = bytes.fromhex(private_key_hex)
    signing_key = SigningKey.from_string(private_key, curve=SECP256k1)
    pub_key = signing_key.get_verifying_key().to_string()

    # Using HMAC to generate a deterministic nonce based on private key and an index (for unique nonces)
    nonce = int(hmac.new(private_key, index.to_bytes(32, byteorder='big'), hashlib.sha256).hexdigest(), 16)
    
    # Get the generator point from SECP256k1 curve
    generator = SECP256k1.generator
    nonce_point = generator * nonce  # Multiply the generator by the nonce value
    
    # Convert the PointJacobi to compressed byte format and create the commitment
    nonce_point_compressed = get_compressed_pubkey_from_point(nonce_point)
    commitment = hashlib.sha256(nonce_point_compressed).hexdigest()  # Use compressed form
    
    return pub_key.hex(), commitment, nonce

# Round 2: Aggregating here the public keys and nonce commitments
def aggregate_public_keys(public_keys, nonces, commitments):
    """ Aggregate public keys and their corresponding commitments (round 2) """
    # Step 1: Combine all public keys (sum of points on the curve)
    aggregated_point = None  # Startwith None...
    for pub_key in public_keys:
        point = get_point_from_pubkey(pub_key)
        if aggregated_point is None:
            aggregated_point = point
        else:
            aggregated_point += point
    
    # Step 2: Combine all nonces (same as public keys aggregation)
    aggregated_nonce = None  # Start with None, represents point at infinity..
    for nonce in nonces:
        nonce_point = SECP256k1.generator * nonce
        if aggregated_nonce is None:
            aggregated_nonce = nonce_point
        else:
            aggregated_nonce += nonce_point

    # Step 3: Tweak the aggregated public key as is required when dealing with taproot
    tweak_input = ''.join(commitments).encode()
    
    # Add the x-coordinate of the aggregated nonce to the tweak input since y is irrelevant
    nonce_x_bytes = aggregated_nonce.x().to_bytes(32, byteorder='big')
    tweak_input += nonce_x_bytes  # Add the x-coordinate of the nonce to the tweak input
    
    tweak_hash = hashlib.sha256(tweak_input).digest()
    
    # The final tweaked key (for Taproot) is aggregated with a tweak
    final_aggregated_point = aggregated_point + SECP256k1.generator * int.from_bytes(tweak_hash, "big")

    # Step 4: Return the final aggregated public key
    return get_compressed_pubkey_from_point(final_aggregated_point)

# Test inputs (the public keys generated earlier am using them here)
public_keys = [
    '03bf52f56da5759f47469558745a542eeeb44a64aa5033f924b8488adc0e9e3d54',
    '03a82a6bf68eec34c494dd04b7b764ab64ba9a76f1ec621652bd18204c84da6214',
    '02cdc2bee6172652e70cd72f9b028d1d593cb45dc4004d19b10ee6660ba56be00c'
]

private_keys = [
    '707bdd67c2b9f2eeee4d09e8e596fbe7f7da4571f331dfde67bc8c2cac18cb2d',
    '72a3070314e7b94c3d5b25e2c37fbc0efabc290df03a8cd03b1c94153044c3a7',
    'b69dfd7678e239c1dc970ce45c25c3f5116b3785af47b6e45a419ae414c0ad80'
]

# Generate nonces and commitments for round 1
user_pubkeys = []
user_nonces = []
user_commitments = []

for i, pk in enumerate(private_keys):
    pub_key, commitment, nonce = generate_nonce_and_commitment(pk, i)
    user_pubkeys.append(pub_key)
    user_commitments.append(commitment)
    user_nonces.append(nonce)

# Perform the aggregation in round 2
final_aggregated_key = aggregate_public_keys(user_pubkeys, user_nonces, user_commitments)

# Output the final aggregated key
print("Final Aggregated Public Key (Compressed):", final_aggregated_key.hex())


# Final Aggregated Public Key (Compressed): 039afa1ae9084778a89a7f2352648f2c3d82ede6d8a2a7bf58d055d1d8e34d7de9