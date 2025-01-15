import binascii
from hashlib import sha256
import segwit_addr
from ecdsa.curves import SECP256k1
from ecdsa.ellipticcurve import Point


# jsut helper functions for sha256
def my_sha256(data):
    """Compute SHA-256 hash."""
    return sha256(data).digest()


def taproot_tweak(pubkey_bytes, commitment):
    """
    Apply the Taproot tweak logic to derive the tweaked public key.
    This logic takes into account the commitment to ensure the resulting public key is valid for Taproot addresses.
    """
    if not commitment:
        raise ValueError("Commitment cannot be empty for Taproot tweak.")

    # Step 1: Hash the public key and the commitment together
    tweak_hash = my_sha256(pubkey_bytes + commitment)

    # Step 2: Converted the hash to a scalar (integer) for tweaking as is required from documentation
    tweak_int = int.from_bytes(tweak_hash, "big")

    # Step 3: Decode the original public key into an elliptic curve point
    curve = SECP256k1.curve
    generator = SECP256k1.generator
    x_coord = int.from_bytes(pubkey_bytes[1:], "big")  # Exclude the first byte (0x02 or 0x03)
    is_even = pubkey_bytes[0] == 0x02
    y_squared = (x_coord**3 + curve.a() * x_coord + curve.b()) % curve.p()
    y_coord = pow(y_squared, (curve.p() + 1) // 4, curve.p())
    if is_even != (y_coord % 2 == 0):
        y_coord = curve.p() - y_coord
    pubkey_point = Point(curve, x_coord, y_coord, generator.order())

    # Step 4: Apply the tweak: Q = P + H(P || c) * G as read from doc tweaking logic for p2tr address gen
    tweaked_point = pubkey_point + tweak_int * generator

    # Step 5: Convert the tweaked point back to a 32-byte public key
    tweaked_pubkey = tweaked_point.x().to_bytes(32, "big")

    return tweaked_pubkey


def derive_taproot_address_from_musig2_pubkey(musig2_pubkey, commitment):
    """
    Deriving Taproot address from a MuSig2 aggregated public key as generated earlier

    """
    try:
        # Step 1: Convert hex string to bytes
        pubkey_bytes = bytes.fromhex(musig2_pubkey)

        # Steps 2: Apply the Taproot tweak logic
        tweaked_pubkey = taproot_tweak(pubkey_bytes, commitment)

        # Step no. 3: Create the ScriptPubKey
        scriptpubkey = b"\x51" + b"\x20" + tweaked_pubkey  # Prefix 5120 to the tweaked public key very important as read from stackoverflow comments

        # Step 4: Extract version and program from the ScriptPubKey
        version = scriptpubkey[0] - 0x50 if scriptpubkey[0] else 0
        program = scriptpubkey[2:]

        # Step 5: Use segwit_addr file to generate the Bech32m address for encoding 
        taproot_address = segwit_addr.encode('tb', version, program)

        return taproot_address

    except Exception as e:
        print(f"Error during Taproot address derivation: {e}")
        return None


musig2_pubkey = "039afa1ae9084778a89a7f2352648f2c3d82ede6d8a2a7bf58d055d1d8e34d7de9"  # aggregated public key generated from previous step
commitment = my_sha256(b"MyCustomScript")  # could be anything as input
taproot_address = derive_taproot_address_from_musig2_pubkey(musig2_pubkey, commitment)

if taproot_address:
    print(f"Derived Taproot Address: {taproot_address}")
else:
    print("Failed to derive Taproot address.")


# Recent Derived Taproot Address: tb1pey7vyy8r79g9c6vwa37n955hvw6p4380r3l4x4y53lkek5c8aejsc2mk92 // Has 3 UTXOs received earlier from faucets
# https://mempool.space/testnet4/address/tb1pey7vyy8r79g9c6vwa37n955hvw6p4380r3l4x4y53lkek5c8aejsc2mk92