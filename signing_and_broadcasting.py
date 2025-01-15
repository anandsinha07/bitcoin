import os
import time
import requests
from hashlib import sha256
from ecdsa.curves import SECP256k1
from ecdsa.ellipticcurve import Point
from datetime import datetime
from bitcoinlib.transactions import Transaction, Output, Input
import bitcoin

# Constants declarations for dynamic configurations for handling time related tasks
MAX_WAIT_TIME = 600  # Maximum wait time in seconds for locktime
SLEEP_INTERVAL = 10  # Interval between block height checks in seconds
MEMPOOL_API_URL = "https://mempool.space/testnet4/api"

# for schnorr signatures
curve = SECP256k1
n = curve.order
G = curve.generator

# Keys for participants
private_keys = [
    '707bdd67c2b9f2eeee4d09e8e596fbe7f7da4571f331dfde67bc8c2cac18cb2d',
    '72a3070314e7b94c3d5b25e2c37fbc0efabc290df03a8cd03b1c94153044c3a7',
    'b69dfd7678e239c1dc970ce45c25c3f5116b3785af47b6e45a419ae414c0ad80'
]

taproot_address = 'tb1pey7vyy8r79g9c6vwa37n955hvw6p4380r3l4x4y53lkek5c8aejsc2mk92' # as derived earlier where 3 utcos present
recipient_address = 'tb1ppdzf7kl4a8lua2fw626tjrcq92hx23f5pr0q7flauszt7fwuaxps4evugp' # just random receive p2tr address from sparrow wallet 
change_address = 'tb1pjv675ammca7kk5mlcuseynars5l67ksejzvftgenjfp4whjr58rs4d3ysm' # just random change p2tr address from sparrow wallet


def log_with_timestamp(message):
    """Log messages with a timestamp."""
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}")


# Schnorr Signature Helper Functions for nonce and other required utilities
def generate_nonce():
    """Generate a random scalar as the nonce."""
    return int.from_bytes(os.urandom(32), "big") % n


def hash_message(message, R_point):
    """Hash the message and R-point to create the challenge."""
    h = sha256()
    h.update(R_point.to_bytes(33, "big") + message)
    return int(h.hexdigest(), 16) % n


def generate_partial_signature(private_key, message):
    """Generating a partial Schnorr signaturse."""
    nonce = generate_nonce()
    R = nonce * G  # Commitment point
    if not curve.curve.contains_point(R.x(), R.y()):
        raise ValueError("Generated point is not on SECP256k1 curve.")
    R_bytes = int(R.x()).to_bytes(33, "big")  # Convert to compressed format
    e = hash_message(message, R.x())  # Challenge
    s = (nonce + e * private_key) % n  # Partial signature returns
    return s, R

def log_point(point, label):
    """Log whether a point is on the SECP256k1 curve."""
    try:
        if point is None:
            log_with_timestamp(f"{label}: Point is None")
            return
        if curve.curve.contains_point(point.x(), point.y()):
            log_with_timestamp(f"{label}: Valid point on SECP256k1 curve. X={point.x()}, Y={point.y()}")
        else:
            log_with_timestamp(f"{label}: Point is NOT on SECP256k1 curve! X={point.x()}, Y={point.y()}")
    except Exception as e:
        log_with_timestamp(f"{label}: Error validating point - {e}")


def log_transaction_inputs(inputs):
    """Log transaction input details using as_dict() from bitcoinlib explored"""
    for input_obj in inputs:
        try:
            input_details = input_obj.as_dict()
            log_with_timestamp(f"Input details: {input_details}")
        except Exception as e:
            log_with_timestamp(f"Error retrieving input details: {e}")

def verify_transaction_inputs(tx):
    """Verify each input in the transaction using its hash as suggested"""
    for i, input_obj in enumerate(tx.inputs):
        try:
            is_valid = input_obj.verify(bytes.fromhex(tx.txid))
            if is_valid:
                log_with_timestamp(f"Input {i} verification passed.")
            else:
                log_with_timestamp(f"Input {i} verification failed.")
        except Exception as e:
            log_with_timestamp(f"Error verifying input {i}: {e}")


def aggregate_signatures(signatures_and_points):
    """Aggregate partial Schnorr signatures."""
    partial_signatures, R_points = zip(*signatures_and_points)
    aggregated_signature = sum(partial_signatures) % n
    
    # Initialize R aggregation with a neutral point
    aggregated_R = None #as None
    for R in R_points:
        log_point(R, "Aggregating R Point")
        if aggregated_R is None:
            aggregated_R = R
        else:
            aggregated_R = aggregated_R + R  # curve-compatible addition

    if not curve.curve.contains_point(aggregated_R.x(), aggregated_R.y()):
        raise ValueError("Aggregated R is not on SECP256k1 curve.")
    
    log_with_timestamp(f"Aggregated signature: {aggregated_signature}, Aggregated R: {aggregated_R}")
    return aggregated_signature

# """Fetch UTXOs for a given address from Mempool.space Testnet4."""
def get_utxos(address):
    url = f"{MEMPOOL_API_URL}/address/{address}/utxo"
    response = requests.get(url)
    if response.status_code == 200:
        utxos = response.json()
        log_with_timestamp(f"Fetched {len(utxos)} UTXOs for address {address}.")
        if not utxos:
            log_with_timestamp("No UTXOs found.")
        return utxos
    else:
        log_with_timestamp(f"Error fetching UTXOs: {response.status_code} {response.text}")
        raise ValueError(f"Error fetching UTXOs: {response.status_code} {response.text}")

    """Fetch the current block height with retry logic..."""
def fetch_current_block_height(retries=3):
    url = f"{MEMPOOL_API_URL}/blocks/tip/height"
    for attempt in range(retries):
        try:
            response = requests.get(url)
            if response.status_code == 200:
                return response.json()
            else:
                log_with_timestamp(f"Attempt {attempt + 1} failed: {response.status_code} {response.text}")
        except Exception as e:
            log_with_timestamp(f"Error fetching block height: {e}")
        time.sleep(2)
    raise ValueError("Failed to fetch current block height after retries.")


    """Broadcast a raw transaction to Mempool.space Testnet and print the decoded transaction..."""
def send_raw_transaction(tx_hex):    
    try:
        """# Decode the transaction using the `bitcoin` library... can be removed since I incorporated utility functions from bitcoinlib.. keeping this for now"""
        decoded_tx = bitcoin.deserialize(tx_hex)
        log_with_timestamp(f"Decoded transaction: {decoded_tx}")
    except Exception as e:
        log_with_timestamp(f"Error decoding transaction: {e}")
        if "TX decode failed" in str(e):
            raise ValueError("Transaction seems to be missing inputs. Check input creation in create_and_broadcast_transaction.")
        else:
            raise ValueError(f"Failed to decode transaction: {e}")

    url = f"{MEMPOOL_API_URL}/tx"
    headers = {"Content-Type": "text/plain"}  # Ensures proper format
    try:
        response = requests.post(url, data=tx_hex, headers=headers, timeout=10)
        if response.status_code == 200:
            print(f"Transaction successfully broadcasted. TxID: {response.text}")
            return response.text
        else:
            print(f"Error broadcasting transaction: {response.status_code} {response.text}")
            raise ValueError(f"Error broadcasting transaction: {response.status_code} {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Request error: {e}")
        raise ValueError(f"Failed to broadcast transaction due to network error: {e}")


# to create transaction and then send to brodcast
def create_and_broadcast_transaction(locktime):
    utxos = get_utxos(taproot_address)
    if not utxos:
        raise ValueError("No UTXOs available for the address.")
    
    log_with_timestamp(f"Fetched UTXOs: {utxos}")
    total_input = sum(utxo['value'] for utxo in utxos)
    fee = 1000
    send_amount = int(total_input * 0.9)
    change_amount = total_input - send_amount - fee

    # Create outputs
    outputs = [
        Output(value=send_amount, address=recipient_address, network="testnet4"),
        Output(value=change_amount, address=change_address, network="testnet4")
    ]

    # Loging UTXOs and verifying their inclusion
    log_with_timestamp("Creating inputs for the transaction.")
    inputs = []
    for utxo in utxos:
        log_with_timestamp(f"UTXO details: txid={utxo['txid']}, vout={utxo['vout']}, value={utxo['value']}")
        inputs.append(Input(utxo['txid'], utxo['vout'], utxo['value']))  # Properly create input
    log_with_timestamp(f"Transaction inputs created: {inputs}")

    # Verify if any inputs were created
    if not inputs:
        raise ValueError("Failed to create transaction inputs. Check UTXOs.") 

    # Log the input and output details for further inspection
    log_with_timestamp(f"Transaction outputs: {outputs}")

    # Create transaction
    tx = Transaction(
        inputs=inputs,
        outputs=outputs,
        locktime=locktime,
        network="testnet4"
    )

    log_transaction_inputs(inputs)  # will log input details

    log_with_timestamp(f"Transaction hash before signing: {tx.txid}")

    # Aggregate and attach the signature
    partial_signatures_and_points = [
        generate_partial_signature(int(private_key, 16), bytes.fromhex(tx.txid))
        for private_key in private_keys
    ]
    aggregated_signature = aggregate_signatures(partial_signatures_and_points)
    tx.signatures = [aggregated_signature]

    log_with_timestamp(f"Transaction details: {tx.__dict__}")

# Verify transaction inputs
    verify_transaction_inputs(tx)

    tx_hex = tx.as_hex() 
    log_with_timestamp(f"Signed transaction hex: {tx_hex}")

    # Broadcast the transaction
    tx_id = send_raw_transaction(tx_hex)
    log_with_timestamp(f"Transaction broadcasted. TxID: {tx_id}")
    return tx_id
    
def wait_for_locktime(future_locktime):
    """Wait for locktime to pass with timeout handling."""
    start_time = time.time()
    while time.time() - start_time < MAX_WAIT_TIME:
        current_height = fetch_current_block_height()
        if current_height >= future_locktime:
            return
        log_with_timestamp(f"Current block height: {current_height}, waiting...")
        time.sleep(SLEEP_INTERVAL)
    raise TimeoutError("Timeout while waiting for locktime to pass.")


# Test Function for CLTVs
def test_cltv():
    """Test CLTV conditions."""
    current_height = fetch_current_block_height()
    future_locktime = current_height + 10
    try:
        create_and_broadcast_transaction(future_locktime)
        log_with_timestamp("FAIL: Transaction was broadcasted before locktime.")
    except Exception as e:
        log_with_timestamp(f"PASS: Expected failure before locktime: {e}")
    wait_for_locktime(future_locktime)
    try:
        create_and_broadcast_transaction(future_locktime)
        log_with_timestamp("PASS: Transaction successfully broadcasted after locktime.")
    except Exception as e:
        log_with_timestamp(f"FAIL: Unexpected error after locktime: {e}")


if __name__ == "__main__":
    test_cltv()