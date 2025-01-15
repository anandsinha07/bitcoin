# Bitcoin Musig2 Aggregated Public Key & Shcnorr Signatures

The process of generating an aggregated public key for Bitcoin transactions using Musig2 and Schnorr signatures. It includes steps to generate key pairs, aggregate public keys, derive a Pay-to-Taproot (P2TR) address, and sign & broadcast transactions.

## Prerequisites

- Python 3.x
- Install the necessary dependencies:
  ```bash
  python3 -m venv bitcoin_env
  source bitcoin_env/bin/activate
  pip3 install requests ecdsa bitcoinlib bitcoin

## Steps

### Step 1: Generate Key Pairs

This step generates individual key pairs (private and public keys) for users. In this project, 3 users are considered for the demonstration.

Run the following command to generate the key pairs:

```bash
python3 key_gen.py
```

This will generate private and public keys for each user and display them.

---

### Step 2: Aggregate Musig2 Public Keys

In this step, the public keys generated in the previous step are aggregated into a Musig2 public key. You need to hardcode the key pairs into the `aggregate_keys.py` file.

Run the following command to aggregate the keys:

```bash
python3 aggregate_keys.py
```

---

### Step 3: Derive Taproot Address

Using the aggregated public keys from Step 2, this step derives the P2TR (Taproot) address.

Run the following command to derive the Taproot address:

```bash
python3 derive_taproot.py
```

---

### Step 4: Sign and Broadcast the Transaction

This final step demonstrates Musig2 aggregation and Schnorr signature by signing and broadcasting a transaction. All reuired details are hardcoded in this step generated at previous steps

Run the following command to sign and broadcast the transaction:

```bash
python3 sign_and_broadcast.py
```


## Notes:
- Ensure that all necessary dependencies and libraries are installed before running the scripts.
- You can adjust the number of users or modify key pairs as needed by editing the Python scripts.
- Make sure environment is set up to interact with Bitcoin Testnet for broadcasting the transaction. This case virtual setup done.
- Functionalities are not yet fully functional and only meant for testnet4 environment for bitcoin transactions.


