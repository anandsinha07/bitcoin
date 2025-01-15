from bitcoinlib.keys import HDKey

# Generate individual keys
def generate_individual_keys(n=3):
    keys = []
    for _ in range(n):
        key = HDKey()  # Generate a new HDKey
        private_key = key.private_hex  # Extract private key in hex format
        public_key = key.public_hex  # Extract public key in hex format
        keys.append((private_key, public_key))
    return keys

# Display keys
keys = generate_individual_keys()
for i, (priv, pub) in enumerate(keys):
    print(f"User {i+1}: Private Key: {priv}, Public Key: {pub}")


# User 1: 
# Private Key: 707bdd67c2b9f2eeee4d09e8e596fbe7f7da4571f331dfde67bc8c2cac18cb2d,
# Public Key: 03bf52f56da5759f47469558745a542eeeb44a64aa5033f924b8488adc0e9e3d54

# User 2: 
# Private Key: 72a3070314e7b94c3d5b25e2c37fbc0efabc290df03a8cd03b1c94153044c3a7, 
# Public Key: 03a82a6bf68eec34c494dd04b7b764ab64ba9a76f1ec621652bd18204c84da6214
# User 3: 
# Private Key: b69dfd7678e239c1dc970ce45c25c3f5116b3785af47b6e45a419ae414c0ad80, 
# Public Key: 02cdc2bee6172652e70cd72f9b028d1d593cb45dc4004d19b10ee6660ba56be00c