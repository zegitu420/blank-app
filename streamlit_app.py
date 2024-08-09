import streamlit as st

from solders.keypair import Keypair
from solana.rpc.api import Client
from solana.transaction import Transaction
from solana.rpc.types import TxOpts

from cryptography.fernet import Fernet

import os
import ast
import base64
import binascii
import requests
import asyncio
import base64
import random
import time

# Set environment variables
ENV = os.getenv('cluster', 'mainnet-beta')
SOLANA_RPC_ENDPOINT = 'https://api.devnet.solana.com' if ENV == 'devnet' else 'https://jupiter.genesysgo.net/'

# List of Solana RPC endpoints
SOLANA_RPC_ENDPOINT_LIST = [
    'https://api.mainnet-beta.solana.com',
    'https://try-rpc.mainnet.solana.blockdaemon.tech/'
]

# Define the same algorithm and key/IV used during encryption
# key = Fernet.generate_key()
# data = [88,59,239]
key = b"jLGm6CfVxPSxKVuC6yyJEWhv0vrHjSKgsXNXbL2xw-g="
fernet = Fernet(key)
# encrypted_data = fernet.encrypt(data)
encrypted_data = b"gAAAAABmtX08VOjxhkx7K6RwjD_BcP4tYeGypl7vFtE_i_KqMZl6sP5uLmHEt4pcMSfBBGYM1TD5w8_ocqdjkc6W9-Cn3qLW9uzAy4PCrxEiktjfCJjRyqukAju8x5UNvMJVHJ4mtHg-2oYe7cAAUjO7atvlw0pwrOsZryfhi7V0DdZV5MJxSmpdGeOxB5BH1zVBkYH56XUgP7Cb94hCTEKRBPFKqUEg-9iQvoD7mJkk2blmyDsweQqpenIcqqXA25-9vqhU0sPJT5V2VAijr4L_oKN6u2iDijc_yyxDacX1vnDRy5YDV2PpV1GiPH5BfDzUcq7EMGIAj6JwndkddDjieczKIoMaCbILJ6WC5eci9zZXf6j-uTE1HRp955iyrciPH_E1EpDC"
decrypted_data = fernet.decrypt(encrypted_data)
# print("key:", key)
# print("Encrypted data:", encrypted_data)
# print("Decrypted data:", decrypted_data)

decoded_string = decrypted_data.decode('utf-8')
data_list = ast.literal_eval(decoded_string)
# print("Decrypted data:", data_list)

# Generate USER_KEYPAIR
USER_KEYPAIR = Keypair().from_bytes(data_list)
print(USER_KEYPAIR.pubkey())

def delay(seconds):
    time.sleep(seconds)

async def recheck(input_mint: str, output_mint: str, input_amount: str, output_amount: str) -> bool:
    print("recheck")
    print("inputToken: ", input_mint)
    print("outputToken: ", output_mint)
    print("inputAmount: ", input_amount)
    print("outputAmount: ", output_amount)

    response = requests.get(
        f"https://quote-api.jup.ag/v6/quote?inputMint={input_mint}&outputMint={output_mint}&amount={input_amount}&slippageBps=25",
        headers={'User-Agent': ''}
    )
    route_json = response.json()
    print("outputAmount1: ", output_amount)
    print("outputAmount2: ", route_json['outAmount'])

    return route_json['outAmount'] >= output_amount

async def order(route: dict):
    print("route")
    print(route)

    response = requests.post(
        "https://quote-api.jup.ag/v6/swap",
        json={
            "route": route,
            "userPublicKey": USER_KEYPAIR.pubkey,
            "wrapUnwrapSOL": True,
        },
        headers={'Content-Type': 'application/json', 'User-Agent': ''}
    )
    transaction_json = response.json()
    print("transactionResponse")
    print(transaction_json)

    swap_transaction_buf = base64.b64decode(transaction_json['swapTransaction'])
    transaction = Transaction.deserialize(swap_transaction_buf)
    transaction.sign([USER_KEYPAIR])

    rpc = random.choice(SOLANA_RPC_ENDPOINT_LIST)
    client = Client(rpc)
    print(rpc)

    raw_transaction = transaction.serialize()
    txid = await client.send_raw_transaction(raw_transaction, opts=TxOpts(skip_preflight=True, max_retries=2))
    await client.confirm_transaction(txid)
    print(f"https://solscan.io/tx/{txid}")

async def start_roop():
    USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    USDT = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
    PAI = "Ea5SjE2Y6yvCeW5dYTn7PYMuW5ikXkvbGdcmSnXeaLjS"
    SOL = "So11111111111111111111111111111111111111112"
    BTC = "9n4nbM75f5Ui33ZbPYXn59EwSgE8CGsHtAeTH5YFeJ9E"
    ETH = "7vfCXTUXx5WJV5JADk17DUJ4ksgau7utNKj4b963voxs"
    RAY = "4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R"
    SRM = "SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt"
    GMT = "7i5KKsX2weiTkry7jA4ZwSuXGhs5eJBEjY8vVxR4pfRx"
    BTC = "3NZ9JMVBmGAqocybic2c7LQCJScmgsAZ6vQqTDzcqmJh"
    
    pairs_list = [
        [SOL, ETH, BTC],
        [SOL, BTC, ETH],
    ]

    for pairs in pairs_list:
        await start(pairs)
        delay(10)

    for pairs in pairs_list:
        await start(pairs)
        delay(10)
    for pairs in pairs_list:
        await start(pairs)
        delay(10)
    for pairs in pairs_list:
        await start(pairs)
        delay(10)
    for pairs in pairs_list:
        await start(pairs)
        delay(10)
    for pairs in pairs_list:
        await start(pairs)
        delay(10)
    for pairs in pairs_list:
        await start(pairs)
        delay(10)
    for pairs in pairs_list:
        await start(pairs)
        delay(10)
    for pairs in pairs_list:
        await start(pairs)
        delay(10)
    for pairs in pairs_list:
        await start(pairs)
        delay(10)

async def start(pairs):
    first_input_amount = 250_000_000
    output_mint = pairs[0]
    input_mint = pairs[1]
    amount = first_input_amount

    routes = []
    input_mints = []
    output_mints = []
    input_amounts = []
    output_amounts = []

    for i in range(len(pairs)):
        input_mint = pairs[i]
        output_mint = pairs[(i + 1) % len(pairs)]
        input_amounts.append(amount)
        input_mints.append(input_mint)
        output_mints.append(output_mint)

        print("roop: ", i)
        print("inputToken: ", input_mint)
        print("outputToken: ", output_mint)
        print("amount: ", amount)

        response = requests.get(
            f"https://quote-api.jup.ag/v6/quote?inputMint={input_mint}&outputMint={output_mint}&amount={amount}&slippageBps=25",
            headers={'User-Agent': ''}
        )
        route_json = response.json()
        routes.append(route_json)
        
        print("inputAmount: ", route_json['inAmount'])
        print("outputAmount: ", route_json['outAmount'])
        amount = route_json['outAmount']
        output_amounts.append(amount)

    print("inputAmount->outputAmount: ", f"{first_input_amount}->{amount}")
    print("inputAmount/outputAmount: ", int(amount) / first_input_amount)

    st.write(f"{first_input_amount}->{amount}")

    if int(amount) / first_input_amount < 1.0001:
        print("there is no order")
        return
        
    rechecked = [await recheck(input_mints[i], output_mints[i], input_amounts[i], output_amounts[i]) for i in range(len(routes))]
    for ret in rechecked:
        if not ret:
            print("rechecked there is no order", ret)
            return

    for route in routes:
        await order(route)

asyncio.run(start_roop())

