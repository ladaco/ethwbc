#!/usr/bin/env python3

import binascii, hashlib, hmac, struct
import mnemonic
import requests
import simplejson
from rich import print
from rich.panel import Panel
from rich.console import Console
from multiprocessing import Process
from requests_html import HTMLSession
from ecdsa.curves import SECP256k1
from eth_utils import to_checksum_address, keccak as eth_utils_keccak

filename = 'EthRich.txt'
with open(filename) as f0 :
    add = f0.read().split()
add = set(add)

console = Console()

BIP39_PBKDF2_ROUNDS = 2048
BIP39_SALT_MODIFIER = "mnemonic"
BIP32_PRIVDEV = 0x80000000
BIP32_CURVE = SECP256k1
BIP32_SEED_MODIFIER = b'Bitcoin seed'
ETH_DERIVATION_PATH = "m/44'/60'/0'/0"

class PublicKey:
    def __init__(self, private_key):
        self.point = int.from_bytes(private_key, byteorder='big') * BIP32_CURVE.generator

    def __bytes__(self):
        xstr = self.point.x().to_bytes(32, byteorder='big')
        parity = self.point.y() & 1
        return (2 + parity).to_bytes(1, byteorder='big') + xstr

    def address(self):
        x = self.point.x()
        y = self.point.y()
        s = x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
        return to_checksum_address(eth_utils_keccak(s)[12:])

def mnemonic_to_bip39seed(mnemonic, passphrase):
    mnemonic = bytes(mnemonic, 'utf8')
    salt = bytes(BIP39_SALT_MODIFIER + passphrase, 'utf8')
    return hashlib.pbkdf2_hmac('sha512', mnemonic, salt, BIP39_PBKDF2_ROUNDS)

def bip39seed_to_bip32masternode(seed):
    k = seed
    h = hmac.new(BIP32_SEED_MODIFIER, seed, hashlib.sha512).digest()
    key, chain_code = h[:32], h[32:]
    return key, chain_code

def derive_bip32childkey(parent_key, parent_chain_code, i):
    assert len(parent_key) == 32
    assert len(parent_chain_code) == 32
    k = parent_chain_code
    if (i & BIP32_PRIVDEV) != 0:
        key = b'\x00' + parent_key
    else:
        key = bytes(PublicKey(parent_key))
    d = key + struct.pack('>L', i)
    while True:
        h = hmac.new(k, d, hashlib.sha512).digest()
        key, chain_code = h[:32], h[32:]
        a = int.from_bytes(key, byteorder='big')
        b = int.from_bytes(parent_key, byteorder='big')
        key = (a + b) % BIP32_CURVE.order
        if a < BIP32_CURVE.order and key != 0:
            key = key.to_bytes(32, byteorder='big')
            break
        d = b'\x01' + h[32:] + struct.pack('>L', i)
    return key, chain_code

def parse_derivation_path(str_derivation_path):
    path = []
    if str_derivation_path[0:2] != 'm/':
        raise ValueError("Can't recognize derivation path. It should look like \"m/44'/60/0'/0\".")
    for i in str_derivation_path.lstrip('m/').split('/'):
        if "'" in i:
            path.append(BIP32_PRIVDEV + int(i[:-1]))
        else:
            path.append(int(i))
    return path

def mnemonic_to_private_key(mnemonic, str_derivation_path, passphrase=""):
    derivation_path = parse_derivation_path(str_derivation_path)
    bip39seed = mnemonic_to_bip39seed(mnemonic, passphrase)
    master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)
    private_key, chain_code = master_private_key, master_chain_code
    for i in derivation_path:
        private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)
    return private_key

def balance(addr):
    url_n = f"https://eth1.trezor.io/address/{addr}"
    se = HTMLSession()
    nmp = se.get(url_n)
    Master = nmp.html.xpath('/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]')
    return Master[0].text


def transaction(addr):
    url_n = f"https://eth1.trezor.io/address/{addr}"
    se = HTMLSession()
    nmp = se.get(url_n)
    Master = nmp.html.xpath('/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]')
    return Master[0].text



def mmdr():
#if __name__ == '__main__':
    z = 0
    w = 0
    m = 0
    #f = open('result_eth.txt', 'a')
    mobj = mnemonic.Mnemonic("english")
    while True:
        mnemonic_words = mobj.generate(strength=128)
        private_key = mnemonic_to_private_key(mnemonic_words, str_derivation_path=f'{ETH_DERIVATION_PATH}/0')
        public_key = PublicKey(private_key)
        addr = public_key.address()
        addr = str.lower(addr)
        priv = binascii.hexlify(private_key).decode("utf-8")
        words = mnemonic_words
        #https://api.bscscan.com/api?module=account&action=balance&address=0x0000b07FCf8ED4F6D7E1411e2d47d8742B9Aba85&apikey=6FBCS9ED62AAAB1J6KYBB8TWSB4CFSXAK8
        #https://api.etherscan.io/api?module=account&action=balance&address=0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae&tag=latest&apikey=AS1S5B6DHNJAT7T4ABIN59CYCW3RGEWJRT
        balance_url = "https://api.bscscan.com/api?module=account&action=balance&address=" + str(addr) + "&apikey=6FBCS9ED62AAAB1J6KYBB8TWSB4CFSXAK8"
        
        r = requests.get(balance_url, headers={"x-api-key":"6FBCS9ED62AAAB1J6KYBB8TWSB4CFSXAK8"})

        try:
            r = r.json()
            #print(r)
            #btc = float(r["result"])
            #print("" + str(btc) + "")
                    
            if "result" in r:
                btc = float(r["result"])
                #if btc == 0.0:
                 #text1 = "Addr: " + str(addr) + " Bal: " + str(btc) + " ETH."
                 #print("seed phrase: {:<90} {:<15}".format(mnemonic_words, text1))
                
                if btc > 0:
                    w += 1
                    f = open('result_eth.txt', 'a')
                    f.write("seed phrase: " + mnemonic_words + "\t" + "Bal: " + str(btc) + " ETH.\n")
                    f.close()
                text1 = "Addr: " + str(addr) + " Bal: " + str(btc) + " ETH."
                print("seed phrase: {:<90} {:<15}".format(mnemonic_words, text1))
            else:
                print("Fatal error")
        except simplejson.errors.JSONDecodeError:
            print("API error")
            
        MmPanel = str(
            '[gold1 on grey15]Total Checked: ' + '[orange_red1]' + str(
                z) + '[/][gold1 on grey15] ' + ' Win:' + '[white]' + str(
                w) + '[/]' + '[grey74]  ReqSpeed: ' + '[/][gold1]             Balance: ' + '[/][aquamarine1]' + str(
                btc) + '[/][gold1]             Transaction : ' + '[/][aquamarine1]' + str(
                m) + '\n[/][gold1 on grey15]Addr0: ' + '[white] ' + str(
                addr) + '[/]\nPRIVATEKEY: [grey54]' + str(priv) + '[/]\nMNEMONIC: [grey54]'+str(words)+'[/]')
        style = "gold1 on grey11"
        console.print(Panel(str(MmPanel), title="[white]Ethereum Mnemonic Checker V3[/]",
                            subtitle="[green_yellow blink] Ladaco.info [/]", style="green"), style=style, justify="full")

        m += 1
        z += 1
        iffer = 0.0
        if btc > iffer:
            w += 1
            f1 = open('Winner___ETH___WalletWinner.txt', 'a')
            f1.write(f'\nAddress     === {addr}')
            f1.write(f'\nPrivateKey  === {priv}')
            f1.write(f'\nMnemonic    === {words}')
            f1.write(f'\nBalance === {btc}')
            #f1.write(f'\nTransaction === {transaction(addr)}')
            f1.write(f'\n            -------------                   \n')
            f1.close()
            
        if addr in add :
            w += 1
            f1 = open('Winner___ETH___WalletWinner.txt' , 'a')
            f1.write('\nAddress     === '+str(addr))
            f1.write('\nPrivateKey  === '+str(priv))
            f1.write('\nMnemonic    === '+str(words))
            f1.write('\n            ---          \n')
            f1.close()
            
        private_key1 = mnemonic_to_private_key(mnemonic_words, str_derivation_path=f'{ETH_DERIVATION_PATH}/1')
        public_key1 = PublicKey(private_key1)
        addr1 = public_key1.address()
        addr1 = str.lower(addr1)
        #addr1 = '0x0000b07FCf8ED4F6D7E1411e2d47d8742B9Aba85'
        priv1 = binascii.hexlify(private_key1).decode("utf-8")
        words = mnemonic_words
        #https://api.bscscan.com/api?module=account&action=balance&address=0x0000b07FCf8ED4F6D7E1411e2d47d8742B9Aba85&apikey=6FBCS9ED62AAAB1J6KYBB8TWSB4CFSXAK8
        #https://api.etherscan.io/api?module=account&action=balance&address=0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae&tag=latest&apikey=AS1S5B6DHNJAT7T4ABIN59CYCW3RGEWJRT
        balance_url = "https://api.bscscan.com/api?module=account&action=balance&address=" + str(addr1) + "&apikey=6FBCS9ED62AAAB1J6KYBB8TWSB4CFSXAK8"
        
        r = requests.get(balance_url, headers={"x-api-key":"6FBCS9ED62AAAB1J6KYBB8TWSB4CFSXAK8"})

        try:
            r = r.json()
            #print(r)
            #btc = float(r["result"])
            #print("" + str(btc) + "")
                    
            if "result" in r:
                btc = float(r["result"])
                #if btc == 0.0:
                 #text1 = "Addr: " + str(addr) + " Bal: " + str(btc) + " ETH."
                 #print("seed phrase: {:<90} {:<15}".format(mnemonic_words, text1))
                
                if btc > 0:
                    w += 1
                    f = open('result_eth.txt', 'a')
                    f.write("seed phrase: " + mnemonic_words + "\t" + "Bal: " + str(btc) + " ETH.\n")
                    f.close()
                text1 = "Addr1: " + str(addr1) + " Bal: " + str(btc) + " ETH."
                print("seed phrase: {:<90} {:<15}".format(mnemonic_words, text1))
            else:
                print("Fatal error")
        except simplejson.errors.JSONDecodeError:
            print("API error")
            
        MmPanel = str(
            '[gold1 on grey15]Total Checked: ' + '[orange_red1]' + str(
                z) + '[/][gold1 on grey15] ' + ' Win:' + '[white]' + str(
                w) + '[/]' + '[grey74]  ReqSpeed: ' + '[/][gold1]             Balance: ' + '[/][aquamarine1]' + str(
                btc) + '[/][gold1]             Transaction : ' + '[/][aquamarine1]' + str(
                m) + '\n[/][gold1 on grey15]Addr1: ' + '[white] ' + str(
                addr1) + '[/]\nPRIVATEKEY: [grey54]' + str(priv1) + '[/]\nMNEMONIC: [grey54]'+str(words)+'[/]')
        style = "gold1 on grey11"
        console.print(Panel(str(MmPanel), title="[white]Ethereum Mnemonic Checker V4[/]",
                            subtitle="[green_yellow blink] Ladaco.info [/]", style="green"), style=style, justify="full")
        z += 1
        iffer = 0.0
        if btc > iffer:
            w += 1
            f1 = open('Winner___ETH___WalletWinner.txt', 'a')
            f1.write(f'\nAddress     === {addr1}')
            f1.write(f'\nPrivateKey  === {priv1}')
            f1.write(f'\nMnemonic    === {words}')
            f1.write(f'\nBalance === {btc}')
            #f1.write(f'\nTransaction === {transaction(addr)}')
            f1.write(f'\n            -------------                   \n')
            f1.close()
            
          #addr1 = str.lower(addr1)          
        if addr1 in add :
            w += 1
            f1 = open('Winner___ETH___WalletWinner.txt' , 'a')
            f1.write('\nAddress     === '+str(addr1))
            f1.write('\nPrivateKey  === '+str(priv1))
            f1.write('\nMnemonic    === '+str(words))
            f1.write('\n            ---          \n')
            f1.close()
            
            
mmdr()

if __name__ == '__main__':
    for i in range(len(add)):
        p = multiprocessing.Process(target=mmdrza)
        p.start()
        p.join()
    
