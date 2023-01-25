# python bitcoin.py
import codecs
import hashlib
import threading
import random
import ecdsa
import requests
from hdwallet import HDWallet
from hdwallet.symbols import BTC as SYMBOL
from requests_html import HTMLSession
from rich.console import Console
from rich.panel import Panel

console = Console()
console.clear()

#filer = input('\n[*] Just Enter the Desired Text File Name [HERE] : ')
filename = ('Bitcoins.txt')
filer1 = ('Win_Bitcoins')

with open(filename) as fw :
    add = fw.read().split()
add = set(add)

#mylist = []

#filename = str(filer + ".txt")
#with open(filename, newline='', encoding='utf-8') as f:
#    for line in f:
#        mylist.append(line.strip())


class Color():
    Red = '\33[31m'
    Green = '\33[32m'
    Yellow = '\33[33m'
    Cyan = '\33[36m'
    White = '\33[37m'
    Reset = '\033[0m'


# Example easy:

red = Color.Red
green = Color.Green
yellow = Color.Yellow
cyan = Color.Cyan
white = Color.White
reset = Color.Reset


def GetBal(str):
    url_n = f"https://btc2.trezor.io/address/{str}"
    se = HTMLSession()
    nmp = se.get(url_n)
    Master = nmp.html.xpath('/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]')
    return Master[0].text


class BrainWallet:

    @staticmethod
    def generate_address_from_passphrase(passphrase):
        private_key = str(hashlib.sha256(
            passphrase.encode('utf-8')).hexdigest())
        address = BrainWallet.generate_address_from_private_key(private_key)
        return private_key, address

    @staticmethod
    def generate_address_from_private_key(private_key):
        public_key = BrainWallet.__private_to_public(private_key)
        address = BrainWallet.__public_to_address(public_key)
        return address

    @staticmethod
    def __private_to_public(private_key):
        private_key_bytes = codecs.decode(private_key, 'hex')
        key = ecdsa.SigningKey.from_string(
            private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
        key_bytes = key.to_string()
        key_hex = codecs.encode(key_bytes, 'hex')
        bitcoin_byte = b'04'
        public_key = bitcoin_byte + key_hex
        return public_key

    @staticmethod
    def __public_to_address(public_key):
        public_key_bytes = codecs.decode(public_key, 'hex')
        # Run SHA256 for the public key
        sha256_bpk = hashlib.sha256(public_key_bytes)
        sha256_bpk_digest = sha256_bpk.digest()
        ripemd160_bpk = hashlib.new('ripemd160')
        ripemd160_bpk.update(sha256_bpk_digest)
        ripemd160_bpk_digest = ripemd160_bpk.digest()
        ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
        network_byte = b'00'
        network_bitcoin_public_key = network_byte + ripemd160_bpk_hex
        network_bitcoin_public_key_bytes = codecs.decode(
            network_bitcoin_public_key, 'hex')
        sha256_nbpk = hashlib.sha256(network_bitcoin_public_key_bytes)
        sha256_nbpk_digest = sha256_nbpk.digest()
        sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
        sha256_2_nbpk_digest = sha256_2_nbpk.digest()
        sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
        checksum = sha256_2_hex[:8]
        address_hex = (network_bitcoin_public_key + checksum).decode('utf-8')
        wallet = BrainWallet.base58(address_hex)
        return wallet

    @staticmethod
    def base58(address_hex):
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        b58_string = ''
        leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
        address_int = int(address_hex, 16)
        while address_int > 0:
            digit = address_int % 58
            digit_char = alphabet[digit]
            b58_string = digit_char + b58_string
            address_int //= 58
        ones = leading_zeros // 2
        for one in range(ones):
            b58_string = '1' + b58_string
        return b58_string


def MmDrza():
    w = 0
    count = 0
    total = 0
    for i in range(0, 10000):
        count += 1
		
        c1 = str ('0')
        c2 = str ('0')
        c3 = str ('0')
        c4 = str ('0')
        c5 = str ('0')
        c6 = str ('0')
        c7 = str ('0')
        c8 = str ('0')
        c9 = str ('0')
        c10 = str ('0')
        c11 = str ('0')
        c12 = str ('0')
        c13 = str ('0')
        c14 = str ('0')
        c15 = str ('0')
        c16 = str ('0')
        c17 = str ('0')
        c18 = str ('0')
        c19 = str ('0')
        c20 = str ('0')
        c21 = str ('0')
        c22 = str ('0')
        c23 = str ('0')
        c24 = str ('0')
        c25 = str ('0')
        c26 = str ('0')
        c27 = str ('0')
        c28 = str ('0')
        c29 = str ('0')
        c30 = str ('0')
        c31 = str ('0')
        c32 = str ('0')
        c33 = str ('0')
        c34 = str ('0')
        c35 = str ('0')
        c36 = str ('0')
        c37 = str ('0')
        c38 = str ('0')
        c39 = str ('0')
        c40 = str ('0')
        c41 = str ('0')
        c42 = str ('0')
        c43 = str ('0')
        c44 = str ('0')
        c45 = str ('0')
        c46 = str ('0')
        c47 = str ('0')
        c48 = str (random.choice('23'))
        c49 = str (random.choice('0123456789abcdef'))
        c50 = str (random.choice('0123456789abcdef'))
        c51 = str (random.choice('0123456789abcdef'))
        c52 = str (random.choice('0123456789abcdef'))
        c53 = str (random.choice('0123456789abcdef'))
        c54 = str (random.choice('0123456789abcdef'))
        c55 = str (random.choice('0123456789abcdef'))
        c56 = str (random.choice('0123456789abcdef'))
        c57 = str (random.choice('0123456789abcdef'))
        c58 = str (random.choice('0123456789abcdef'))
        c59 = str (random.choice('0123456789abcdef'))
        c60 = str (random.choice('0123456789abcdef'))
        c61 = str (random.choice('0123456789abcdef'))
        c62 = str (random.choice('0123456789abcdef'))
        c63 = str (random.choice('0123456789abcdef'))
        c64 = str (random.choice('0123456789abcdef'))

        magic = (c1+c2+c3+c4+c5+c6+c7+c8+c9+c10+c11+c12+c13+c14+c15+c16+c17+c18+c19+c20+c21+c22+c23+c24+c25+c26+c27+c28+c29+c30+c31+c32+c33+c34+c35+c36+c37+c38+c39+c40+c41+c42+c43+c44+c45+c46+c47+c48+c49+c50+c51+c52+c53+c54+c55+c56+c57+c58+c59+c60+c61+c62+c63+c64)

        private_key = str(magic)
        #if count ==10 :
            #private_key ='000000000000000000000000000000000000000000000001a838B13505b26867'


        #passphrase = mylist[i]
        wallet = BrainWallet()
        #private_key, address = wallet.generate_address_from_passphrase(passphrase)
        address = wallet.generate_address_from_private_key(private_key)
        hdwallet: HDWallet = HDWallet(symbol=SYMBOL)
        hdwallet.from_private_key(private_key=private_key)
        # All Address Type Bitcoin Wallet -------------------
        addr1 = hdwallet.p2pkh_address()
        addr2 = hdwallet.p2sh_address()
        addr3 = hdwallet.p2wsh_address()
        addr4 = hdwallet.p2wpkh_address()
        addr5 = hdwallet.p2wsh_in_p2sh_address()
        addr6 = hdwallet.p2wpkh_in_p2sh_address()
        # All Value Check Balance ---------------------------
        bal1 = str(0) #bal1 = GetBal(addr1)
        bal2 = str(0)
        bal3 = str(0)
        bal4 = str(0)
        bal5 = str(0)
        bal6 = str(0)
        total += 6
        ifer = '0 BTC'
        printer = f"[A] P2PKH           : {addr1} # Balance:{bal1}\n" \
                  f"[A] P2SH            : {addr2} # Balance:{bal2}\n" \
                  f"[A] P2WSH           : {addr3} # Balance:{bal3}\n" \
                  f"[A] P2WPKH          : {addr4} # Balance:{bal4}\n" \
                  f"[A] P2WSH COMPRESS  : {addr5} # Balance:{bal5}\n" \
                  f"[A] P2WPKH COMPRESS : {addr6} # Balance:{bal6}\n" \
                  f"[P] PRIVATE KEY : {private_key}\n" \
                  f"{'=' * 26} MMDRZA.COM {'=' * 26}\n"
        #if bal1 != ifer:
        if addr1 in add or addr3 in add or addr4 in add or addr6 in add :
            w += 1
            with open(f"{filer1}.txt", "a", encoding="utf-8", errors="ignore") as pf:
                pf.write(printer).close()

        else:
            print(
                #f"{red}SCAN:{count}{reset} - {red}CHECK/REQ:{reset}{yellow}{total}{reset} - {green}Found:{w}{reset} # {cyan}Passphrase:{reset}{white}{passphrase}{reset}\n"
                f"{red}SCAN:{count}{reset} - {red}CHECK/REQ:{reset}{yellow}{total}{reset} - {green}Found:{w}{reset} # {cyan}Priv:{reset}{white}{private_key}{reset}\n"
                f"      [P2PKH] {yellow}#{reset} BALANCE:{red}{bal1}{reset} {white}{addr1}{reset}\n"
                f"       [P2SH] {yellow}#{reset} BALANCE:{red}{bal2}{reset} {white}{addr2}{reset}\n"
                f"      [P2WSH] {yellow}#{reset} BALANCE:{red}{bal3}{reset} {white}{addr3}{reset}\n"
                f"     [P2WPKH] {yellow}#{reset} BALANCE:{red}{bal4}{reset} {white}{addr4}{reset}\n"
                f" [P2WSH-COMP] {yellow}#{reset} BALANCE:{red}{bal5}{reset} {white}{addr5}{reset}\n"
                f"[P2WPKH-COMP] {yellow}#{reset} BALANCE:{red}{bal6}{reset} {white}{addr6}{reset}\n"
                f"{'=' * 33}{yellow} MMDRZA.COM{reset} {'=' * 33}")

        #addr = str.lower(ethadd)
        #if count ==10 :
            #addr1 ='16jY7qLJnxb7CHZyqBP8qca9d51gAjyXQN'
        if addr1 in add :
            w += 1
            print('Winner: '+str(w)+' Addr: ',addr1,'  Priv Key:  ',private_key,'\n')
            f1 = open('Winner_BTC_Wallet.txt' , 'a')
            f1.write('\nAddress: '+str(addr1))
            f1.write('\nPrivateKey: '+str(private_key))
            #f1.write('\nMnemonic    === '+str(words))
            f1.write('\n            ---          \n')
            f1.close() 
	
MmDrza()

if __name__ == "__main__":
    Master = threading.Thread(target=MmDrza)
    Master.start()
    Master.join()
