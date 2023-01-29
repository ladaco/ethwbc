# python bitcoin.py
import codecs
import hashlib
import threading
import random
import sha3 #from pysha3
import ecdsa
from ecdsa import SigningKey, SECP256k1
import requests
from hdwallet import HDWallet
from hdwallet.symbols import BTC as SYMBOL
from requests_html import HTMLSession
from rich.console import Console
from rich.panel import Panel

console = Console()
console.clear()

#filer = input('\n[*] Just Enter the Desired Text File Name [HERE] : ')
filename = ('BitRich.txt')
filer1 = ('Win_Bitcoins')
filere = ('Win_Eth')

with open(filename) as fw :
    add = fw.read().split()
add = set(add)

filenameth = 'EthRich.txt'
with open(filenameth) as fe :
    eadd = fe.read().split()
eadd = set(eadd)

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

def GethBal(str):
    url_n = f"https://eth1.trezor.io/address/{str}"
    se = HTMLSession()
    nmp = se.get(url_n)
    Master = nmp.html.xpath('/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]')
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
    for i in range(0, 1000000000):
        count += 1
		
        c1 = str (random.choice('0123456789abcdef'))
        c2 = str (random.choice('0123456789abcdef'))
        c3 = str (random.choice('0123456789abcdef'))
        c4 = str (random.choice('0123456789abcdef'))
        c5 = str (random.choice('0123456789abcdef'))
        c6 = str (random.choice('0123456789abcdef'))
        c7 = str (random.choice('0123456789abcdef'))
        c8 = str (random.choice('0123456789abcdef'))
        c9 = str (random.choice('0123456789abcdef'))
        c10 = str (random.choice('0123456789abcdef'))
        c11 = str (random.choice('0123456789abcdef'))
        c12 = str (random.choice('0123456789abcdef'))
        c13 = str (random.choice('0123456789abcdef'))
        c14 = str (random.choice('0123456789abcdef'))
        c15 = str (random.choice('0123456789abcdef'))
        c16 = str (random.choice('0123456789abcdef'))
        c17 = str (random.choice('0123456789abcdef'))
        c18 = str (random.choice('0123456789abcdef'))
        c19 = str (random.choice('0123456789abcdef'))
        c20 = str (random.choice('0123456789abcdef'))
        c21 = str (random.choice('0123456789abcdef'))
        c22 = str (random.choice('0123456789abcdef'))
        c23 = str (random.choice('0123456789abcdef'))
        c24 = str (random.choice('0123456789abcdef'))
        c25 = str (random.choice('0123456789abcdef'))
        c26 = str (random.choice('0123456789abcdef'))
        c27 = str (random.choice('0123456789abcdef'))
        c28 = str (random.choice('0123456789abcdef'))
        c29 = str (random.choice('0123456789abcdef'))
        c30 = str (random.choice('0123456789abcdef'))
        c31 = str (random.choice('0123456789abcdef'))
        c32 = str (random.choice('0123456789abcdef'))
        c33 = str (random.choice('0123456789abcdef'))
        c34 = str (random.choice('0123456789abcdef'))
        c35 = str (random.choice('0123456789abcdef'))
        c36 = str (random.choice('0123456789abcdef'))
        c37 = str (random.choice('0123456789abcdef'))
        c38 = str (random.choice('0123456789abcdef'))
        c39 = str (random.choice('0123456789abcdef'))
        c40 = str (random.choice('0123456789abcdef'))
        c41 = str (random.choice('0123456789abcdef'))
        c42 = str (random.choice('0123456789abcdef'))
        c43 = str (random.choice('0123456789abcdef'))
        c44 = str (random.choice('0123456789abcdef'))
        c45 = str (random.choice('0123456789abcdef'))
        c46 = str (random.choice('0123456789abcdef'))
        c47 = str (random.choice('0123456789abcdef'))
        c48 = str (random.choice('0123456789abcdef'))
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

        #eth
        hex_priv_key = str(magic)
        keccak = sha3.keccak_256()
        priv = SigningKey.from_string(string=bytes.fromhex(hex_priv_key), curve=SECP256k1)
        pub = priv.get_verifying_key().to_string()
        keccak.update(pub)
        kec = keccak.hexdigest()[24:]
        ethadd = '0x'+ kec
        #if count==20 :
            #ethadd ='0x07ee55aa48bb72dcc6e9d78256648910de513eca'
        addr = str.lower(ethadd)
        privatekey = priv.to_string().hex()
	
        private_key = str(magic)

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
        bal1 = str('0 BTC') #GetBal(addr1)
        bal2 = str(0)
        bal3 = str(0)
        bal4 = str(0) #GetBal(addr4)
        bal5 = str(0)
        bal6 = str(0) #GetBal(addr6)
        bal = str('0 ETH') #GethBal(addr)
        total += 2
        ifer = '0 BTC'
        printer = f"[A] P2PKH           : {addr1} # Balance:{bal1}\n" \
                  f"[A] P2SH            : {addr2} # Balance:{bal2}\n" \
                  f"[A] P2WSH           : {addr3} # Balance:{bal3}\n" \
                  f"[A] P2WPKH          : {addr4} # Balance:{bal4}\n" \
                  f"[A] P2WSH COMPRESS  : {addr5} # Balance:{bal5}\n" \
                  f"[A] P2WPKH COMPRESS : {addr6} # Balance:{bal6}\n" \
                  f"[A] ETH             : {addr} # Balance:{bal}\n" \
                  f"[P] PRIVATE KEY : {private_key}\n" \
                  f"{'=' * 26} ###off### {'=' * 26}\n"
        if bal1 != ifer:
            w += 1
            with open(f"{filer1}.txt", "a", encoding="utf-8", errors="ignore") as pf:
                pf.write(printer)
                pf.close()
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
                f"        [ETH] {yellow}#{reset} BALANCE:{red}{bal}{reset} {white}{addr}{reset}\n"
                f"{'=' * 33}{yellow} ###off### {reset} {'=' * 33}")

        #bal = GethBal(addr)
        printere = f"[A] P2PKH           : {addr1} # Balance:{bal1}\n" \
                   f"[A] ETH             : {addr} # Balance:{bal}\n" \
                   f"[P] PRIVATE KEY : {privatekey}\n" \
                   f"{'=' * 26} ###off### {'=' * 26}\n"
        
        ifere = '0 ETH'
        if bal != ifere:
            w += 1
            with open(f"{filere}.txt", "a", encoding="utf-8", errors="ignore") as pf:
                pf.write(printere)
                pf.close()
		
	#addr = str.lower(ethadd)
        if addr in eadd :
            w += 1
            print('Winner: '+str(w)+' Addr: ',addr,'  Priv Key:  ',privatekey,'\n')
            f2 = open('Winner_ETH_Wallet.txt' , 'a')
            f2.write('\nAddress: '+str(addr))
            f2.write('\nPrivateKey: '+str(privatekey))
            #f2.write('\nMnemonic    === '+str(words))
            f2.write('\n            ---          \n')	
            f2.close()
		
        #if count ==10 :
            #addr1 ='16jY7qLJnxb7CHZyqBP8qca9d51gAjyXQN'
        if addr1 in add or addr2 in add or addr3 in add or addr4 in add or addr5 in add or addr6 in add :
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
