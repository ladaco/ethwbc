import sys
from ecdsa import SigningKey, SECP256k1
import sha3 #from pysha3
import random
import time

filename = 'EthRich.txt'
with open(filename) as fw :
    add = fw.read().split()
add = set(add)

start=time.time()

def seek():
    i=1
    w = 0
    while (i<=5000000):
        tm=time.time()-start
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

        hex_priv_key = str(magic)
        keccak = sha3.keccak_256()
        priv = SigningKey.from_string(string=bytes.fromhex(hex_priv_key), curve=SECP256k1)
        pub = priv.get_verifying_key().to_string()
        keccak.update(pub)
        kec = keccak.hexdigest()[24:]
        ethadd = '0x'+ kec
        privatekey = priv.to_string().hex()
        
        f=open("BitKey.txt","a")
        f.write(''+privatekey+'\n')
        f.close()
        #if i==1000 :
            #ethadd ='0x07ee55aa48bb72dcc6e9d78256648910de513eca'
        #print('\n\n--------------------------------')
        print('Win: '+str(w)+'/'+str(i)+' Addr:  ',ethadd,'  Priv Key:  ',priv.to_string().hex(),'\n')
        addr = str.lower(ethadd)          
        if addr in add :
            w += 1
            print('Winner: '+str(w)+'/'+str(i)+' Addr: ',ethadd,'  Priv Key:  ',priv.to_string().hex(),'\n')
            f1 = open('Winner__ETH__WalletWinner.txt' , 'a')
            f1.write('\nAddress     === '+str(addr))
            f1.write('\nPrivateKey  === '+str(privatekey))
            #f1.write('\nMnemonic    === '+str(words))
            f1.write('\n            ---          \n')
            f1.close()  
        
        
        #f=open("ethKey.tx","a")
        #f.write(str(i)+' - '+privatekey+'\n')
        #f.close()
        #f=open("ethAdd.txt","a")
        #f.write(str(i)+' - '+ethadd+'\n')
        #f.close()
        
        
        i = i+1
        time.sleep(0)
        print("Total Time For Genereted = %s"%tm)



seek()
