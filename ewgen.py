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

        hex_priv_key = str(magic)
        keccak = sha3.keccak_256()
        priv = SigningKey.from_string(string=bytes.fromhex(hex_priv_key), curve=SECP256k1)
        pub = priv.get_verifying_key().to_string()
        keccak.update(pub)
        kec = keccak.hexdigest()[24:]
        ethadd = '0x'+ kec
        privatekey = priv.to_string().hex()
        
        f=open("ethKey.txx","a")
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


