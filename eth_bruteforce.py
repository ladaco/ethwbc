import colorama
from colorama import Fore, Back, Style
colorama.init()
import web3
from web3.auto import w3

print("Loading...")
with open("eth_balance_all.txt","r") as m:
    add = m.read().split()
add= set(add)
i = 0
def guess():
  acct = w3.eth.account.create('KEYSMASH FJAFJKLDSKF7JKFDJ 1530')
  addr = acct.address

  print("     ",i, addr, acct.privateKey.hex())
  if addr in add:
     print(Fore.BLUE +"FOUND!!!", addr, " ", acct.privateKey.hex())
     s1 = addr
     s2 = acct.privateKey.hex()
     f=open("FOUND.txt","a")
     f.write(s1)
     f.write(":"+s2)      
     f.close()
while 1:
    guess()
    i += 1