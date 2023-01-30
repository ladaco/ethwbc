

with open('btc_balance_sorted.csv', 'r') as f_in, open('btc_balance_sorted.txt', 'w') as f_out:
    content = f_in.read().replace(',^[*]', ' ')
    f_out.write(content)
    f_out.close()
