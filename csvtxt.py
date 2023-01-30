import csv

with open('btc_balance_sorted.csv') as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=',')
    line_count = 0
    for row in csv_reader:
        if line_count == 0:
            print(f'Column names are {", ".join(row)}')
            line_count += 1
        else:
            print(f'\t{row[0]} {row[1]}  {row[2]} {row[3]}')
            line_count += 1
            f_out = open('btc_balance_sorted.txt', 'a')
            content = (f'\n{row[0]}')
            f_out.write(content)
            f_out.close()
    print(f'Processed {line_count} lines.')
    


#with open('btc_balance_sorted.csv', 'r') as f_in, open('btc_balance_sorted.txt', 'w') as f_out:
    #content = f_in.read().replace(',', ' ')
    #f_out.write(content)
    #f_out.close()
