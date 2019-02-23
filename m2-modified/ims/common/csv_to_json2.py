import csv, json,sys, io


def csv2json(fileName):
    
    file = open(fileName, "r")
    reader = csv.reader(file, delimiter="\n")
    list_d = []
    i = 0
    jsonData = None
    counter = 0
    for row in reader:
        j = 1
        counter+=1
        dic = {}
        row[i] = row[i].replace('"', '')
        dic[j] = row[i][:row[i].index(":")]
        j += 1
        dic[j] = row[i][row[i].index(":"):row[0].index(",")]
        j += 1
        rowdata = row[i][row[i].index(",")+1:]
        nreader = rowdata.split(",")
        for r in nreader:
            if ":" in r:
                n = r[r.index(":")+1:]
            else:
                n = None
            dic[j] = n
            j += 1
        list_d.append(dic)
	jsonData = json.dumps(list_d)
    return jsonData


