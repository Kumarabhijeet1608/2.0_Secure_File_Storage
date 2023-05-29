import os
from file import openFile
import math

def split(path): 
    # path = openFile()
    f = open(path, "r")
    content = f.read()
    f.close()
    
    size = 0
    for char in content: 
        size += 1

    # print(f"Total size of the file -> {size}")
    limit = (size / 4)
    # print(f"Limit of each file -> {limit}")
    buffer = math.ceil(limit)
    # print(f"Buffer of each file -> {buffer}")
    
    k = 0

    for i in range(0, 4): 
        name = str(i) + ".txt"
        path = os.path.join(os.getcwd() + "/SplitFiles", name)
        f = open(path , "w")
        ctr = 0 
        
        for j in range(k , size):
            k+=1
            f.write(content[j])
            ctr+=1
            if(ctr == buffer and i != 4): 
                f.close()
                break
        f.close()


def merge(): 
    mainFile = open("Output.txt", "w")
    for i in range(0, 4):
        name = os.path.join(os.getcwd() + "/SplitFiles", str(i) + ".txt")
        f = open(name, "r")
        cont = f.read()
        print("From Encrypted File -> " + str(i))
        mainFile.write(cont)
        f.close()
        os.remove(name)
    mainFile.close()



if __name__=="__main__": 
    split()
    merge()
    
    
    
    