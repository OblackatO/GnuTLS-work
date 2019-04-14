"""
Script used to plot density plots for some random variable. 
Several random variables might be mixed in the same plot.

The example shown here is a plot of the ticks of the CPU for the decryption
(RSA 1024) of low and high hamming data.
"""
import pandas as pd
import matplotlib.pyplot as plt

file1 = open("Decrypt_HHWData_SomeRSA_Key.txt", "r").readlines()
file1 = list(map(int, file1))

file2 = open("Decrypt_LHWData_SomeRSA_Key.txt", "r").readlines()
file2 = list(map(int, file2))

x = pd.DataFrame({'HHW Data Decryption': file1, 
                  'LHW Data Decryption': file2}).plot.kde(bw_method=0.3, ind=[150, 200, 250, 300, 350, 400, 450, 500, 550, 600, 650, 700, 750],
                                                         title="Low and High HW Data, Decryption.") # or pd.Series()
plt.xlabel("Time (ms)")
plt.show(x)
