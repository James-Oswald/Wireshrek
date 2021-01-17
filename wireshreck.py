

import json
import time
import threading
import tkinter as tk
import tkinter.ttk as ttk
from scapy.all import sniff
from scapy.compat import raw
from datetime import datetime
from scapy.utils import hexdump
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP

maxPackets = 10 
exitPgrm = False                #application state
reFilter = False                #enter state to apply new filter?
pktFilter = ""                  #current filter
pkts = [None] * maxPackets      #last 10 packets
pktIndex = 0                    #position of the last packet

rulesFile = open("rules.json")
rules = json.load(rulesFile)["rules"]

        
def onFilter():
    global reFilter, pktFilter
    reFilter = True
    pktFilter = pktFilterInput.get() 

def onStop():
    global exitPgrm, reFilter
    reFilter = True
    exitPgrm = True

def sniffThreadLoop():
    numPackets = 0
    def stopSniff(pkt):
        return reFilter
    def onPacket(pkt):
        global pkts, pktIndex
        nonlocal numPackets
        aTime = datetime.now().strftime("%H:%M:%S")
        pkts[pktIndex] = (pkt, numPackets, aTime)
        pktIndex = (pktIndex + 1) % maxPackets
        numPackets += 1
    while not exitPgrm:
        sniff(filter=pktFilter, prn=onPacket, stop_filter=stopSniff, store=0)

def updateDisplayLoop():
    while not exitPgrm:
        for i in range(0, maxPackets):
            pktData = pkts[pktIndex + i - maxPackets]
            if pktData != None:
                pkt, numPackets, aTime = pktData
                for crule in rules:
                    try:
                        if eval(crule["rule"]):
                            src = eval(crule["src"])
                            dst = eval(crule["dst"])
                            prot = crule["name"]
                            msg = eval(crule["msg"])
                            pktList.item(pktListChildren[i], values=(numPackets, aTime, src, dst, prot, msg), tags=(prot))
                            break
                    except:
                        pktList.item(pktListChildren[i], values=(numPackets, aTime, "unkown", "unkown", "unkown", "unkown"))
                        break
        time.sleep(0.5)

window = tk.Tk()
window.geometry("800x600")
pktFilterInput = tk.Entry(window)
pktFilterInput.pack()
pktFilterBtn =  tk.Button(window, command=onFilter, text="Apply BPF Syntax Filter")
pktFilterBtn.pack()
pktList = ttk.Treeview(window, selectmode="browse")
pktList["columns"] = ("c1","c2","c3", "c4", "c5", "c6")
pktList.column("#0", width=0, minwidth=0, stretch=tk.NO)
pktList.column("c1", width=50, minwidth=50, stretch=tk.NO)
pktList.column("c2", width=70, minwidth=70, stretch=tk.NO)
pktList.column("c3", width=90, minwidth=90, stretch=tk.NO)
pktList.column("c4", width=90, minwidth=90, stretch=tk.NO)
pktList.column("c5", width=50, minwidth=50, stretch=tk.NO)
pktList.column("c6", width=100, minwidth=200, stretch=tk.YES)
pktList.heading("#0",text="", anchor=tk.W)
pktList.heading("c1", text="No.", anchor=tk.W)
pktList.heading("c2", text="Time", anchor=tk.W)
pktList.heading("c3", text="Source", anchor=tk.W)
pktList.heading("c4", text="Dest", anchor=tk.W)
pktList.heading("c5", text="Proto", anchor=tk.W)
pktList.heading("c6", text="Message", anchor=tk.W)
pktListChildren = []
for i in range(0, maxPackets):
    pktListChildren.append(pktList.insert("", "end", values=(0, 0, 0, 0, 0, 0), tags=("none")))


#set up coloring tags for each rule
pktList.tag_configure("none", background="#ffffff", foreground="#ffffff")
for crule in rules:
    pktList.tag_configure(crule["name"], background=crule["bg"], foreground=crule["fg"])

#Hack from the Tk  to fix bug with coloring for Treeviews
#https://core.tcl-lang.org/tk/info/509cafafae
fixed_map = lambda o,s: [e for e in s.map("Treeview", query_opt=o) if e[:2] != ("!disabled", "!selected")]
style = ttk.Style()
style.map("Treeview", foreground=fixed_map("foreground", style), background=fixed_map("background",style))

pktList.pack(side="top", fill="both")

updateThread = threading.Thread(target=updateDisplayLoop)
sniffThread = threading.Thread(target=sniffThreadLoop)
updateThread.start()
sniffThread.start()
window.mainloop()
onStop()