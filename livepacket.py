
import tkinter as tk
import tkinter.ttk as ttk
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from datetime import datetime
import threading
import json

exitPgrm = False    #application state
reFilter = False
pktFilter = ""
rulesFile = open("rules.json")
rules = json.load(rulesFile)["rules"]
    
def onFilter():
    global reFilter
    global pktFilter 
    reFilter = True
    pktFilter = pktFilterInput.get() 

def onStop():
    global exitPgrm
    global reFilter
    reFilter = True
    exitPgrm = True

def sniffThreadLoop():
    global exitPgrm
    global pktFilter
    def stopSniff(pkt):
        global reFilter
        return reFilter
    numPackets = 0
    def onPacket(pkt):
        nonlocal numPackets
        global rules
        if len(pktList.get_children()) > 100:
            ident = pktList.get_children()[0]
            pktList.delete(ident)
        for crule in rules:
            if eval(crule["rule"]):
                time = datetime.now().strftime("%H:%M:%S")
                src = eval(crule["src"])
                dst = eval(crule["dst"])
                prot = crule["name"]
                msg = eval(crule["msg"])
                pktList.insert("", "end", iid=str(numPackets), values=(time, src, dst, prot, msg), tags=(prot))
                numPackets += 1
                break
    while not exitPgrm:
        sniff(filter=pktFilter, prn=onPacket, stop_filter=stopSniff)

window = tk.Tk()
window.geometry("800x600")
pktFilterInput = tk.Entry(window)
pktFilterInput.pack()
pktFilterBtn =  tk.Button(window, command=onFilter, text="Apply BPF Syntax Filter")
pktFilterBtn.pack()
pktList = ttk.Treeview(window, selectmode="browse")
pktList["columns"] = ("c1","c2","c3", "c4", "c5")
pktList.column("#0", width=0, minwidth=0, stretch=tk.NO)
pktList.column("c1", width=100, minwidth=100, stretch=tk.YES)
pktList.column("c2", width=100, minwidth=100, stretch=tk.YES)
pktList.column("c3", width=50, minwidth=50, stretch=tk.YES)
pktList.column("c4", width=50, minwidth=50, stretch=tk.YES)
pktList.column("c4", width=100, minwidth=200, stretch=tk.YES)
pktList.heading("#0",text="", anchor=tk.W)
pktList.heading("c1", text="Time", anchor=tk.W)
pktList.heading("c2", text="Source", anchor=tk.W)
pktList.heading("c3", text="Dest", anchor=tk.W)
pktList.heading("c4", text="Proto", anchor=tk.W)
pktList.heading("c5", text="Message", anchor=tk.W)
pktList.tag_configure("6", background="#E7E6FF", foreground="#12272E") #TCP
pktList.tag_configure("17", background="#daeeff", foreground="#12272e") #UDP
pktList.tag_configure("1", background="#daeeff", foreground="#fce0ff") #ICMP

#set up coloring tags for each rule
for crule in rules:
    pktList.tag_configure(crule["name"], background=crule["bg"], foreground=crule["fg"])

#Hack from the Tk  to fix bug with coloring for Treeviews
#https://core.tcl-lang.org/tk/info/509cafafae
def fixed_map(option):
    return [elm for elm in style.map("Treeview", query_opt=option)
            if elm[:2] != ("!disabled", "!selected")]
style = ttk.Style()
style.map("Treeview", foreground=fixed_map("foreground"), background=fixed_map("background"))

pktList.pack(side="top", fill="both")

sniffThread = threading.Thread(target=sniffThreadLoop)
sniffThread.start()
window.mainloop()
onStop()