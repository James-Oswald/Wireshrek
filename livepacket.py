
import tkinter as tk
import tkinter.ttk as ttk
from scapy.all import sniff
from scapy.layers.inet import IP
from datetime import datetime
import threading

exitPgrm = False    #application state
reFilter = False
pktFilter = ""
    
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
        if IP in pkt:
            if len(pktList.get_children()) > 10:
                ident = pktList.get_children()[0]
                pktList.delete(ident)
            time = datetime.now().strftime("%H:%M:%S")
            src = str(pkt[IP].src)
            dest = str(pkt[IP].dst)
            prot = str(pkt[IP].proto)
            pktList.insert("", "end", iid=str(numPackets), values=(time, src, dest, prot), tags=(prot))
            numPackets += 1
    while not exitPgrm:
        sniff(filter=pktFilter, prn=onPacket, stop_filter=stopSniff)

window = tk.Tk()
window.geometry("800x600")
pktFilterInput = tk.Entry(window)
pktFilterInput.pack()
pktFilterBtn =  tk.Button(window, command=onFilter, text="Apply BPF Syntax Filter")
pktFilterBtn.pack()
pktList = ttk.Treeview(window, selectmode="browse")
pktList["columns"] = ("c1","c2","c3", "c4")
pktList.column("#0", width=0, minwidth=0, stretch=tk.NO)
pktList.column("c1", width=100, minwidth=100, stretch=tk.YES)
pktList.column("c2", width=100, minwidth=100, stretch=tk.YES)
pktList.column("c3", width=80, minwidth=50, stretch=tk.YES)
pktList.column("c4", width=100, minwidth=100, stretch=tk.YES)
pktList.heading("#0",text="", anchor=tk.W)
pktList.heading("c1", text="Time", anchor=tk.W)
pktList.heading("c2", text="Source", anchor=tk.W)
pktList.heading("c3", text="Dest", anchor=tk.W)
pktList.heading("c4", text="", anchor=tk.W)
pktList.tag_configure("6", background="#E7E6FF", foreground="#12272E") #TCP
pktList.tag_configure("17", background="#daeeff", foreground="#12272e") #UDP
pktList.tag_configure("1", background="#daeeff", foreground="#fce0ff") #ICMP

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