import tkinter as tk
import tkinter.ttk as tkk

class Application(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.pack()
        self.setup()

    def setup(self):
        self.packetList = tkk.Treeview(self)
        self.packetList["columns"] = ("one","two","three")
        self.packetList.column("#0", width=270, minwidth=270, stretch=tk.YES)
        self.packetList.column("one", width=150, minwidth=150, stretch=tk.YES)
        self.packetList.column("two", width=400, minwidth=200, stretch=tk.YES)
        self.packetList.column("three", width=80, minwidth=50, stretch=tk.YES)
        self.packetList.heading("#0",text="Time", anchor=tk.W)
        self.packetList.heading("one", text="Source", anchor=tk.W)
        self.packetList.heading("two", text="Dest", anchor=tk.W)
        self.packetList.heading("three", text="Size", anchor=tk.W)
        self.packetList.pack(side="top")

        self.test = tk.Button(self, text="TEST", command=self.test)
        self.test.pack()

        self.quit = tk.Button(self, text="QUIT", fg="red", command=self.master.destroy)
        self.quit.pack(side="bottom")

    def test(self):
        self.packetList.insert("", 'end', text ="L1", values =("Nidhi", "F", "25")) 

root = tk.Tk()
root.geometry("800x600")
app = Application(master=root)
app.mainloop()
