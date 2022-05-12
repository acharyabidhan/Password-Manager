from tkinter import *
from tkinter import messagebox
import os, random, pyperclip

root = Tk()
root.resizable(0,0)
window_width = 800
window_height = 400
root.title("Password Manager And Random Password Generator")
try:
    root.iconbitmap("icon.ico")
except: pass
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
position_top = int(screen_height / 2 - window_height / 2)
position_right = int(screen_width / 2 - window_width / 2)
root.geometry(f'{window_width}x{window_height}+{position_right}+{position_top}')

user = (os.path.split(os.path.expanduser('~'))[-1])
passwordsPath = f"C:\\Users\\{user}\\Password Manager\\"
if not os.path.isdir(passwordsPath):
    os.mkdir(passwordsPath)

appName = StringVar()
userName = StringVar()
password = StringVar()
upperCase = IntVar()
lowerCase = IntVar(value=1)
numbers = IntVar()
symbols = IntVar()
passLenngth = IntVar(value=8)

def clearInputs():
    appInput.delete(0, END)
    unameInput.delete(0, END)
    pwInput.delete(0, END)

def copy():
    pyperclip.copy(password.get())

numbersList = ["1","2","3","4","5","6","7","8","9","0","1","2","3","4","5","6","7","8","9","0","5","6","7","8",]
upperCaselist = [" ","A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z"]
lowerCaseList = ["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z"]
symbolsList = ["!","@","#","$","%","^","&","*","(",")","-","_","=","+","[","{","}","]",";",":","'","|","<",",",">",".","?"]
def generateRandomPassword():
    passLen = passwordLength.get()
    random.shuffle(numbersList)
    randomHint = f"{upperCase.get()}{lowerCase.get()}{numbers.get()}{symbols.get()}"
    random.shuffle(upperCaselist)
    random.shuffle(lowerCaseList)
    random.shuffle(symbolsList)
    pwInput.delete(0, END)

    if not randomHint == "0000":
        if randomHint == "0001":
            oSyList = []
            for i in range(0,passLen):
                oSyList.append(symbolsList[i])
            pwInput.insert(0,"".join(oSyList))

        if randomHint == "0010":
            oNoList = []
            for j in range(0,passLen):
                oNoList.append(numbersList[j])
            pwInput.insert(0,"".join(oNoList))

        if randomHint == "0011":
            numAsym = numbersList+symbolsList
            random.shuffle(numAsym)
            nAndSym = []
            for k in range(0,passLen):
                nAndSym.append(numAsym[k])
            pwInput.insert(0,"".join(nAndSym))

        if randomHint == "0100":
            oLwC = []
            for l in range(0, passLen):
                oLwC.append(lowerCaseList[l])
            pwInput.insert(0,"".join(oLwC))

        if randomHint == "0101":
            lAndC = lowerCaseList+symbolsList
            random.shuffle(lAndC)
            lcAndSy = []
            for m in range(0, passLen):
                lcAndSy.append(lAndC[m])
            pwInput.insert(0,"".join(lcAndSy))

        if randomHint == "0110":
            lcAndNo = lowerCaseList+numbersList
            random.shuffle(lcAndNo)
            lAndN = []
            for n in range(0, passLen):
                lAndN.append(lcAndNo[n])
            pwInput.insert(0,"".join(lAndN))

        if randomHint == "0111":
            LwNoSy = lowerCaseList+numbersList+symbolsList
            random.shuffle(LwNoSy)
            lns = []
            for o in range(0,passLen):
                lns.append(LwNoSy[o])
            pwInput.insert(0,"".join(lns))

        if randomHint == "1000":
            onlyU = []
            for p in range(0, passLen):
                onlyU.append(upperCaselist[p])
            pwInput.insert(0,"".join(onlyU))

        if randomHint == "1001":
            oUs = upperCaselist+symbolsList
            random.shuffle(oUs)
            us = []
            for q in range(0,passLen):
                us.append(oUs[q])
            pwInput.insert(0,"".join(us))

        if randomHint == "1010":
            uNo = upperCaselist+numbersList
            random.shuffle(uNo)
            un = []
            for r in range(0,passLen):
                un.append(uNo[r])
            pwInput.insert(0,"".join(un))

        if randomHint == "1011":
            uNs = upperCaselist+lowerCaseList+symbolsList
            random.shuffle(uNs)
            uns = []
            for s in range(0,passLen):
                uns.append(uNs[s])
            pwInput.insert(0,"".join(uns))

        if randomHint == "1100":
            uAl = upperCaselist+lowerCaseList
            random.shuffle(uAl)
            ul = []
            for t in range(0,passLen):
                ul.append(uAl[t])
            pwInput.insert(0,"".join(ul))

        if randomHint == "1101":
            uLs = upperCaselist+lowerCaseList+symbolsList
            random.shuffle(uLs)
            uls = []
            for u in range(0,passLen):
                uls.append(uLs[u])
            pwInput.insert(0,"".join(uls))

        if randomHint == "1110":
            uLn = upperCaselist+lowerCaseList+numbersList
            random.shuffle(uLn)
            uln = []
            for v in range(0,passLen):
                uln.append(uLn[v])
            pwInput.insert(0,"".join(uln))

        if randomHint == "1111":
            all = numbersList+upperCaselist+lowerCaseList+symbolsList
            random.shuffle(all) 
            aLl = []
            for a in range(0, passLen):
                aLl.append(all[a])
            pwInput.insert(0,"".join(aLl))

    else: messagebox.showinfo("Info", "Check atleast one option to generate random password")

def savepassword():
    filename = appName.get()
    if filename != "" and userName.get() != "" and password.get() != "":
        if filename.isalpha():
            if not " " in userName.get():
                filename = filename.capitalize()
                if not os.path.isdir(f"{passwordsPath}\\{filename}"):
                    os.mkdir(f"{passwordsPath}\\{filename}")
                with open(f"{passwordsPath}\\{filename}\\{userName.get()}", "w") as p:
                    p.write(password.get())
                if not f"{filename} || {userName.get()}" in passwordsList.get(0,END):
                    passwordsList.insert(END, f"{filename} || {userName.get()}")
                clearInputs()
            else: messagebox.showinfo("Invalid", "Username/Email/Phone number shouldn't contain any spaces")
        else: messagebox.showinfo("Invalid", "App/Website name shouldn't contain any spaces/numbers/special characters.")

pswdFrame = LabelFrame(root, background="#32a852", bd=0, font=(15))
pswdFrame.place(x=0, y=0, height=400, width=400)

passwordsList = Listbox(root, bg="white", cursor="hand2",font=(12), selectmode=SINGLE, bd=0, foreground="black")
passwordsList.place(x=0, y=0, height=300, width=400)

allSavedItems = os.listdir(f"{passwordsPath}")

try:
    allSavedItems.remove("password")
except: pass

allSavedItemsLists = []

if allSavedItems:
    for appIndex in range(len(allSavedItems)):
        appUsers = os.listdir(f"{passwordsPath}\\{allSavedItems[appIndex]}")
        for userIndex in range(len(appUsers)):
            oneUSer = []
            oneUSer.append(allSavedItems[appIndex])
            oneUSer.append(appUsers[userIndex])
            allSavedItemsLists.append(oneUSer)

if allSavedItemsLists:
    for oneuser in allSavedItemsLists:
        passwordsList.insert(END, f"{oneuser[0]} || {oneuser[1]}")

authFrame = LabelFrame(root, background="white", bd=0, font=(15))
authFrame.place(x=0, y=300, height=100, width=400)

def showPw():
    showBtn.config(text="Hide", command=hidePw)
    authPwInput.config(show="")

def hidePw():
    showBtn.config(text="Show", command=showPw)
    authPwInput.config(show="*")

def getAdminInfo():
    if os.path.isfile(f"{passwordsPath}\\password"):
        pwPlaceholder = "Enter password to view or update or remove items"
        saveBtnText = "Authenticate"
        return [pwPlaceholder,saveBtnText]

    else:
        pwPlaceholder = "Set new password for this app!"
        saveBtnText = "Save password"
        return [pwPlaceholder,saveBtnText]

adminPass = StringVar()

def viewDetails():
    clearInputs()
    toView = passwordsList.get(ACTIVE)
    if toView:
        toView = toView.split(" || ")
        toViewAppName = toView[0]
        toViewUserName = toView[1]
        with open(f"{passwordsPath}\\{toViewAppName}\\{toViewUserName}", "r") as det:
            toViewPassword = det.read()
        toViewPassword = toViewPassword
        appInput.insert(0,toViewAppName)
        unameInput.insert(0,toViewUserName)
        pwInput.insert(0,toViewPassword)

def removeItem():
    if passwordsList.curselection():
        try:
            toRemoveItem = passwordsList.get(ACTIVE)
            toRemoveItem = toRemoveItem.split(" || ")
            removeFromApp = toRemoveItem[0]
            toRemUsername = toRemoveItem[1]
            os.remove(f"{passwordsPath}\\{removeFromApp}\\{toRemUsername}")
            passwordsList.delete(passwordsList.curselection())
        except:pass

def showInfo():
    if adminPass.get() != "":
        savesAdminPass = open(f"{passwordsPath}\\password", "r")
        pPassword = savesAdminPass.read()
        if pPassword == adminPass.get():
            authPwInput.delete(0, END)
            authPwInput["state"] = DISABLED
            showBtn["state"] = DISABLED
            adminSaveBtn["state"] = DISABLED
            pwInpLabel.config(text="Now you can view passwords from above list.")
            adminSaveBtn.config(text="Authenticated")
            removeBtn["state"] = NORMAL
            showDetails["state"] = NORMAL
        else:
            messagebox.showinfo("Info","Incorrect password!")
    else:
        messagebox.showinfo("Info","Enter password for authentication!")

def saveAdminPassword():
    if adminSaveBtn["text"] == "Authenticate":
        adminSaveBtn.config(command=showInfo)
        return
    if len(adminPass.get()) >= 4:
        with open(f"{passwordsPath}\\password", "w") as ap:
            ap.write(adminPass.get())
        pwInpLabel.config(text="Enter password to view or update or remove items!")
        adminSaveBtn.config(text="Authenticate", command=showInfo)
        authPwInput.delete(0, END)
    else: messagebox.showinfo("Info", "Password must be atleast 4 characters long!")
        
pwInpLabel = Label(authFrame, text=getAdminInfo()[0], background="white", foreground="black", font=(10))
pwInpLabel.place(relx=0.02, rely=0.02)

authPwInput = Entry(authFrame, textvariable=adminPass, width=50, show="*")
authPwInput.place(relx=0.02, rely=0.25, height=22)

showBtn = Button(authFrame, text="Show",bd=0, command=showPw)
showBtn.place(relx=0.80, rely=0.25)

adminSaveBtn = Button(authFrame, text=getAdminInfo()[1], width=15, command=saveAdminPassword)
adminSaveBtn.place(relx=0.02, rely=0.55)

showDetails = Button(authFrame, text="View details", width=15, state=DISABLED, command=viewDetails)
showDetails.place(relx=0.32, rely=0.55)

removeBtn = Button(authFrame, text="Remove", width=14, state=DISABLED, command=removeItem)
removeBtn.place(relx=0.62, rely=0.55)

inputFrame = LabelFrame(root, foreground="black", background="white", bd=0, font=(15))
inputFrame.place(x=400, y=0, height=400, width=400)

appLabel = Label(inputFrame, text="App/Website Name", background="white", font=(15), foreground="black")
appLabel.place(rely=0.0)

appInput = Entry(inputFrame, width=60, textvariable=appName)
appInput.place(rely=0.07)

unameLabel = Label(inputFrame, text="Username/Email/Phone Number", background="white", font=(15), foreground="black")
unameLabel.place(rely=0.17)

unameInput = Entry(inputFrame,width=60, textvariable=userName)
unameInput.place(rely=0.24)

pwLabel = Label(inputFrame, text="Password", background="white", font=(15), foreground="black")
pwLabel.place(rely=0.34)

pwInput = Entry(inputFrame, width=60, textvariable=password)
pwInput.place(rely=0.41)

randomButton = Button(inputFrame, text="Random", width=10, command=generateRandomPassword)
randomButton.place(relx=0.02, rely=0.50)

saveButton = Button(inputFrame, text="Save", width=10, command=savepassword)
saveButton.place(relx=0.24, rely=0.50)

clearButton = Button(inputFrame, text="Clear", width=10, command=clearInputs)
clearButton.place(relx=0.46, rely=0.50)

clearButton = Button(inputFrame, text="Copy", width=10, command=copy)
clearButton.place(relx=0.68, rely=0.50)

randomFrame = LabelFrame(inputFrame, foreground="black", background="white", text="Options for Random Password", bd=0, font=(15))
randomFrame.place(x=0, y=250, height=150, width=400)

includeUC = Checkbutton(randomFrame,background="white", text="Include Uppercase", width=15, activebackground="white", variable=upperCase)
includeUC.place(relx=0.10, rely=0.10)

includeLC = Checkbutton(randomFrame,background="white", text="Include Lowercase", width=15,activebackground="white", variable=lowerCase)
includeLC.place(relx=0.10, rely=0.40)

includeN = Checkbutton(randomFrame,background="white", text="Include Numbers", width=15, activebackground="white", variable=numbers)
includeN.place(relx=0.60,rely=0.10)

includeS = Checkbutton(randomFrame,background="white", text="Include Symbols", width=15, activebackground="white", variable=symbols)
includeS.place(relx=0.60, rely=0.40)

passwordLength = Scale(randomFrame, from_= 4, to = 24, background="white", foreground="black",orient = HORIZONTAL, bd=0, variable=passLenngth)
passwordLength.place(relx=0.0, rely=0.65, width=400)
password_characters = numbersList+upperCaselist+lowerCaseList+symbolsList

root.mainloop()
#Made with ❤️ by Bidhan Acharya :)