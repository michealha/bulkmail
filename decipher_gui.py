import subprocess, os, sys, time, shutil, pickle, tkinter as tk
from cryptography.fernet import Fernet

code_string = """import hashlib, base64, os
from cryptography.fernet import Fernet

def make_key(key):
    key = hashlib.sha256(key.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(key)

def replace_name(filename):
    name = '.'.join(filename.split('.')[:-4])
    return name

class Decipher:
    def __init__(self, key, pc_id, extension=None):
        self.key = make_key(key)
        self.pc_id = pc_id
        self.extension = extension if extension is not None else ''
        self.fernet = Fernet(self.key)
    
    def decrypt_file(self, filename):
        previous_name = replace_name(filename)
        with open(filename, 'rb') as f:
            dec = base64.b64decode(f.read())
            with open(previous_name, 'wb') as f:
                text = self.fernet.decrypt(dec)
                f.write(text)

    def decrypt_disk(self, drive):
        for path, subdirs, files in os.walk(drive):
            for file in files:
                filepath = os.path.join(path, file)
                if os.path.isfile(filepath) and self.extension in file and self.pc_id in file:
                    self.decrypt_file(filepath)
                    os.remove(filepath)

def main(key, pc_id, extension=None, details=None):
    decipher = Decipher(key, pc_id, extension)
    driveLetters = 'ABDEFGHIJKLMNOPQRSTUVWXYZ'
    drives = ['%s:/' % (d) for d in driveLetters if os.path.exists('%s:' % (d))]
    try:
        for drive in drives:
            decipher.decrypt_disk(drive)
    except:
        pass
    homepath = os.environ['HOMEPATH']
    homedrive = os.environ['HOMEDRIVE']
    path = os.path.join(homedrive, homepath) + '\\desktop\\details.txt'
    if details is not None:
        with open(path, 'w+') as f:
            f.write(details)

if __name__ == '__main__': \n"""


class MainWindow:
    def __init__(self, root):
        self.root = root
        self.key = tk.StringVar()
        self.pc_id = tk.StringVar()
        self.extension = tk.StringVar()
        self.details = tk.StringVar()
        self.status = tk.StringVar()
        self.status.set("---")
        self.should_cancel = False
        self.THIS_FOLDER_G = os.path.dirname(os.path.realpath(__file__))

        root.title("Decipher App")
        root.configure(bg="#eeeeee")

        try:
            icon_img = tk.Image(
                "photo",
                file=self.THIS_FOLDER_G + "/assets/icon.png"
            )
            root.call(
                "wm",
                "iconphoto",
                root._w,
                icon_img
            )
        except Exception:
            pass

        self.key_label = tk.Label(
            root,
            text="Enter the Secret Key to Decrypt files",
            bg="#eeeeee",
            anchor=tk.W
        )

        self.key_label.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=0,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.key_entry = tk.Entry(
            root,
            textvariable=self.key,
            bg="#fff",
            exportselection=0,
            relief=tk.FLAT
        )

        self.key_entry.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=1,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        
        

        self.pc_id_label = tk.Label(
            root,
            text="Enter the PC id to decrypt files related to a specific computer",
            bg="#eeeeee",
            anchor=tk.W
        )
        
        self.pc_id_label.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=5,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.pc_id_entry = tk.Entry(
            root,
            textvariable=self.pc_id,
            bg="#fff",
            exportselection=0,
            relief=tk.FLAT
        )

        self.pc_id_entry.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=6,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.extension_label = tk.Label(
            root,
            text="Enter the extension to decrypt files (This can be left blank)",
            bg="#eeeeee",
            anchor=tk.W
        )
        
        self.extension_label.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=7,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.extension_entry = tk.Entry(
            root,
            textvariable=self.extension,
            bg="#fff",
            exportselection=0,
            relief=tk.FLAT
        )

        self.extension_entry.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=8,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )


        self.details_label = tk.Label(
            root,
            text="Enter the decryption details here",
            bg="#eeeeee",
            anchor=tk.W
        )
        
        self.details_label.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=9,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.details_entry = tk.Entry(
            root,
            textvariable=self.details,
            bg="#fff",
            exportselection=0,
            relief=tk.FLAT
        )

        self.details_entry.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=10,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )
        
          
        self.encrypt_btn = tk.Button(
            root,
            text="BUILD DECRYPTOR",
            command=self.build_callback,
            width=42,
            bg="#1089ff",
            fg="#ffffff",
            bd=2,
            relief=tk.FLAT
        )
        self.encrypt_btn.grid(
            padx=15,
            pady=8,
            ipadx=24,
            ipady=6,
            row=11,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )      

        self.reset_btn = tk.Button(
            root,
            text="RESET",
            command=self.reset_callback,
            bg="#aaaaaa",
            fg="#ffffff",
            bd=2,
            relief=tk.FLAT
        )

        self.reset_btn.grid(
            padx=15,
            pady=(4, 12),
            ipadx=24,
            ipady=6,
            row=12,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.status_label = tk.Label(
            root,
            textvariable=self.status,
            bg="#eeeeee",
            anchor=tk.W,
            justify=tk.LEFT,
            relief=tk.FLAT,
            wraplength=350
        )

        self.status_label.grid(
            padx=12,
            pady=(0, 12),
            ipadx=0,
            ipady=1,
            row=12,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        tk.Grid.columnconfigure(root, 0, weight=1)
        tk.Grid.columnconfigure(root, 1, weight=1)
        tk.Grid.columnconfigure(root, 2, weight=1)
        tk.Grid.columnconfigure(root, 3, weight=1)

    def build_callback(self):
        self.freeze_controls()
        root = os.path.dirname(os.path.realpath(__file__))
        key = self.key.get()
        pc_id = self.pc_id.get()
        extension = self.extension.get()
        details = self.details.get()
        data = {
            'key': key,
            'pc_id': pc_id,
            'extension': extension,
            'details': details
        }
        string = "    {} = '{}'\n"
        string = ''.join((string.format(k, v) for k, v in data.items()))
        try:     
            os.chdir(root)
            with open('dec.py', 'wb') as f:
                f.write(code_string.encode('utf-8'))
                f.write(string.encode('utf8'))
                f.write(b"    main(key, pc_id, extension, details)\n")
            self.status.set('Building executable, please wait ...')
            self.status_label.update()
            try:
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                subprocess.call('pyinstaller --noconsole --onefile dec.py', startupinfo=si)
            except OSError as e:
                with open('error.txt', 'w') as f:
                    f.write('Failed :' + str(e))
            os.remove('dec.py')
            os.remove('dec.spec')
            cipher_exe_path = os.path.join(root, 'dist/dec.exe')
            shutil.copy2(cipher_exe_path, root)
            shutil.rmtree('__pycache__/')
            shutil.rmtree('build/')
            shutil.rmtree('dist/')

            self.status.set('1 decipher file created successfully')
            self.status_label.update()
            time.sleep(5)
            sys.exit()
        except Exception as e:
            self.status.set(e)
            self.status_label.update()

        self.unfreeze_controls()


    def freeze_controls(self):
        self.key_entry.configure(state="disabled")
        self.pc_id_entry.configure(state="disabled")
        self.extension_entry.configure(state="disabled")
        self.details_entry.configure(state="disabled")
        self.encrypt_btn.configure(state="disabled")
        self.reset_btn.configure(text="CANCEL", command=self.cancel_callback,
            fg="#ed3833", bg="#fafafa")
        self.status_label.update()
    
    def unfreeze_controls(self):
        self.key_entry.configure(state="normal")
        self.details_entry.configure(state="normal")
        self.pc_id_entry.configure(state="normal")
        self.extension_entry.configure(state="normal")
        self.encrypt_btn.configure(state="normal")
        self.reset_btn.configure(text="RESET", command=self.reset_callback,
            fg="#ffffff", bg="#aaaaaa")
        self.status_label.update()


    def reset_callback(self):
        self.key.set("")
        self.pc_id.set("")
        self.extension.set("")
        self.status.set("---")
        self.details.set("---")
    
    def cancel_callback(self):
        self.should_cancel = True


if __name__ == "__main__":
    ROOT = tk.Tk()
    MAIN_WINDOW = MainWindow(ROOT)
    ROOT.mainloop()


    
    
            

