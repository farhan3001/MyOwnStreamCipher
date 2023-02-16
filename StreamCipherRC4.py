import os
import sys
import hashlib
import tkinter as tk
from tkinter import filedialog
from Cryptodome.Cipher import ARC4

# Simple explanation of RC4 encryption and decryption process
class StreamCipherRC4:
    #  KSA    
    def keyStateArray(self,key):
        S = [i for i in range(0, 256)]
        
        i = 0
        for j in range(0, 256):
            i = (i + S[j] + key[j % len(key)]) % 256
            
            tmp = S[j]
            S[j] = S[i]
            S[i] = tmp #swap element
            
        return S
        
    # PRGA
    def pseudoRandomGenerationAutomation(self,S):
        i = 0
        j = 0
        while True:
            i = (1 + i) % 256
            j = (S[i] + j) % 256
            
            tmp = S[j]
            S[j] = S[i]
            S[i] = tmp # swap element
            
            yield S[(S[i] + S[j]) % 256] # add both elements and mod 256       


    def encryption(self,text, key):
        text = [ord(char) for char in text]
        key = [ord(char) for char in key]
        
        S = self.keyStateArray(key)
        key_stream = self.pseudoRandomGenerationAutomation(S)
        
        ciphertext = ''
        for char in text:
            enc = str(hex(char ^ next(key_stream))).upper()
            ciphertext += (enc)
            
        return ciphertext
        

    def decryption(self,ciphertext, key):
        ciphertext = ciphertext.split('0X')[1:]
        ciphertext = [int('0x' + c.lower(), 0) for c in ciphertext]
        key = [ord(char) for char in key]
        
        S = self.keyStateArray(key)
        key_stream = self.pseudoRandomGenerationAutomation(S)
        
        plaintext = ''
        for char in ciphertext:
            dec = str(chr(char ^ next(key_stream)))
            plaintext += dec
        
        return plaintext

class EncryptionTool:
    def __init__(self, user_file, user_key):
        # get the path to input file
        self.user_file = user_file

        self.input_file_size = os.path.getsize(self.user_file)
        self.chunk_size = 1024
        self.total_chunks = (self.input_file_size // self.chunk_size) + 1
        
        # convert the key to bytes
        self.user_key = bytes(user_key, "utf-8")

        # get the file extension
        self.file_extension = self.user_file.split(".")[-1]
        
        # hash type for hashing key
        self.hash_type = "SHA256"

        # encrypted file name
        self.encrypt_output_file = ".".join(self.user_file.split(".")[:-1]) \
            + "." + self.file_extension + ".rc4"

        # decrypted file name
        self.decrypt_output_file = self.user_file.split(".")
        self.decrypt_output_file = ".".join(self.decrypt_output_file[:-2]) \
            + "." + self.decrypt_output_file[1]

        # dictionary to store hashed key
        self.hashed_key = dict()

        # hash key and into 32 bit hashes
        self.hashKey()

    def readInChunks(self, file_object, chunk_size=1024):
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def encryption(self):
        # create a cipher object
        cipher_object = ARC4.new(
            self.hashed_key["key"]
        )

        input_file = open(self.user_file, "rb")
        output_file = open(self.encrypt_output_file, "ab")
        done_chunks = 0

        for piece in self.readInChunks(input_file, self.chunk_size):
            encrypted_content = cipher_object.encrypt(piece)
            output_file.write(encrypted_content)
            done_chunks += 1
            yield (done_chunks / self.total_chunks) * 100
        
        input_file.close()
        output_file.close()

        # clean up the cipher object
        del cipher_object

    def decryption(self):
        # create a cipher object
        cipher_object = ARC4.new(
            self.hashed_key["key"]
        )

        # delete file if file already exist
        self.abort()

        input_file = open(self.user_file, "rb")
        output_file = open(self.decrypt_output_file, "xb")
        done_chunks = 0

        for piece in self.readInChunks(input_file):
            decrypted_content = cipher_object.decrypt(piece)
            output_file.write(decrypted_content)
            done_chunks += 1
            yield (done_chunks / self.total_chunks) * 100
        
        input_file.close()
        output_file.close()

        # clean up the cipher object
        del cipher_object

    def abort(self):
        if os.path.isfile(self.encrypt_output_file):
            os.remove(self.encrypt_output_file)
        if os.path.isfile(self.decrypt_output_file):
            os.remove(self.decrypt_output_file)


    def hashKey(self):
        # convert key to hash
        # create a new hash object
        hasher = hashlib.new(self.hash_type)
        hasher.update(self.user_key)

        # turn the output key hash into 32 bytes (256 bits)
        self.hashed_key["key"] = bytes(hasher.hexdigest()[:32], "utf-8")

        # clean up hash object
        del hasher

class MainWindow:

    # configure root directory path relative to this file
    THIS_FOLDER_G = ""
    if getattr(sys, "frozen", False):
        THIS_FOLDER_G = os.path.dirname(sys.executable)
    else:
        THIS_FOLDER_G = os.path.dirname(os.path.realpath(__file__))

    def __init__(self, root):
        self.root = root
        self._cipher = None
        self._file_url = tk.StringVar()
        self._secret_key = tk.StringVar()
        self._status = tk.StringVar()
        self._status.set("---")

        self.should_cancel = False

        root.title("RC4 Stream Cipher Encryption Python")
        root.configure(bg="#FFFDD0")

        self.file_entry_label = tk.Label(
            root,
            text="Enter File Path Or Click SELECT FILE Button",
            bg="#FFFDD0",
            fg="#000000",
            anchor=tk.W
        )
        self.file_entry_label.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=0,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.file_entry = tk.Entry(
            root,
            textvariable=self._file_url,
            bg="#fff",
            exportselection=0,
            relief=tk.FLAT
        )
        self.file_entry.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=1,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.select_btn = tk.Button(
            root,
            text="SELECT FILE",
            command=self.selectFileCallback,
            width=42,
            bg="#1089ff",
            fg="#000000",
            bd=2,
            relief=tk.FLAT
        )
        self.select_btn.grid(
            padx=15,
            pady=8,
            ipadx=24,
            ipady=6,
            row=2,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.key_entry_label = tk.Label(
            root,
            text="Enter Key for Encryption and Decryption",
            bg="#FFFDD0",
            fg="#000000",
            anchor=tk.W
        )
        self.key_entry_label.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=3,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.key_entry = tk.Entry(
            root,
            textvariable=self._secret_key,
            bg="#fff",
            exportselection=0,
            relief=tk.FLAT
        )
        self.key_entry.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=4,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.encrypt_btn = tk.Button(
            root,
            text="ENCRYPT",
            command=self.encryptCallback,
            bg="#ed3833",
            fg="#000000",
            bd=2,
            relief=tk.FLAT
        )
        self.encrypt_btn.grid(
            padx=(15, 6),
            pady=8,
            ipadx=24,
            ipady=6,
            row=7,
            column=0,
            columnspan=2,
            sticky=tk.W+tk.E+tk.N+tk.S
        )
        
        self.decrypt_btn = tk.Button(
            root,
            text="DECRYPT",
            command=self.decryptCallback,
            bg="#00bd56",
            fg="#000000",
            bd=2,
            relief=tk.FLAT
        )
        self.decrypt_btn.grid(
            padx=(6, 15),
            pady=8,
            ipadx=24,
            ipady=6,
            row=7,
            column=2,
            columnspan=2,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.reset_btn = tk.Button(
            root,
            text="RESET",
            command=self.resetCallback,
            bg="#aaaaaa",
            fg="#000000",
            bd=2,
            relief=tk.FLAT
        )
        self.reset_btn.grid(
            padx=15,
            pady=(4, 12),
            ipadx=24,
            ipady=6,
            row=8,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.status_label = tk.Label(
            root,
            textvariable=self._status,
            bg="#FFFDD0",
            fg="#000000",
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
            row=9,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        tk.Grid.columnconfigure(root, 0, weight=1)
        tk.Grid.columnconfigure(root, 1, weight=1)
        tk.Grid.columnconfigure(root, 2, weight=1)
        tk.Grid.columnconfigure(root, 3, weight=1)

    def selectFileCallback(self):
        try:
            name = filedialog.askopenfile()
            self._file_url.set(name.name)
    
        except Exception as e:
            self._status.set(e)
            self.status_label.update()
    
    def freezeControls(self):
        self.file_entry.configure(state="disabled")
        self.key_entry.configure(state="disabled")
        self.select_btn.configure(state="disabled")
        self.encrypt_btn.configure(state="disabled")
        self.decrypt_btn.configure(state="disabled")
        self.reset_btn.configure(text="CANCEL", command=self.cancelCallback,
            fg="#ed3833", bg="#fafafa")
        self.status_label.update()
    
    def unfreezeControls(self):
        self.file_entry.configure(state="normal")
        self.key_entry.configure(state="normal")
        self.select_btn.configure(state="normal")
        self.encrypt_btn.configure(state="normal")
        self.decrypt_btn.configure(state="normal")
        self.reset_btn.configure(text="RESET", command=self.resetCallback,
            fg="#ffffff", bg="#aaaaaa")
        self.status_label.update()

    def encryptCallback(self):
        self.freezeControls()

        try:
            self._cipher = EncryptionTool(
                self._file_url.get(),
                self._secret_key.get(),
            )
            for percentage in self._cipher.encryption():
                if self.should_cancel:
                    break
                percentage = "{0:.2f}%".format(percentage)
                self._status.set(percentage)
                self.status_label.update()
            self._status.set("File Encrypted!")
            if self.should_cancel:
                self._cipher.abort()
                self._status.set("Cancelled!")
            self._cipher = None
            self.should_cancel = False
        except Exception as e:
            self._status.set(e)

        self.unfreezeControls()

    def decryptCallback(self):
        self.freezeControls()

        try:
            self._cipher = EncryptionTool(
                self._file_url.get(),
                self._secret_key.get(),
            )
            for percentage in self._cipher.decryption():
                if self.should_cancel:
                    break
                percentage = "{0:.2f}%".format(percentage)
                self._status.set(percentage)
                self.status_label.update()
            self._status.set("File Decrypted!")
            if self.should_cancel:
                self._cipher.abort()
                self._status.set("Cancelled!")
            self._cipher = None
            self.should_cancel = False
        except Exception as e:
            self._status.set(e)
        
        self.unfreezeControls()

    def resetCallback(self):
        self._cipher = None
        self._file_url.set("")
        self._secret_key.set("")
        self._status.set("---")
    
    def cancelCallback(self):
        self.should_cancel = True


if __name__ == "__main__":
    ROOT = tk.Tk()
    MAIN_WINDOW = MainWindow(ROOT)
    ROOT.mainloop()