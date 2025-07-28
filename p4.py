import os
import tkinter as tk
from tkinter import filedialog
from functools import partial
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from tkinter import messagebox
from PIL import Image
import numpy as np
import io
from Crypto.Util import Padding
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad



def aes_dcrypt(mode, key, iv, input_file, output_file):
    # Seleccionamos el modo de operación
    if mode == "ECB":
        cipher_mode = AES.MODE_ECB
    elif mode == "CBC":
        cipher_mode = AES.MODE_CBC
    elif mode == "CFB":
        cipher_mode = AES.MODE_CFB
    elif mode == "OFB":
        cipher_mode = AES.MODE_OFB
    else:
        raise ValueError("Modo de operación no válido")
    
    # Creamos el objeto de cifrado/descifrado
    if mode == "ECB":
        cipher = AES.new(key, cipher_mode)
    else:
        cipher = AES.new(key, cipher_mode, iv)

    with open(input_file, "rb") as f:
        bmp_header = f.read(54)  # Leemos los primeros 54 bytes del archivo BMP (encabezado)
        bmp_data = f.read()  # Leemos los datos de la imagen


     # Cifrado
    nombreArchivo = os.path.splitext(input_file)[0]
    print(nombreArchivo)
    ciphertext = cipher.decrypt(pad(bmp_data, AES.block_size))
    with open(nombreArchivo + output_file+".bmp", "wb") as f:
        f.write(bmp_header + ciphertext)  # Escribimos el encabezado y los datos cifrados en el archivo de salida




def aes_crypt(mode, key, iv, input_file, output_file):
    # Seleccionamos el modo de operación
    if mode == "ECB":
        cipher_mode = AES.MODE_ECB
    elif mode == "CBC":
        cipher_mode = AES.MODE_CBC
    elif mode == "CFB":
        cipher_mode = AES.MODE_CFB
    elif mode == "OFB":
        cipher_mode = AES.MODE_OFB
    else:
        raise ValueError("Modo de operación no válido")
    
    # Creamos el objeto de cifrado/descifrado
    if mode == "ECB":
        cipher = AES.new(key, cipher_mode)
    else:
        cipher = AES.new(key, cipher_mode, iv)

    with open(input_file, "rb") as f:
        bmp_header = f.read(54)  # Leemos los primeros 54 bytes del archivo BMP (encabezado)
        bmp_data = f.read()  # Leemos los datos de la imagen


     # Cifrado
    nombreArchivo = os.path.splitext(input_file)[0]
    print(nombreArchivo)
    ciphertext = cipher.encrypt(pad(bmp_data, AES.block_size))
    with open(nombreArchivo + output_file+".bmp", "wb") as f:
        f.write(bmp_header + ciphertext)  # Escribimos el encabezado y los datos cifrados en el archivo de salida



def crypt_event(mode, key, iv, input_file, output_file):
    try:
        print(output_file)
        key = key.encode("utf-8")
        iv = iv.encode("utf-8")
        aes_crypt(mode, key, iv, input_file, output_file)
        #messagebox.showinfo("Éxito", f"El archivo {output_file} ha sido creado")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def dcrypt_event(mode, key, iv, input_file, output_file):
    try:
        print(output_file)
        key = key.encode("utf-8")
        iv = iv.encode("utf-8")
        aes_dcrypt(mode, key, iv, input_file, output_file)
        #messagebox.showinfo("Éxito", f"El archivo {output_file} ha sido creado")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def file_select(entry):
    file_path = filedialog.askopenfilename()
    entry.delete(0, tk.END)
    entry.insert(0, file_path)
 

def main():
    
    def on_option_selected(*args):
    # This function will be called every time the value of mode_var changes
    # It updates the value of mode_var with the currently selected option
        print(mode_var.get())

    # Creamos la ventana principal
    root = tk.Tk()
    root.title("Cifrado AES")
    
    # Creamos los widgets necesarios
    mode_label = tk.Label(root, text="Modo de operación:")
    mode_options = ["ECB", "CBC", "CFB", "OFB"]
    mode_var = tk.StringVar(root, value=mode_options[0])
    mode_menu = tk.OptionMenu(root, mode_var, *mode_options)
    # Bind the on_option_selected function to the mode_var variable
    mode_var.trace("w", on_option_selected)

    
    key_label = tk.Label(root, text="Clave:")
    key_entry = tk.Entry(root)
    
    iv_label = tk.Label(root, text="Vector de inicialización:")
    iv_entry = tk.Entry(root)
    
    input_label = tk.Label(root, text="Archivo de entrada:")
    input_entry = tk.Entry(root)
    input_button = tk.Button(root, text="Seleccionar archivo", command=partial(file_select, input_entry))
    

    #output sera el input sin extension
    output_entry = os.path.splitext(input_entry.get())[0] 

    
    #encrypt_button = tk.Button(root, text="Cifrar", command=partial(crypt_event, mode_var.get(), key_entry.get(), iv_entry.get(), input_entry.get(), output_entry.get() + "_e" + mode_var.get()))
        #decrypt_button = tk.Button(root, text="Descifrar", command=partial(crypt_event, mode_var.get(), key_entry.get(), iv_entry.get(), input_entry.get(), output_entry.get() + "_d" + mode_var.get()))
    #change partial() to lambda:
    encrypt_button = tk.Button(root, text="Cifrar", command=lambda: crypt_event(mode_var.get(), key_entry.get(), iv_entry.get(), input_entry.get(), output_entry  + "_e" + mode_var.get()))
    decrypt_button = tk.Button(root, text="Descifrar", command=lambda: dcrypt_event(mode_var.get(), key_entry.get(), iv_entry.get(), input_entry.get(), output_entry  + "_d" + mode_var.get()))
    
    # Creamos la disposición de la ventana
    mode_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
    mode_menu.grid(row=0, column=1, padx=10, pady=10)

    key_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
    key_entry.grid(row=1, column=1, padx=10, pady=10)

    iv_label.grid(row=2, column=0, padx=10, pady=10, sticky="w")
    iv_entry.grid(row=2, column=1, padx=10, pady=10)

    input_label.grid(row=3, column=0, padx=10, pady=10, sticky="w")
    input_entry.grid(row=3, column=1, padx=10, pady=10)
    input_button.grid(row=3, column=2, padx=10, pady=10)




    encrypt_button.grid(row=5, column=0, padx=10, pady=10)
    decrypt_button.grid(row=5, column=1, padx=10, pady=10)

    # Iniciamos el ciclo de eventos
    root.mainloop()


if __name__ == "__main__":
    main()



