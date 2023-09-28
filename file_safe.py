import sys
import PySimpleGUI as sg
from cryptography.fernet import Fernet
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def resource_path(relative_path):
    # Get absolute path to resource, works for dev and for PyInstaller
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

def get_key_from_password(password):
    backend = default_backend()
    salt = 1
    salt = salt.to_bytes(2, 'big')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        backend = backend
    )
    key = base64.urlsafe_b64encode(kdf.derive(bytes(password, 'utf-8')))
    return key
    
def save_file(path, text, password):
    key = get_key_from_password(password)
    fernet = Fernet(key)
    encrypted_text = fernet.encrypt(bytes(text, 'utf-8'))
    with open(path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_text)

def read_file(path, password):
    key = get_key_from_password(password)
    fernet = Fernet(key)
    text = None
    try:
        with open(path, 'rb') as enc_file:
            encrypted_text = enc_file.read()
        text = fernet.decrypt(encrypted_text)
        text = str(text, encoding='ascii', errors='backslashreplace')
    except:
        text = None
        
    return text

def show_window():

    menu_def = [['File', ['New', 'Open', 'Save', 'Save As', 'Close', 'Exit']]]

    layout = [[sg.Menu(menu_def, tearoff=False, pad=(200, 1))],
                [sg.Multiline(size=(100,50), key='-MLINE-', expand_x = True, expand_y = True, enable_events = True)]]

    window = sg.Window('File Safe', layout, resizable = True, icon = resource_path('file_safe.ico'))

    path = None
    password = None
    text_has_changed = False
    
    while True:
        event, values = window.read()
        print(event, values)
        if event in (sg.WIN_CLOSED, 'Exit'):
            break
        elif event == '-MLINE-':
            text_has_changed = True
        elif event == 'Save' or event == 'Save As':
            print(path, password)
            if event == 'Save' and path != None:
                save_file(path, values['-MLINE-'], password)
                text_has_changed = False
            else:
                # Ask the user for a file path
                new_path = sg.popup_get_file('Select file path', save_as = True)
                if new_path == None:
                    continue
                # Ask the user for a password
                new_password = sg.popup_get_text('Enter the password needed to open the file', title="Password")
                if new_password == None:
                    continue
                save_file(new_path, values['-MLINE-'], new_password)
                path = new_path
                password = new_password
                text_has_changed = False

        elif event == 'New' or event == 'Close' or event == 'Open':
            print('Create a new file')
            print(f'Text to save: {values["-MLINE-"]}')
            if values['-MLINE-'] != None and len(values['-MLINE-']) > 0 and text_has_changed:
                # Ask the user if they want to save the existing file before exiting
                save_file_response = sg.popup_yes_no('Do you want to save your file?')
                if save_file_response == 'Yes':

                    if path == None:
                        # Ask the user for a file path
                        path = sg.popup_get_file('Select file path', save_as = True)
                        if path == None:
                            continue
                    if password == None:
                        # Ask the user for a password
                        password = sg.popup_get_text('Enter the password needed to open the file', title="Password")
                        if password == None:
                            continue

                    save_file(path, values['-MLINE-'], password)

            if event == 'Open':
                # Ask the user for the path
                path = sg.popup_get_file('Select file path')
                if path == None:
                    continue
                # Ask the user for a password
                password = sg.popup_get_text('Enter the password needed to open the file', title="Password")
                if password == None:
                    continue
                text = read_file(path, password)
                if text == None:
                    sg.popup_ok('Sorry, but the file could not be opened. Please check the path and password and try again.')
                else:
                    window['-MLINE-'].print(text)
            else:
                # Clear the window of text
                window['-MLINE-'].update('')

                path = None
                password = None
                text_has_changed = False
    
    
    window.close()


if len(sys.argv) == 1:
    show_window()

