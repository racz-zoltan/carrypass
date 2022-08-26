# Copyright 2022 Rácz Zoltán


from ctypes import windll, c_int64
windll.user32.SetProcessDpiAwarenessContext(c_int64(-4))

import os
os.environ['KIVY_IMAGE'] = 'pil'


from multiprocessing.sharedctypes import Value
import kivy
kivy.require('2.0.0')
import kivymd


from kivy.core.window import Window

Window.maximize()

maxSize = Window.system_size


desiredSize = (maxSize[0]*0.28, maxSize[1]*0.85)
Window.size = desiredSize


Window.left = maxSize[0]*0.7
Window.top = maxSize[1]*0.12


from kivymd.uix.screen import MDScreen
from kivy.uix.screenmanager import ScreenManager, Screen, FadeTransition, FallOutTransition, WipeTransition
from kivymd.app import MDApp
from kivymd.uix.menu import MDDropdownMenu
from kivy.lang import Builder
from kivy.uix.image import Image
from kivymd.uix.button import MDFillRoundFlatIconButton, MDFillRoundFlatButton, MDFloatingActionButtonSpeedDial
from kivymd.uix.textfield import MDTextField
from kivymd.uix.label import MDLabel
from kivymd.uix.toolbar import MDToolbar
from kivymd.uix.fitimage import FitImage
from kivymd.uix.list import OneLineListItem, ThreeLineListItem, IRightBodyTouch, OneLineAvatarIconListItem, OneLineIconListItem
from kivy.properties import ObjectProperty, StringProperty
from kivy.uix.recycleview import RecycleView
from kivymd.uix.toolbar import MDTopAppBar
from kivymd.uix.button import MDFlatButton
from kivymd.uix.dialog import MDDialog
from kivy.uix.image import Image
from kivy.uix.widget import Widget
from kivymd.uix.button import MDFloatingActionButtonSpeedDial
from kivymd.uix.behaviors import RoundedRectangularElevationBehavior
from kivymd.uix.card import MDCard
from kivy.utils import get_color_from_hex
from kivymd.icon_definitions import md_icons
from kivymd.uix.selectioncontrol import MDCheckbox
from kivymd.toast import toast



from random import sample, randint
from string import ascii_lowercase


import sqlite3
import sys
from kivy.resources import resource_add_path, resource_find
import pandas as pd
import secrets
from urllib.parse import urlsplit
import hashlib
from hashlib import sha256
import string
import random
import re 
from datetime import datetime
from turtle import bgcolor, title, width
from numpy import var
import pyperclip
import time
import pyautogui
from PIL import ImageGrab, Image, ImageTk
import webbrowser
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import ctypes


import onetimepad
import pyotp
import qrcode
import socket
import uuid

import pwnedpasswords


from tkinter import *

tk_root = Tk()

screen_width = tk_root.winfo_screenwidth()
screen_height = tk_root.winfo_screenheight()



def create_pandas_table(sql_query, conn):
    table = pd.read_sql_query(sql_query, conn)
    return table


def get_random_password_string(length):
		letters_count = length-3
		digits_count = 1
		lowercase_count = 1
		uppercase_count = 1
		letters = ''.join((secrets.choice(string.ascii_letters + string.digits) for i in range(letters_count)))
		digits = ''.join((secrets.choice(string.digits) for i in range(digits_count)))
		lowers = ''.join((secrets.choice(string.ascii_lowercase) for i in range(lowercase_count)))
		uppers = ''.join((secrets.choice(string.ascii_uppercase) for i in range(uppercase_count)))


		sample_list = list(letters + digits + lowers + uppers)
		random.shuffle(sample_list)

		final_string = ''.join(sample_list)
		return final_string



def get_random_special_password_string(length):
		letters_count = length-4
		digits_count = 1
		punctuation_count = 1
		lowercase_count = 1
		uppercase_count = 1
		letters = ''.join((secrets.choice(string.ascii_letters + string.digits + string.punctuation) for i in range(letters_count)))
		digits = ''.join((secrets.choice(string.digits) for i in range(digits_count)))
		lowers = ''.join((secrets.choice(string.ascii_lowercase) for i in range(lowercase_count)))
		uppers = ''.join((secrets.choice(string.ascii_uppercase) for i in range(uppercase_count)))
		punctuations = ''.join((secrets.choice(string.punctuation) for i in range(punctuation_count)))

		sample_list = list(letters + digits + lowers + uppers + punctuations)
		random.shuffle(sample_list)

		final_string = ''.join(sample_list)
		return final_string


folder_for_eyes = '/carrypass_images'
folder_for_keys = '/carrypass_keys'
folder_for_db = '/carrypass_database'



eyes_isExist = os.path.exists(folder_for_eyes)
keys_isExist = os.path.exists(folder_for_keys)
db_isExist = os.path.exists(folder_for_db)

 
if not eyes_isExist:
  os.makedirs(folder_for_eyes)


if not keys_isExist:
  os.makedirs(folder_for_keys)


if not db_isExist:
  os.makedirs(folder_for_db)


iteration_number_one = 300000
iteration_number_two = 100000


logged_in_or_not = []


stored_masterpass = ''

wrong_password = ['alma']

master_received = ''

timeout = ''

timeout_start = ''

insecure_login = False

url_for_id = """"""

secret_note = ""

selected_device_id = ""




conn = sqlite3.connect('/carrypass_database/master.db')

c = conn.cursor()


c.execute("""CREATE TABLE if not exists masterpassword (
    masterpass text,
	salt text,
    pepper text,
	created_time text)
	""")



c.execute("""CREATE TABLE if not exists logindata (
	category text,
	nickname text,
	url text,
	username text,
	salt text,
	variant integer,
	pepper text,  
	special text,
	max_pass_length text,
	two_page text,
	created_time text,
	username_img text,
	password_img text,
	ciphertext text,
	usn_x_ratio real,
	usn_y_ratio real,
	pwd_x_ratio real,
	pwd_y_ratio real,
	ciphertext_two text,
	webbrowser text)
	""")


c.execute("""CREATE TABLE if not exists notes (
    textone text,
	texttwo text,
	salt_one text,
	salt_two text
	)
	""")



c.execute("""CREATE TABLE if not exists twofa_newdevice (
    two_f_a text,
	two_f_a_salt text,
	qr_base text,
	time_of_trust text
	)
	""")



c.execute("""CREATE TABLE if not exists devices (
	device_id text,
    device_nickname text,
	device_name text,
	salt text,
    timeoftrust integer,
	twofa text,
	twofa_filename text
	)
	""")


conn.commit()

conn.close()


class CustomOverFlowMenu(MDDropdownMenu):
    pass


class LoginWindow(Screen):
    password_mask = StringProperty("•")


class OTPWindow(Screen):
    password_mask = StringProperty("•")


class MainViewWindow(Screen):
	pass


class EditListItemWindow(Screen):
	pass


class EditPasswordWindow(Screen):
	pass




class FutureSettingsWindow(Screen):
	pass


class WebbrowserSettingsWindow(Screen):
	pass


class DeviceSettingsWindow(Screen):
	pass


class ProcessingRequestWindow(Screen):
	pass


class StarterWindow(Screen):
	pass


class ApplicationWindow(Screen):
	pass


class WindowManager(ScreenManager):
        ScreenManager(transition=FadeTransition())
        pass


class MD3Card(MDCard, RoundedRectangularElevationBehavior):
    '''Implements a material design v3 card.'''

    text = StringProperty()


class ListItemWithCheckbox(OneLineAvatarIconListItem):
    '''Custom list item.'''

    icon = StringProperty("android")


class RightCheckbox(IRightBodyTouch, MDCheckbox):
    '''Custom right container.'''




class CustomOneLineIconListItem(OneLineIconListItem):
    icon = StringProperty()


class PreviousMDIcons(Screen):
    pass


class MDFloatingActionButtonSpeedDial(Button):
    pass



class CarryPassApp(MDApp):

        from ctypes import windll, c_int64
        windll.user32.SetProcessDpiAwarenessContext(c_int64(-4))

        insecure_dialog = None
        unclear_dialog = None
        no_image_dialog = None
        save_usn_image_dialog = None
        save_pwd_image_dialog = None
        delete_record_dialog = None
        password_change_dialog = None
        login_before_passwordchange = None
        application_startup = None
        delete_noteone_dialog = None
        delete_notetwo_dialog = None
        delete_device_dialog = None
        

        icon = 'carrypass_blue.png'


        loginmenu = {
            'Add new login page': 'web-plus',
            'Add new application': 'card-plus-outline',
            'Check pwned passwords': 'chess-pawn',
        }

        selectedpagemenu = {
            'Get current password': 'table-key',
            'Edit password': 'key-change',
            'Renew password': 'autorenew',
            'Select primary browser': 'web',
        }

        notemenu = {
            'Save note': 'content-save-all-outline',
            'Delete note': 'delete-forever-outline',
        }


        devicesmenu = {
            'Create QR-code for TOTP': 'qrcode-scan',
            'Delete QR-code': 'delete-variant',
        }


        def build(self):
            Window.borderless = True

            Window.size = desiredSize

            self.theme_cls.material_style = "M3"
            self.theme_cls.theme_style = "Light"
            self.theme_cls.primary_palette = "Indigo"
            return Builder.load_file('main_blue.kv')


        def window_sizing(self):
            Window.maximize()

            maxSize = Window.system_size

            desiredSize = (maxSize[0]*0.28, maxSize[1]*0.85)
            Window.size = desiredSize

            Window.left = maxSize[0]*0.71
            Window.top = maxSize[1]*0.12


        def timeout_app(self):
            if time.time() > timeout_start + timeout:
                self.root.ids.activate.ids.login_label.text = "Application timed out"
                self.deactivate_with_timeout()
            else:
                pass



        def query_login_data(self):
                global master_pass_stored
                global master_salt
                global master_pepper
                global site_url_oid_list
                global masterpass_list
                global master_created_time
                try:
                    conn = sqlite3.connect("/carrypass_database/master.db")
                    site_url_oid = create_pandas_table("SELECT category, nickname, url, username, salt, pepper, special, max_pass_length, two_page, created_time, username_img, password_img, ciphertext, webbrowser FROM logindata ORDER BY oid", conn)
                    site_url_oid_list = []
                    for url in site_url_oid['url']:
                        site_url_oid_list.append(url)


                    masterpass_query = create_pandas_table("SELECT masterpass, salt, pepper, created_time FROM masterpassword ORDER BY oid", conn)
                    masterpass_list = []
                    for passw in masterpass_query['masterpass']:
                        masterpass_list.append(passw)

                    master_pass_stored = masterpass_query['masterpass'].iloc[0]
                    master_salt = masterpass_query['salt'].iloc[0]
                    master_pepper = masterpass_query['pepper'].iloc[0]
                    master_created_time = masterpass_query['created_time'].iloc[0]
                    conn.close()

                except:
                    pass



        def one_time_password(self):
                global timeout_start
                global timeout

                timeout_start = time.time()

                global device_name
                global devices_names_list
                global devices_salt_list
                try:
                    conn = sqlite3.connect("/carrypass_database/master.db")
                    devices_all = create_pandas_table("SELECT device_id, device_nickname, device_name, salt, timeoftrust, twofa, twofa_filename FROM devices ORDER BY oid", conn)
                    conn.close()

                    devices_id_list = []
                    for deviceid in devices_all['device_id']:
                        devices_id_list.append(deviceid)

                    devices_names_list = []
                    for device in devices_all['device_name']:
                        devices_names_list.append(device)

                    devices_salt_list = []
                    for salt in devices_all['salt']:
                        devices_salt_list.append(salt)

                    devices_time_of_trust_list = []
                    for time_of_trust in devices_all['timeoftrust']:
                        devices_time_of_trust_list.append(time_of_trust)

                    devices_twofa_list = []
                    for twofa in devices_all['twofa']:
                        devices_twofa_list.append(twofa)

                    devices_twofa_filename_list = []
                    for twofa_filename in devices_all['twofa_filename']:
                        devices_twofa_filename_list.append(twofa_filename)
                    
                    device_name = socket.gethostname()


                    device_index = devices_names_list.index(device_name)
                    current_device_id = devices_id_list[device_index]

                    current_device_trust = devices_time_of_trust_list[device_index]
                    current_twofa = devices_twofa_list[device_index]
                    current_twofa_filename = devices_twofa_filename_list[device_index]

                    conn = sqlite3.connect("/carrypass_database/master.db")
                    newdevice_data = create_pandas_table("SELECT two_f_a, two_f_a_salt, time_of_trust FROM twofa_newdevice ORDER BY oid", conn)

                    list_two_f_a_salt = newdevice_data['two_f_a_salt'].values.tolist()

                    secret_two_f_a_salt = list_two_f_a_salt[0]


                    conn.close()

                    key_one = hashlib.pbkdf2_hmac(
                    'sha256', 
                    logged_in_or_not[0].encode('utf-8'), 
                    secret_two_f_a_salt, 
                    iteration_number_one, 
                    dklen=64 
                    )
                    small_key_one = hashlib.pbkdf2_hmac(
                    'sha256', 
                    key_one, 
                    secret_two_f_a_salt, 
                    iteration_number_two, 
                    dklen=32
                    )

                    file_in = open(current_twofa_filename, "rb")
                    nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

                    cipher = AES.new(small_key_one, AES.MODE_EAX, nonce)
                    decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)
                    base_for_otp = decrypted_key.decode('UTF-8')

                    deciphered_twofa = onetimepad.decrypt(base_for_otp, current_twofa)


                    device_name = socket.gethostname()
                    device_id = uuid.getnode()

                    device_identifier = str(device_id)+device_name

                    device_id_one = hashlib.pbkdf2_hmac(
                    'sha256', 
                    device_identifier.encode('utf-8'),  
                    secret_two_f_a_salt, 
                    10000, 
                    dklen=64 
                    )
                    device_id_hashed = hashlib.pbkdf2_hmac(
                    'sha256', 
                    device_id_one, 
                    secret_two_f_a_salt, 
                    5000, 
                    dklen=32
                    )


                except:
                    pass

                if device_name in devices_names_list and current_device_id == device_id_hashed and deciphered_twofa == 'yes':
                    timeout = current_device_trust

                    self.root.current = "one-time-pass"
                    self.root.manager.transition.direction = "up"

                elif device_name in devices_names_list and current_device_id == device_id_hashed and deciphered_twofa == 'no':
                    timeout = int(current_device_trust)

                    self.root.current = "mainview"
                    self.root.manager.transition.direction = "up"

                else:
                    self.new_machine()

            


        def activate(self):
                        global master_received
                        if self.root.ids.activate.ids.password.text == "" and len(logged_in_or_not) == 0:
                            self.root.ids.activate.ids.login_label.text = "Enter password"
                        elif len(logged_in_or_not) == 1:
                            self.root.ids.activate.ids.password.text = ""
                            
                        else:
                            master_received = self.root.ids.activate.ids.password.text
                            self.root.ids.activate.ids.password.text = ""
                            datetime_hashed = sha256(master_created_time.encode('ascii')).hexdigest()
                            datetime_bytes = bytes(datetime_hashed, 'utf-8')
                            num_date = re.findall("[1-9]+", master_created_time) 
                            joined_date = ''.join(num_date) 
                            added_first = int(joined_date[-5:]) 
                            added_second = int(joined_date[-10:-5]) 


                            key = hashlib.pbkdf2_hmac(
                            'sha256', 
                            master_received.encode('utf-8'), 
                            master_salt+datetime_bytes, 
                            iteration_number_one+added_first, 
                            dklen=128 
                            )
                            small_master = hashlib.pbkdf2_hmac(
                            'sha256', 
                            key, 
                            master_salt, 
                            iteration_number_two+added_second,
                            dklen=128 
                            )


                            stringed_master = str(small_master)
                            alphanum = re.findall('[a c-z A-Z 0-9]+', stringed_master)
                            master_key = ''.join(alphanum)


                            key_one = hashlib.pbkdf2_hmac(
                            'sha256', 
                            master_received.encode('utf-8'),
                            master_pepper, 
                            iteration_number_one, 
                            dklen=64 
                            )
                            small_key_one = hashlib.pbkdf2_hmac(
                            'sha256', 
                            key_one, 
                            master_pepper, 
                            iteration_number_two,
                            dklen=32
                            )

                            try:
                                file_in = open("/carrypass_keys/CarryPass_masterpass.bin", "rb")
                                nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

                                cipher = AES.new(small_key_one, AES.MODE_EAX, nonce)
                                decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)
                                random_text_for_masterpass_otp = decrypted_key.decode('UTF-8')


                                deciphered_masterpass = onetimepad.decrypt(random_text_for_masterpass_otp, master_pass_stored)


                                if master_key == deciphered_masterpass:
                                        logged_in_or_not.append(master_received)
                                        self.root.ids.activate.ids.password.text = ""
                                        self.root.ids.activate.ids.login_label.text = ""

                                        global wrong_password
                                        wrong_password = ['alma']

                                        self.one_time_password()
                                    
                            except:
                                if len(wrong_password) >= 3:
                                    MDApp.get_running_app().stop()
                                    Window.close()
  
                                else:
                                    trials = len(wrong_password)
                                    self.root.ids.activate.ids.login_label.text = f"Wrong password {trials}/3"
                                    wrong_password.append(master_received)




        def application_shutdown(self):
                MDApp.get_running_app().stop()
                Window.close()



        def application_window_minimize(self):
                Window.size = desiredSize
                Window.minimize()




        def show_application(self):
                Window.raise_window()
                Window.size = desiredSize




        def deactivate(self):
                global logged_in_or_not
                global stored_masterpass
                global wrong_password
                logged_in_or_not = []
                stored_masterpass = ''
                wrong_password = ['alma']
                self.root.ids.activate.ids.login_label.text = ""
                self.root.current = "login"
                self.root.transition.direction = "down"
                


        def add_drag_border(self):
                Window.size = desiredSize
                Window.borderless = False
                Window.size = desiredSize
                self.root.ids.edititem.ids.selectedpagebar.right_action_items = [["lock-reset", lambda x: self.deactivate(), "Deactivate", "Deactivate"], ["drag-horizontal", lambda x: self.remove_drag_border(), "Remove drag-border", "Remove drag-border"], ["close", lambda x: self.application_shutdown(), "Close", "Close"]]
                self.root.ids.mainview.ids.mypagesbar.right_action_items = [["lock-reset", lambda x: self.deactivate(), "Deactivate", "Deactivate"], ["drag-horizontal", lambda x: self.remove_drag_border(), "Remove drag-border", "Remove drag-border"], ["close", lambda x: self.application_shutdown(), "Close", "Close"]]
                self.root.ids.mainview.ids.privatenotesbar.right_action_items = [["lock-reset", lambda x: self.deactivate(), "Deactivate", "Deactivate"], ["drag-horizontal", lambda x: self.remove_drag_border(), "Remove drag-border", "Remove drag-border"], ["close", lambda x: self.application_shutdown(), "Close", "Close"]]
                self.root.ids.mainview.ids.trustbar.right_action_items = [["lock-reset", lambda x: self.deactivate(), "Deactivate", "Deactivate"], ["drag-horizontal", lambda x: self.remove_drag_border(), "Remove drag-border", "Remove drag-border"], ["close", lambda x: self.application_shutdown(), "Close", "Close"]]
                self.root.ids.futuresettings.ids.futuretopbar.right_action_items = [["lock-reset", lambda x: self.deactivate(), "Deactivate", "Deactivate"], ["drag-horizontal", lambda x: self.remove_drag_border(), "Remove drag-border", "Remove drag-border"], ["close", lambda x: self.application_shutdown(), "Close", "Close"]]
                self.root.ids.editpassword.ids.passwordbar.right_action_items = [["lock-reset", lambda x: self.deactivate(), "Deactivate", "Deactivate"], ["drag-horizontal", lambda x: self.remove_drag_border(), "Remove drag-border", "Remove drag-border"], ["close", lambda x: self.application_shutdown(), "Close", "Close"]]
                self.root.ids.devicesettings.ids.onedevicebar.right_action_items = [["lock-reset", lambda x: self.deactivate(), "Deactivate", "Deactivate"], ["drag-horizontal", lambda x: self.remove_drag_border(), "Remove drag-border", "Remove drag-border"], ["close", lambda x: self.application_shutdown(), "Close", "Close"]]
                self.root.ids.webbrowser.ids.browserbar.right_action_items = [["lock-reset", lambda x: self.deactivate(), "Deactivate", "Deactivate"], ["drag-horizontal", lambda x: self.remove_drag_border(), "Remove drag-border", "Remove drag-border"], ["close", lambda x: self.application_shutdown(), "Close", "Close"]]
                self.root.ids.application.ids.applicationbar.right_action_items = [["lock-reset", lambda x: self.deactivate(), "Deactivate", "Deactivate"], ["drag-horizontal", lambda x: self.remove_drag_border(), "Remove drag-border", "Remove drag-border"], ["close", lambda x: self.application_shutdown(), "Close", "Close"]]


        def remove_drag_border(self):
                Window.size = desiredSize
                Window.borderless = True
                Window.size = desiredSize
                self.root.ids.edititem.ids.selectedpagebar.right_action_items = [["lock-reset", lambda x: self.deactivate(), "Deactivate", "Deactivate"], ["drag-vertical", lambda x: self.add_drag_border(), "Add drag-border", "Add drag-border"], ["close", lambda x: self.application_shutdown(), "Close", "Close"]]
                self.root.ids.mainview.ids.mypagesbar.right_action_items = [["lock-reset", lambda x: self.deactivate(), "Deactivate", "Deactivate"], ["drag-vertical", lambda x: self.add_drag_border(), "Add drag-border", "Add drag-border"], ["close", lambda x: self.application_shutdown(), "Close", "Close"]]
                self.root.ids.mainview.ids.privatenotesbar.right_action_items = [["lock-reset", lambda x: self.deactivate(), "Deactivate", "Deactivate"], ["drag-vertical", lambda x: self.add_drag_border(), "Add drag-border", "Add drag-border"], ["close", lambda x: self.application_shutdown(), "Close", "Close"]]
                self.root.ids.mainview.ids.trustbar.right_action_items = [["lock-reset", lambda x: self.deactivate(), "Deactivate", "Deactivate"], ["drag-vertical", lambda x: self.add_drag_border(), "Add drag-border", "Add drag-border"], ["close", lambda x: self.application_shutdown(), "Close", "Close"]]
                self.root.ids.futuresettings.ids.futuretopbar.right_action_items = [["lock-reset", lambda x: self.deactivate(), "Deactivate", "Deactivate"], ["drag-vertical", lambda x: self.add_drag_border(), "Add drag-border", "Add drag-border"], ["close", lambda x: self.application_shutdown(), "Close", "Close"]]
                self.root.ids.editpassword.ids.passwordbar.right_action_items = [["lock-reset", lambda x: self.deactivate(), "Deactivate", "Deactivate"], ["drag-vertical", lambda x: self.add_drag_border(), "Add drag-border", "Add drag-border"], ["close", lambda x: self.application_shutdown(), "Close", "Close"]]
                self.root.ids.devicesettings.ids.onedevicebar.right_action_items = [["lock-reset", lambda x: self.deactivate(), "Deactivate", "Deactivate"], ["drag-vertical", lambda x: self.add_drag_border(), "Add drag-border", "Add drag-border"], ["close", lambda x: self.application_shutdown(), "Close", "Close"]]
                self.root.ids.webbrowser.ids.browserbar.right_action_items = [["lock-reset", lambda x: self.deactivate(), "Deactivate", "Deactivate"], ["drag-vertical", lambda x: self.add_drag_border(), "Add drag-border", "Add drag-border"], ["close", lambda x: self.application_shutdown(), "Close", "Close"]]
                self.root.ids.application.ids.applicationbar.right_action_items = [["lock-reset", lambda x: self.deactivate(), "Deactivate", "Deactivate"], ["drag-vertical", lambda x: self.add_drag_border(), "Add drag-border", "Add drag-border"], ["close", lambda x: self.application_shutdown(), "Close", "Close"]]



        def deactivate_with_timeout(self):
                global logged_in_or_not
                global stored_masterpass
                global wrong_password
                logged_in_or_not = []
                stored_masterpass = ''
                wrong_password = ['alma']
                self.root.ids.activate.ids.login_label.text = "Application timed out"
                self.root.current = "login"
                self.root.transition.direction = "down"      



        def list_login_pages(self, text="", search=False):
            
            conn = sqlite3.connect('/carrypass_database/master.db')

            site_data = create_pandas_table("SELECT nickname, url FROM logindata ORDER BY oid", conn)
            
            list_nick = site_data['nickname'].values.tolist()
            list_url = site_data['url'].values.tolist()

            conn.close()


            def add_each_loginpage(nick, url):
                self.root.ids.mainview.ids.rv_url.data.append(
                    {
                        "viewclass": "TwoLineListItem",
                        "text": nick,
                        "secondary_text": url,
                        "theme_text_color": 'Custom',
                        "text_color": get_color_from_hex("#21004b"),
                        "on_press": lambda x=nick, y=url: self.edit_item(x, y),
                    }
                )

            self.root.ids.mainview.ids.rv_url.data = []
            num=0
            for nick in list_nick:
                if search:
                    if text in nick:
                        add_each_loginpage(nick, list_url[num])
                else:
                    add_each_loginpage(nick, list_url[num])
                num+=1

    


        def list_all_devices(self, text="", search=False):
            
            conn = sqlite3.connect('/carrypass_database/master.db')


            site_data = create_pandas_table("SELECT device_id, device_nickname, device_name, salt, timeoftrust, twofa, twofa_filename  FROM devices ORDER BY oid", conn)
            
            list_device_id = site_data['device_id'].values.tolist()
            list_nick = site_data['device_nickname'].values.tolist()
            list_name = site_data['device_name'].values.tolist()
            list_timeoftrust = site_data['timeoftrust'].values.tolist()

            conn.close()


            def add_each_device(nick, name, dev_id, timetrust):
                self.root.ids.mainview.ids.rv_dev.data.append(
                    {
                        "viewclass": "TwoLineListItem",
                        "text": nick,
                        "secondary_text": name,
                        "theme_text_color": 'Custom',
                        "text_color": get_color_from_hex("#21004b"),
                        "on_press": lambda nick=nick, name=name, dev_id=dev_id, timetrust=timetrust: self.edit_device(nick, name, dev_id, timetrust),
                    }
                )

            self.root.ids.mainview.ids.rv_dev.data = []
            num=0
            for nick in list_nick:
                if search:
                    if text in nick:
                        add_each_device(nick, list_name[num], list_device_id[num], list_timeoftrust[num])
                else:
                    add_each_device(nick, list_name[num], list_device_id[num], list_timeoftrust[num])
                num+=1




        def list_current_device_only(self, text=selected_device_id, search=True):
            global timeout_start
            self.timeout_app()
            timeout_start = time.time()
            
            conn = sqlite3.connect('/carrypass_database/master.db')

            site_data = create_pandas_table("SELECT device_id, device_nickname, device_name, salt, timeoftrust, twofa, twofa_filename  FROM devices ORDER BY oid", conn)
            
            list_device_id = site_data['device_id'].values.tolist()
            list_nick = site_data['device_nickname'].values.tolist()
            list_name = site_data['device_name'].values.tolist()
            list_timeoftrust = site_data['timeoftrust'].values.tolist()

            conn.close()


            def add_each_device(nick, name, dev_id, timetrust):
                self.root.ids.mainview.ids.rv_dev.data.append(
                    {
                        "viewclass": "TwoLineListItem",
                        "text": nick,
                        "secondary_text": name,
                        "theme_text_color": 'Custom',
                        "text_color": get_color_from_hex("#21004b"),
                        "on_press": lambda nick=nick, name=name, dev_id=dev_id, timetrust=timetrust: self.edit_device(nick, name, dev_id, timetrust),
                    }
                )

            self.root.ids.mainview.ids.rv_dev.data = []

            device_name = socket.gethostname()
            device_index = list_name.index(device_name)

            add_each_device(list_nick[device_index], list_name[device_index], list_device_id[device_index], list_timeoftrust[device_index])



        def populate_masterpass(self):
                    salt = os.urandom(128)
                    date_time = datetime.today()
                    datetime_created = date_time.strftime("%Y-%m-%d %H:%M:%S.%f")
                    num_date = re.findall("[1-9]+", datetime_created) 
                    joined_date = ''.join(num_date) 
                    added_first = int(joined_date[-5:]) 
                    added_second = int(joined_date[-10:-5]) 
                    datetime_hashed = sha256(datetime_created.encode('ascii')).hexdigest()
                    datetime_bytes = bytes(datetime_hashed, 'utf-8')
                    new_master = self.root.ids.starterwindow.ids.startpassword.text
                    logged_in_or_not.append(new_master)

                    key = hashlib.pbkdf2_hmac(
                    'sha256',
                    new_master.encode('utf-8'), 
                    salt+datetime_bytes, 
                    iteration_number_one+added_first,
                    dklen=128 
                    )
                    small_master = hashlib.pbkdf2_hmac(
                    'sha256', 
                    key, 
                    salt, 
                    iteration_number_two+added_second, 
                    dklen=128 
                    )
                    stringed_master = str(small_master)
                    alphanum = re.findall('[a c-z A-Z 0-9]+', stringed_master)
                    master_key = ''.join(alphanum)


                    random_secret = get_random_password_string(512) 
                                
                    otp_masterpass = onetimepad.encrypt(master_key, random_secret)  

                    random_otp_pad_stored = bytes(otp_masterpass, 'utf-8') 

                    pepper = os.urandom(64)

                    key_one = hashlib.pbkdf2_hmac(
                    'sha256', 
                    new_master.encode('utf-8'), 
                    pepper, 
                    iteration_number_one, 
                    dklen=64 
                    )
                    small_key_one = hashlib.pbkdf2_hmac(
                    'sha256', 
                    key_one, 
                    pepper, 
                    iteration_number_two, 
                    dklen=32
                    )


                    masterpass_filename = 'CarryPass_masterpass'
                    masterpass_file_extension = '.bin'
                    filename_for_masterpass = masterpass_filename+masterpass_file_extension
                    folder_for_masterpass = '/carrypass_keys/'
                    masterpass_file_path = folder_for_masterpass+filename_for_masterpass
                    

                    cipher = AES.new(small_key_one, AES.MODE_EAX)
                    ciphertext, tag = cipher.encrypt_and_digest(random_otp_pad_stored)

                    file_out = open(masterpass_file_path, "wb")
                    [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
                    file_out.close()


                    twofa_yes_no_for_newdevice = 'no'

                    random_secret_for_yesno = get_random_password_string(64)

                    otp_twofa_yes_no_for_newdevice = onetimepad.encrypt(twofa_yes_no_for_newdevice, random_secret_for_yesno)  

                    random_otp_for_time_stored = bytes(otp_twofa_yes_no_for_newdevice, 'utf-8')

                    newdevice_yes_no_filename = 'newdevice_yesno'
                    yes_no_file_extension = '.bin'
                    filename_for_yes_no = newdevice_yes_no_filename+yes_no_file_extension
                    folder_for_yes_no = '/carrypass_keys/'
                    yes_no_file_path = folder_for_yes_no+filename_for_yes_no
                    

                    cipher = AES.new(small_key_one, AES.MODE_EAX)
                    ciphertext, tag = cipher.encrypt_and_digest(random_otp_for_time_stored)

                    file_out = open(yes_no_file_path, "wb")
                    [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
                    file_out.close()


                    base_for_qr_otp = pyotp.random_base32()

                    random_secret_for_qr_base = get_random_password_string(512)

                    otp_base_for_qr = onetimepad.encrypt(base_for_qr_otp, random_secret_for_qr_base)

                    random_otp_for_qr_stored = bytes(otp_base_for_qr, 'utf-8')

                    qr_base_filename = 'qr_base'
                    qr_base_file_extension = '.bin'
                    filename_for_qr_base = qr_base_filename+qr_base_file_extension
                    folder_for_qr_base = '/carrypass_keys/'
                    qr_base_file_path = folder_for_qr_base+filename_for_qr_base
                    

                    cipher = AES.new(small_key_one, AES.MODE_EAX)
                    ciphertext, tag = cipher.encrypt_and_digest(random_otp_for_qr_stored)

                    file_out = open(qr_base_file_path, "wb")
                    [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
                    file_out.close()


                    time_of_trust = '28800'

                    random_secret_for_time = get_random_password_string(512)

                    otp_for_time_trust = onetimepad.encrypt(time_of_trust, random_secret_for_time) 

                    random_otp_for_time_stored = bytes(otp_for_time_trust, 'utf-8')

                    qr_base_filename = 'time_of_trust'
                    qr_base_file_extension = '.bin'
                    filename_for_qr_base = qr_base_filename+qr_base_file_extension
                    folder_for_qr_base = '/carrypass_keys/'
                    qr_base_file_path = folder_for_qr_base+filename_for_qr_base
                    

                    cipher = AES.new(small_key_one, AES.MODE_EAX)
                    ciphertext, tag = cipher.encrypt_and_digest(random_otp_for_time_stored)

                    file_out = open(qr_base_file_path, "wb")
                    [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
                    file_out.close()

                    conn = sqlite3.connect('/carrypass_database/master.db')

                    c = conn.cursor()
                    c.execute("INSERT INTO masterpassword VALUES (:masterpass, :salt, :pepper, :created_time)",
                    {
                        'masterpass': random_secret,
                        'salt': salt,
                        'pepper': pepper,
                        'created_time': datetime_created,
                    })


                    c.execute("INSERT INTO twofa_newdevice VALUES (:two_f_a, :two_f_a_salt, :qr_base, :time_of_trust)",
                    {
                        'two_f_a': random_secret_for_yesno,
                        'two_f_a_salt': pepper,
                        'qr_base': random_secret_for_qr_base,
                        'time_of_trust': random_secret_for_time,
                    })

                    device_name = socket.gethostname()
                    device_id = uuid.getnode()

                    device_identifier = str(device_id)+device_name

                    device_id_one = hashlib.pbkdf2_hmac(
                    'sha256', 
                    device_identifier.encode('utf-8'), 
                    pepper, 
                    10000, 
                    dklen=64 
                    )
                    device_id_hashed = hashlib.pbkdf2_hmac(
                    'sha256', 
                    device_id_one, 
                    pepper, 
                    5000, 
                    dklen=32
                    )

                    twofa_yes_no = 'no'

                    random_secret_for_yesno = get_random_password_string(64)

                    otp_for_twofa_yes_no = onetimepad.encrypt(twofa_yes_no, random_secret_for_yesno)

                    random_otp_for_time_stored = bytes(otp_for_twofa_yes_no, 'utf-8')

                    stringed_device = str(device_name)
                    alphanum = re.findall('[a-z A-Z 0-9]+', stringed_device)
                    device_name_stripped = ''.join(alphanum)

                    yes_no_file_extension = '.bin'
                    filename_for_yes_no = device_name_stripped+yes_no_file_extension
                    folder_for_yes_no = '/carrypass_keys/'
                    yes_no_file_path = folder_for_yes_no+filename_for_yes_no
                    

                    cipher = AES.new(small_key_one, AES.MODE_EAX)
                    ciphertext, tag = cipher.encrypt_and_digest(random_otp_for_time_stored)

                    file_out = open(yes_no_file_path, "wb")
                    [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
                    file_out.close()

                    c.execute("INSERT INTO devices VALUES (:device_id, :device_nickname, :device_name, :salt, :timeoftrust, :twofa, :twofa_filename)",
                    {
                        'device_id': device_id_hashed,
                        'device_nickname': 'device tag',
                        'device_name': device_name,
                        'salt': pepper,
                        'timeoftrust': 28800,
                        'twofa': random_secret_for_yesno,
                        'twofa_filename': yes_no_file_path,
                    })
                    
            
                    conn.commit()

                    conn.close()
                    self.create_note_one_at_start()
                    self.create_note_two_at_start()
                    self.show_application_startup_dialog()





        def new_user_setup(self):
            self.root.current = "starterwindow"
            self.root.transition.direction = "down"


############### AT APPLICATION STARTUP ########################

        def on_start(self):
            Window.size = desiredSize
            self.list_login_pages()
            self.list_all_devices()
            self.query_login_data()
            self.add_drag_border()
            self.remove_drag_border()

            if len(masterpass_list) < 1:
                self.new_user_setup()


            self.query_notes_database()

            if os.path.exists("/carrypass_images/qr_twofa.png"):
                self.root.ids.mainview.ids.qr_image.source = "/carrypass_images/qr_twofa.png"
            else:
                self.root.ids.mainview.ids.qr_image.source = 'carrypass_blue.png'

            


        def on_selectpage_checkbox_active(self, checkbox, value):
            if value:
                self.save_selected_page()
            else:
                self.save_selected_page()



        def on_selectdevice_checkbox_active(self, checkbox, value):
            if value:
                self.save_onedevice_settings()
            else:
                self.save_onedevice_settings()



        def on_futuredevice_checkbox_active(self, checkbox, value):
            if value:
                self.save_newdevice_settings()
            else:
                self.save_newdevice_settings()


        def on_webbrowser_change_checkbox_active(self, checkbox, value):
            if value:
                self.change_default_browser()
            else:
                pass




        def future_settings(self):

            self.open_newdevice_settings()



        def back_to_device_settings(self):
            global timeout
            global timeout_start
            self.timeout_app()
            timeout_start = time.time()
            if len(logged_in_or_not)>0:
                self.root.current = "mainview"
                self.root.transition.direction = "right"
            else:
                self.deactivate_with_timeout()


        def back_to_main_view(self):
            global timeout
            global timeout_start
            self.timeout_app()
            timeout_start = time.time()
            if len(logged_in_or_not)>0:
                self.list_login_pages()
                self.list_all_devices()
                self.root.ids.mainview.ids.search_field.text = ""
                self.root.current = "mainview"
                self.root.transition.direction = "right"
            else:
                self.deactivate_with_timeout()


        def back_to_edit_view(self):
            global timeout
            global timeout_start
            self.timeout_app()
            timeout_start = time.time()
            self.root.current = "itemedit"
            self.root.transition.direction = "right"




        def addnewcallback(self, instance):
            global timeout
            global timeout_start
            self.timeout_app()
            timeout_start = time.time()
            self.root.ids.mainview.ids.addnewfloat.close_stack()
            if instance.icon == "web-plus":
                if len(logged_in_or_not)>0:
                    self.add_new_record()
                else:
                    self.deactivate_with_timeout()                
            elif instance.icon == "card-plus-outline":
                if len(logged_in_or_not)>0:
                    self.root.current = "application"
                    self.root.transition.direction = "left"
                else:
                    self.deactivate_with_timeout()  
            elif instance.icon == "chess-pawn":
                if len(logged_in_or_not)>0:
                    self.have_i_been_pawned()
                else:
                    self.deactivate_with_timeout()  
            else:
                pass



        def editcallback(self, instance):
            global timeout
            global timeout_start
            self.timeout_app()
            timeout_start = time.time()
            self.root.ids.edititem.ids.edititemfloat.close_stack()
            if instance.icon == "key-change":
                if len(logged_in_or_not)>0:
                    self.password_page_data()
                    self.root.current = "editpassword"
                    self.root.transition.direction = "left"
                else:
                    self.deactivate_with_timeout()
            elif instance.icon == "web":
                if len(logged_in_or_not)>0:
                    self.show_webbrowsers_for_page()
                    self.root.current = "webbrowser"
                    self.root.transition.direction = "left"
                else:
                    self.deactivate_with_timeout()
            elif instance.icon == "autorenew":
                if len(logged_in_or_not)>0:
                    self.confirm_login_before_password_change()
                else:
                    self.deactivate_with_timeout()
            elif instance.icon == "table-key":
                if len(logged_in_or_not)>0:
                    self.display_password()
                else:
                    self.deactivate_with_timeout()
            else:
                self.deactivate_with_timeout()
                

        def notescallback(self, instance):
            self.root.ids.mainview.ids.notesfloat.close_stack()
            global timeout
            global timeout_start
            self.timeout_app()
            timeout_start = time.time()
            global secret_note
            if instance.icon == "content-save-all-outline" and secret_note == "one":
                self.store_secret_text_one()               
                self.root.ids.mainview.ids.privatenotes.inactive = True
            elif instance.icon == "content-save-all-outline" and secret_note == "two":
                self.store_secret_text_two()               
                self.root.ids.mainview.ids.privatenotes.inactive = True

            elif instance.icon == "delete-forever-outline" and secret_note == "one":
                if len(logged_in_or_not)>0:
                    self.show_delete_note_one_dialog()
                else:
                    self.deactivate_with_timeout()
                             
            elif instance.icon == "delete-forever-outline" and secret_note == "two":
                if len(logged_in_or_not)>0:
                    self.show_delete_note_two_dialog()
                else:
                    self.deactivate_with_timeout()
                
            elif instance.icon == "delete-forever-outline" and secret_note == "":
                self.toast_open_a_note()
            elif instance.icon == "content-save-all-outline" and secret_note == "":
                self.toast_open_a_note()
                        



        def devicescallback(self, instance):
            global timeout
            global timeout_start
            self.timeout_app()
            timeout_start = time.time()
            global secret_note
            if instance.icon == "qrcode-scan":
                self.root.ids.mainview.ids.devicesfloat.close_stack()
                self.create_qr_image()
            elif instance.icon == "delete-variant":
                self.root.ids.mainview.ids.devicesfloat.close_stack()
                self.delete_qr_image()



        def edit_item(self, page_nickname, url):
            global timeout
            global timeout_start
            self.timeout_app()
            timeout_start = time.time()
            try:
                global url_for_id
                url_for_id = url
                self.root.current = "itemedit"
                self.root.transition.direction = "left"

                self.root.ids.edititem.ids.nickname.text = page_nickname

                if "application" in page_nickname:
                    self.root.ids.edititem.ids.username_check.on_press = lambda: self.get_application_username_img()
                    self.root.ids.edititem.ids.password_check.on_press = lambda: self.get_application_password_img()
                    self.root.ids.edititem.ids.nickname.readonly = True
                    self.root.ids.edititem.ids.nickname.icon_right = "bookmark-check-outline"
                else:
                    self.root.ids.edititem.ids.username_check.on_press = lambda: self.get_username_img()
                    self.root.ids.edititem.ids.password_check.on_press = lambda: self.get_password_img()
                    self.root.ids.edititem.ids.nickname.readonly = False
                    self.root.ids.edititem.ids.nickname.icon_right = "rename-box"

                conn = sqlite3.connect("/carrypass_database/master.db")
                site_data = create_pandas_table("SELECT url, username, pepper, two_page, username_img, password_img, ciphertext_two FROM logindata ORDER BY oid", conn)

                list_url = site_data['url'].values.tolist()
                list_username = site_data['username'].values.tolist()
                list_pepper = site_data['pepper'].values.tolist()
                list_ciphertext_two = site_data['ciphertext_two'].values.tolist()
                list_two_page_login = site_data['two_page'].values.tolist()
                list_username_img = site_data["username_img"].values.tolist()
                list_password_img = site_data["password_img"].values.tolist()
                
                url_index = list_url.index(url)
                site_username = list_username[url_index]
                site_pepper = list_pepper[url_index]
                site_ciphertext_two = list_ciphertext_two[url_index]
                site_two_page_login = list_two_page_login[url_index]
                username_img_stored = list_username_img[url_index]
                password_img_stored = list_password_img[url_index]

                conn.close()

                key_one = hashlib.pbkdf2_hmac(
                'sha256', 
                logged_in_or_not[0].encode('utf-8'), 
                site_pepper, 
                iteration_number_one, 
                dklen=64 
                )
                small_key_one = hashlib.pbkdf2_hmac(
                'sha256', 
                key_one, 
                site_pepper, 
                iteration_number_two, 
                dklen=32
                )


                file_in = open(site_ciphertext_two, "rb")
                nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

                cipher = AES.new(small_key_one, AES.MODE_EAX, nonce)
                decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)
                random_text_for_username_otp = decrypted_key.decode('UTF-8')


                deciphered_username = onetimepad.decrypt(random_text_for_username_otp, site_username)

                self.root.ids.edititem.ids.username.text = deciphered_username

                if site_two_page_login == "yes":
                    self.root.ids.edititem.ids.twopage_switch.active = True
                elif site_two_page_login == "no":
                    self.root.ids.edititem.ids.twopage_switch.active = False

                if len(username_img_stored) > 0:
                    self.root.ids.edititem.ids.username_check.md_bg_color = get_color_from_hex("#aeaeae") 
                else:
                    self.root.ids.edititem.ids.username_check.md_bg_color = get_color_from_hex("#FAFAFA")

                if len(password_img_stored) > 0:
                    self.root.ids.edititem.ids.password_check.md_bg_color = get_color_from_hex("#aeaeae")
                else:
                    self.root.ids.edititem.ids.password_check.md_bg_color = get_color_from_hex("#FAFAFA")

                self.root.ids.webbrowser.ids.firefox.disabled = False
                self.root.ids.webbrowser.ids.firefox_private.disabled = False
                self.root.ids.webbrowser.ids.default_browser.disabled = False
                self.root.ids.webbrowser.ids.applogin.disabled = False
                
                self.password_page_data()
            except:
                self.deactivate_with_timeout()




        def edit_device(self, nick, name, dev_id, timetrust):
            global selected_device_id
            self.root.ids.devicesettings.ids.devicetag.text = nick
            self.root.ids.devicesettings.ids.devicename.text = name
            self.root.ids.devicesettings.ids.trustthisdevice.text = str(timetrust)

            selected_device_id = dev_id

            conn = sqlite3.connect("/carrypass_database/master.db")
            c = conn.cursor()

            twofa_filename_db = create_pandas_table("SELECT device_id, device_name, twofa, twofa_filename FROM devices ORDER BY oid", conn)

            devices_twofa_filename_list = []
            for twofa_filename in twofa_filename_db['twofa_filename']:
                devices_twofa_filename_list.append(twofa_filename)


            devices_id_list = []
            for device_id in twofa_filename_db['device_id']:
                devices_id_list.append(device_id)

            twofa_text_list = []
            for twofa in twofa_filename_db['twofa']:
                twofa_text_list.append(twofa)


            device_index = devices_id_list.index(selected_device_id)

            current_twofa = twofa_text_list[device_index]
            
            current_twofa_filename = devices_twofa_filename_list[device_index]

            c.close()
            conn.close()

            conn = sqlite3.connect("/carrypass_database/master.db")
            newdevice_data = create_pandas_table("SELECT two_f_a, two_f_a_salt, time_of_trust FROM twofa_newdevice ORDER BY oid", conn)

            list_two_f_a_salt = newdevice_data['two_f_a_salt'].values.tolist()

            secret_two_f_a_salt = list_two_f_a_salt[0]


            conn.close()

            if len(logged_in_or_not) < 1:
                self.deactivate_with_timeout()
            else:

                key_one = hashlib.pbkdf2_hmac(
                'sha256', 
                logged_in_or_not[0].encode('utf-8'), 
                secret_two_f_a_salt, 
                iteration_number_one, 
                dklen=64 
                )
                small_key_one = hashlib.pbkdf2_hmac(
                'sha256', 
                key_one, 
                secret_two_f_a_salt, 
                iteration_number_two,
                dklen=32
                )
                    

                file_in = open(current_twofa_filename, "rb")
                nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

                cipher = AES.new(small_key_one, AES.MODE_EAX, nonce)
                decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)
                base_for_otp = decrypted_key.decode('UTF-8')

                deciphered_twofa = onetimepad.decrypt(base_for_otp, current_twofa)

                if deciphered_twofa == "yes":
                    self.root.ids.devicesettings.ids.twofa_switch.active = True
                else:
                    self.root.ids.devicesettings.ids.twofa_switch.active = False


                self.root.current = "devicesettings"
                self.root.transition.direction = "left"

                global timeout_start
                self.timeout_app()
                timeout_start = time.time()






        def check_security_before_launching_robot(self):
            global timeout_start
            global insecure_login
            self.timeout_app()
            timeout_start = time.time()

            global web_address
            if len(logged_in_or_not)>0:
                try:
                    pyperclip.copy('')
                    pyautogui.keyDown('alt')
                    pyautogui.press('tab')
                    pyautogui.keyUp('alt')
                    
                    pyautogui.hotkey('ctrl', 'l')
                    pyautogui.hotkey('ctrl', 'c')
                    pyautogui.hotkey('esc')
                    # global login_message
                    web_address = pyperclip.paste()

                    pyperclip.copy('')
                    is_secure_site = re.match("https:", web_address)
                    insecure_site = re.match("http:", web_address)
                    if is_secure_site:

                        self.launch_robot()
                    elif insecure_site:
                        insecure_login = True
                        self.show_application()
                        self.show_isecure_site_dialog()
                        
                    else:
                        insecure_login = True
                        self.show_application()
                        self.show_unclear_site_dialog()
                        
                except:
                    self.show_application()
                    self.show_unclear_site_dialog()
            else:
                self.deactivate_with_timeout()




        def launch_robot(self):
            global timeout_start
            global insecure_login
            self.timeout_app()
            timeout_start = time.time()
            conn = sqlite3.connect("/carrypass_database/master.db")
            logindata_stored = create_pandas_table("SELECT url FROM logindata ORDER BY oid", conn)
            url_list_stored = logindata_stored["url"].values.tolist()
            global web_address
            pyperclip.copy('')
            if insecure_login:
                pyautogui.keyDown('alt')
                pyautogui.press('tab')
                pyautogui.keyUp('alt')
                insecure_login = False
            try:
                pyautogui.hotkey('ctrl', 'l')
                pyautogui.hotkey('ctrl', 'c')
                pyautogui.hotkey('esc')
                web_address = pyperclip.paste()
                is_web_address = re.match("http", web_address)
                pyperclip.copy('')
                if web_address in url_list_stored:
                        pyautogui.hotkey('win', 'up')
                        pyautogui.hotkey('win', 'up')
                        pyautogui.hotkey('ctrl', '0')
                        global username_img_stored
                        global username_stored
                        global password_img_stored
                        global login_key
                        global usn_x_rate
                        global usn_y_rate
                        global pwd_x_rate
                        global pwd_y_rate
                        global deciphered_username
                        
                        conn = sqlite3.connect("/carrypass_database/master.db")
                        site_data = create_pandas_table("SELECT url, username, salt, pepper, special, two_page, created_time, username_img, password_img, ciphertext, usn_x_ratio, usn_y_ratio, pwd_x_ratio, pwd_y_ratio, ciphertext_two FROM logindata ORDER BY oid", conn)
                        list_url = site_data['url'].values.tolist()
                        list_salt = site_data['salt'].values.tolist()
                        list_pepper = site_data['pepper'].values.tolist()
                        list_two_page = site_data['two_page'].values.tolist()
                        list_created_time = site_data['created_time'].values.tolist()
                        list_username = site_data["username"].values.tolist()
                        list_username_img = site_data["username_img"].values.tolist()
                        list_password_img = site_data["password_img"].values.tolist()
                        list_ciphertext = site_data["ciphertext"].values.tolist()
                        list_ciphertext_two = site_data['ciphertext_two'].values.tolist()

                        list_usn_x = site_data["usn_x_ratio"].values.tolist()
                        list_usn_y = site_data["usn_y_ratio"].values.tolist()
                        list_pwd_x = site_data["pwd_x_ratio"].values.tolist()
                        list_pwd_y = site_data["pwd_y_ratio"].values.tolist()

                        url_index = list_url.index(web_address)
                        site_salt = list_salt[url_index]
                        site_two_page = list_two_page[url_index]
                        site_created_time = list_created_time[url_index]
                        site_ciphertext = list_ciphertext[url_index]

                        username_stored = list_username[url_index]
                        username_img_stored = list_username_img[url_index]
                        password_img_stored = list_password_img[url_index]

                        site_pepper = list_pepper[url_index]
                        site_ciphertext_two = list_ciphertext_two[url_index]

                        usn_x_rate = list_usn_x[url_index]
                        usn_y_rate = list_usn_y[url_index]
                        pwd_x_rate = list_pwd_x[url_index]
                        pwd_y_rate = list_pwd_y[url_index]

                        conn.close()
                        num_date = re.findall("[1-9]+", site_created_time) 
                        joined_date = ''.join(num_date) 
                        added_first = int(joined_date[-5:]) 
                        added_second = int(joined_date[-10:-5]) 
                        datetime_hashed = sha256(site_created_time.encode('ascii')).hexdigest()
                        datetime_bytes = bytes(datetime_hashed, 'utf-8')

                        key = hashlib.pbkdf2_hmac(
                        'sha256', 
                        logged_in_or_not[0].encode('utf-8'), 
                        site_salt+datetime_bytes, 
                        iteration_number_one+added_first, 
                        dklen=64 
                        )
                        small_key = hashlib.pbkdf2_hmac(
                        'sha256', 
                        key, 
                        site_salt, 
                        iteration_number_two+added_second, 
                        dklen=32
                        )
                        file_in = open(site_ciphertext, "rb")
                        nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

                        cipher = AES.new(small_key, AES.MODE_EAX, nonce)
                        decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)
                        login_key = decrypted_key.decode('UTF-8')

                        key_one = hashlib.pbkdf2_hmac(
                        'sha256', 
                        logged_in_or_not[0].encode('utf-8'), 
                        site_pepper, 
                        iteration_number_one, 
                        dklen=64 
                        )
                        small_key_one = hashlib.pbkdf2_hmac(
                        'sha256', 
                        key_one, 
                        site_pepper, 
                        iteration_number_two,
                        dklen=32
                        )


                        file_in = open(site_ciphertext_two, "rb")
                        nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

                        cipher = AES.new(small_key_one, AES.MODE_EAX, nonce)
                        decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)
                        random_text_for_username_otp = decrypted_key.decode('UTF-8')


                        deciphered_username = onetimepad.decrypt(random_text_for_username_otp, username_stored)


                        if site_two_page == 'yes':
                            self.two_page_login()
                        else:		
                            try:
                                screen_width = tk_root.winfo_screenwidth()
                                screen_height = tk_root.winfo_screenheight()

                                usernamelocation = pyautogui.locateCenterOnScreen(f"/carrypass_images/{username_img_stored}", confidence=0.9) # f"/carrypass_images/{username_img_stored}"
                            

                                pyautogui.moveTo(usernamelocation[0], usernamelocation[1]) 
                                
                                pyautogui.click(usernamelocation)
                            
                                pyautogui.doubleClick()
                                pyautogui.press('delete')
                                pyautogui.press('esc')
                                pyperclip.copy(deciphered_username)
                                pyautogui.hotkey("ctrl", "v")
                            
                                time.sleep(0.2)
                                pyautogui.press('esc')
                                pyperclip.copy("")
                                pyautogui.moveTo(1,1)
                                time.sleep(0.2)
                            except:
                                # pass
                                try:
                                    pyautogui.click(screen_width/usn_x_rate, screen_height/usn_y_rate)
                                    pyautogui.doubleClick()
                                    pyautogui.press('delete')
                                    pyautogui.press('esc')
                                    pyperclip.copy(deciphered_username)
                                    pyautogui.hotkey("ctrl", "v")
                                
                                    time.sleep(0.2)
                                    pyautogui.press('esc')
                                    pyperclip.copy("")
                                    pyautogui.moveTo(1,1)
                                    time.sleep(0.2)
                                except:
                                    pass
                            try:
                                passwordlocation = pyautogui.locateCenterOnScreen(f"/carrypass_images/{password_img_stored}", confidence=0.9)

                                pyautogui.moveTo(passwordlocation[0], passwordlocation[1])

                                pyautogui.click(passwordlocation)

                                pyperclip.copy(login_key)
                            
                                pyautogui.doubleClick()
                                pyautogui.press('delete')
                                pyautogui.press('esc')
                                pyautogui.hotkey("ctrl", "v")
                            
                                pyautogui.press('enter')
                                pyperclip.copy("")
                            except:
                                # pass
                                try:
                                    pyautogui.click(screen_width/pwd_x_rate, screen_height/pwd_y_rate)
                                    pyperclip.copy(login_key)
                                
                                    pyautogui.doubleClick()
                                    pyautogui.press('delete')
                                    pyautogui.press('esc')
                                    pyautogui.hotkey("ctrl", "v")
                                
                                    pyautogui.press('enter')

                                    self.show_application()
                                    self.toast_finished_login()
                                    

                                    pyperclip.copy("")
                                except:
                                    self.show_application()
                                    self.show_no_image_dialog()


                elif is_web_address:
                        pyautogui.hotkey('win', 'up')
                        pyautogui.hotkey('win', 'up')
                        pyautogui.hotkey('ctrl', '0')
                        global nickname
                        split_web_address = urlsplit(web_address)
                        nickname_from_split = split_web_address.hostname
                        nickname = nickname_from_split.replace('www.', '')

                        stored_list_of_urls = []
                        
                        for url in url_list_stored:
                            split_urls = urlsplit(url)
                            shorturl_from_split = split_urls.hostname
                            short_urls = shorturl_from_split.replace('www.', '')
                            stored_list_of_urls.append(short_urls)
                        
                        if nickname in stored_list_of_urls:
                            self.login_to_nickname()


                        else:
                            pass
                else:
                    pass

            except:
                self.show_application()
                self.show_no_image_dialog()
                



        def login_to_nickname(self):
                global usn_x_rate
                global usn_y_rate
                global pwd_x_rate
                global pwd_y_rate
                global deciphered_username

                conn = sqlite3.connect("/carrypass_database/master.db")
                site_data = create_pandas_table("SELECT url, username, salt, pepper, special, two_page, created_time, username_img, password_img, ciphertext, usn_x_ratio, usn_y_ratio, pwd_x_ratio, pwd_y_ratio, ciphertext_two FROM logindata ORDER BY oid", conn)
                list_url = site_data['url'].values.tolist()
                list_salt = site_data['salt'].values.tolist()
                list_two_page = site_data['two_page'].values.tolist()
                list_created_time = site_data['created_time'].values.tolist()
                list_username = site_data["username"].values.tolist()
                list_pepper = site_data['pepper'].values.tolist()
                list_ciphertext_two = site_data['ciphertext_two'].values.tolist()

                list_username_img = site_data["username_img"].values.tolist()
                list_password_img = site_data["password_img"].values.tolist()
                list_ciphertext = site_data["ciphertext"].values.tolist()

                list_usn_x = site_data["usn_x_ratio"].values.tolist()
                list_usn_y = site_data["usn_y_ratio"].values.tolist()
                list_pwd_x = site_data["pwd_x_ratio"].values.tolist()
                list_pwd_y = site_data["pwd_y_ratio"].values.tolist()

                stored_list_of_urls = []
                        
                for url in list_url:
                    split_urls = urlsplit(url)
                    shorturl_from_split = split_urls.hostname
                    short_urls = shorturl_from_split.replace('www.', '')
                    stored_list_of_urls.append(short_urls)

                url_index = stored_list_of_urls.index(nickname)
                site_salt = list_salt[url_index]
                site_two_page = list_two_page[url_index]
                site_created_time = list_created_time[url_index]
                site_ciphertext = list_ciphertext[url_index]

                username_stored = list_username[url_index]
                username_img_stored = list_username_img[url_index]
                password_img_stored = list_password_img[url_index]

                site_pepper = list_pepper[url_index]
                site_ciphertext_two = list_ciphertext_two[url_index]

                usn_x_rate = list_usn_x[url_index]
                usn_y_rate = list_usn_y[url_index]
                pwd_x_rate = list_pwd_x[url_index]
                pwd_y_rate = list_pwd_y[url_index]

                conn.close()
                num_date = re.findall("[1-9]+", site_created_time) 
                joined_date = ''.join(num_date) 
                added_first = int(joined_date[-5:]) 
                added_second = int(joined_date[-10:-5]) 
                datetime_hashed = sha256(site_created_time.encode('ascii')).hexdigest()
                datetime_bytes = bytes(datetime_hashed, 'utf-8')

                key = hashlib.pbkdf2_hmac(
                'sha256', 
                logged_in_or_not[0].encode('utf-8'), 
                site_salt+datetime_bytes, 
                iteration_number_one+added_first, 
                dklen=64
                )
                small_key = hashlib.pbkdf2_hmac(
                'sha256', 
                key, 
                site_salt, 
                iteration_number_two+added_second, 
                dklen=32
                )
                file_in = open(site_ciphertext, "rb")
                nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

                cipher = AES.new(small_key, AES.MODE_EAX, nonce)
                decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)
                login_key = decrypted_key.decode('UTF-8')

                key_one = hashlib.pbkdf2_hmac(
                'sha256', 
                logged_in_or_not[0].encode('utf-8'), 
                site_pepper, 
                iteration_number_one, 
                dklen=64 
                )
                small_key_one = hashlib.pbkdf2_hmac(
                'sha256', 
                key_one, 
                site_pepper, 
                iteration_number_two, 
                dklen=32
                )


                file_in = open(site_ciphertext_two, "rb")
                nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

                cipher = AES.new(small_key_one, AES.MODE_EAX, nonce)
                decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)
                random_text_for_username_otp = decrypted_key.decode('UTF-8')


                deciphered_username = onetimepad.decrypt(random_text_for_username_otp, username_stored)

                if site_two_page == 'yes':
                    self.two_page_login()
                else:		
                    try:
                        screen_width = tk_root.winfo_screenwidth()
                        screen_height = tk_root.winfo_screenheight()

                        usernamelocation = pyautogui.locateCenterOnScreen(f"/carrypass_images/{username_img_stored}", confidence=0.9)
                    

                        pyautogui.moveTo(usernamelocation[0], usernamelocation[1]) 
                        
                        pyautogui.click(usernamelocation)
                
                        pyautogui.doubleClick()
                        pyautogui.press('delete')
                        pyautogui.press('esc')
                        pyperclip.copy(deciphered_username)
                        pyautogui.hotkey("ctrl", "v")
                    
                        time.sleep(0.2)
                        pyautogui.press('esc')
                        pyperclip.copy("")
                        pyautogui.moveTo(1,1)
                        time.sleep(0.2)
                    except:
                        try:
                            pyautogui.click(screen_width/usn_x_rate, screen_height/usn_y_rate)
                            pyautogui.doubleClick()
                            pyautogui.press('delete')
                            pyautogui.press('esc')
                            pyperclip.copy(deciphered_username)
                            pyautogui.hotkey("ctrl", "v")
                        
                            time.sleep(0.2)
                            pyautogui.press('esc')
                            pyperclip.copy("")
                            pyautogui.moveTo(1,1)
                            time.sleep(0.2)
                        except:
                            pass
                    try:
                        passwordlocation = pyautogui.locateCenterOnScreen(f"/carrypass_images/{password_img_stored}", confidence=0.9)

                        pyautogui.moveTo(passwordlocation[0], passwordlocation[1])

                        pyautogui.click(passwordlocation)

                        pyperclip.copy(login_key)
                    
                        pyautogui.doubleClick()
                        pyautogui.press('delete')
                        pyautogui.press('esc')
                        pyautogui.hotkey("ctrl", "v")
                    
                        pyautogui.press('enter')
                        
                        pyperclip.copy("")
                        self.show_application()
                        self.toast_finished_login()
                        
                    except:
                        try:
                            pyautogui.click(screen_width/pwd_x_rate, screen_height/pwd_y_rate)
                            pyperclip.copy(login_key)
                        
                            pyautogui.doubleClick()
                            pyautogui.press('delete')
                            pyautogui.press('esc')
                            pyautogui.hotkey("ctrl", "v")
                        
                            pyautogui.press('enter')

                            pyperclip.copy("")
                            self.show_application()
                            self.toast_finished_login()
                            
                        except:
                            self.show_application()
                            self.show_no_image_dialog()





        def two_page_login(self):
                global deciphered_username
                time.sleep(1)
                try:
                    screen_width = tk_root.winfo_screenwidth()
                    screen_height = tk_root.winfo_screenheight()

                    usernamelocation = pyautogui.locateCenterOnScreen(f"/carrypass_images/{username_img_stored}", confidence=0.9) 
                

                    pyautogui.moveTo(usernamelocation[0], usernamelocation[1]) 
                    
                    pyautogui.click(usernamelocation)		
                    
                    pyautogui.doubleClick()
                    pyautogui.press('delete')
                    pyautogui.press('esc')
                    pyperclip.copy(deciphered_username)
                    pyautogui.hotkey("ctrl", "v")
                
                    time.sleep(0.2)
                    pyautogui.press('esc')
                    pyperclip.copy("")
                    pyautogui.press('enter')
                    pyautogui.moveTo(1,1)
                    time.sleep(0.2)
                except:
                    try:
                        pyautogui.click(screen_width/usn_x_rate, screen_height/usn_y_rate)
                        pyautogui.doubleClick()
                        pyautogui.press('delete')
                        pyautogui.press('esc')
                        pyperclip.copy(deciphered_username)
                        pyautogui.hotkey("ctrl", "v")
                    
                        time.sleep(0.2)
                        pyautogui.press('esc')
                        pyperclip.copy("")
                        pyautogui.press('enter')
                        pyautogui.moveTo(1,1)
                        time.sleep(0.2)
                    except:
                        pass
                try:
                    passwordlocation = pyautogui.locateCenterOnScreen(f"/carrypass_images/{password_img_stored}", confidence=0.9)

                    pyautogui.moveTo(passwordlocation[0], passwordlocation[1])

                    pyautogui.click(passwordlocation)

                    pyperclip.copy(login_key)
                
                    pyautogui.doubleClick()
                    pyautogui.press('delete')
                    pyautogui.press('esc')
                    pyautogui.hotkey("ctrl", "v")
                
                    pyautogui.press('enter')
                    pyperclip.copy("")
                    self.toast_finished_login()
                except:
                    try:
                        pyautogui.click(screen_width/pwd_x_rate, screen_height/pwd_y_rate)
                        pyperclip.copy(login_key)
                    
                        pyautogui.doubleClick()
                        pyautogui.press('delete')
                        pyautogui.press('esc')
                        pyautogui.hotkey("ctrl", "v")
                    
                        pyautogui.press('enter')

                        pyperclip.copy("")
                        
                        self.toast_finished_login()
                        self.show_application()
                        
                    except:
                        
                        self.show_no_image_dialog()
                        self.show_application()
                        


        def get_username_img(self):
                    global url_for_id
                    global timeout_start
                    self.timeout_app()
                    timeout_start = time.time()

                    pyautogui.keyDown('alt')
                    pyautogui.press('tab')
                    pyautogui.keyUp('alt')
                    pyautogui.hotkey('win', 'up')
                    pyautogui.hotkey('win', 'up')
                    pyautogui.hotkey('ctrl', '0')

                    pyperclip.copy("")
                    pyautogui.hotkey('win', 'shift', 's')
                    self.show_save_usn_img_dialog()




        def get_application_username_img(self):
                    global url_for_id
                    global timeout_start
                    self.timeout_app()
                    timeout_start = time.time()

                    pyperclip.copy("")
                    pyautogui.hotkey('win', 'shift', 's')
                    self.show_save_usn_img_dialog()
                    



        def get_password_img(self):
                    global url_for_id
                    global timeout_start
                    self.timeout_app()
                    timeout_start = time.time()

                    pyautogui.keyDown('alt')
                    pyautogui.press('tab')
                    pyautogui.keyUp('alt')
                    pyautogui.hotkey('win', 'up')
                    pyautogui.hotkey('win', 'up')
                    pyautogui.hotkey('ctrl', '0')
                    # time.sleep(0.1)
                    pyperclip.copy("")
                    pyautogui.hotkey('win', 'shift', 's')
                    self.show_save_pwd_img_dialog()



        def get_application_password_img(self):
                    global url_for_id
                    global timeout_start
                    self.timeout_app()
                    timeout_start = time.time()
                    pyperclip.copy("")
                    pyautogui.hotkey('win', 'shift', 's')
                    self.show_save_pwd_img_dialog()

                    


        def save_username_image(self):
                    site_url = url_for_id                   
                    try:
                        conn = sqlite3.connect("/carrypass_database/master.db")
                        site_data = create_pandas_table("SELECT url, username_img FROM logindata ORDER BY oid", conn)
                        list_url = site_data['url'].values.tolist()

                        list_username_img = site_data["username_img"].values.tolist()

                        url_index = list_url.index(site_url)

                        username_img_stored = list_username_img[url_index]

                        screen_width = tk_root.winfo_screenwidth()
                        screen_height = tk_root.winfo_screenheight()
                    
                        username_image = ImageGrab.grabclipboard()
                        date_time = datetime.today()
                        datetime_clipped = date_time.strftime("%Y-%m-%d")

                        is_web_address = re.match("http", site_url)
                        if is_web_address:
                            split_web_address = urlsplit(site_url)
                            nickname_from_split = split_web_address.hostname
                            nickname = nickname_from_split.replace('www.', '')
                        else:
                            alphanum = re.findall('[a-z A-Z 0-9]+', site_url)
                            nickname = ''.join(alphanum)
                        
                        whichis = '_usn_'
                        file_extension = '.png'
                        filename_u = nickname+whichis+datetime_clipped+file_extension
                        if os.path.exists("/carrypass_images/"+username_img_stored):
                            if len(username_img_stored) > 0:
                                os.remove("/carrypass_images/"+username_img_stored)
                        else:
                            pass
                        username_image.save(f"/carrypass_images/{filename_u}")

                
                        locate_username = pyautogui.locateCenterOnScreen(f"/carrypass_images/{filename_u}")
                        
                        username_x_location = screen_width/locate_username[0]
                        username_y_location = screen_height/locate_username[1]


                        conn = sqlite3.connect('/carrypass_database/master.db')
                        c = conn.cursor()
                        c.execute("UPDATE logindata SET username_img=?, usn_x_ratio=?, usn_y_ratio=?  WHERE url=?", (filename_u, username_x_location, username_y_location, site_url))
                        conn.commit()
                        conn.close()
                        self.root.ids.edititem.ids.username_check.md_bg_color = get_color_from_hex("#aeaeae")
                        
                        self.toast_image_saved()

                        self.show_application()

                    except:
                        self.toast_image_validation_failed()

                        self.show_application()




        def save_password_image(self):
                site_url = url_for_id
                try:
                    conn = sqlite3.connect("/carrypass_database/master.db")
                    site_data = create_pandas_table("SELECT url, password_img FROM logindata ORDER BY oid", conn)
                    list_url = site_data['url'].values.tolist()

                    list_password_img = site_data["password_img"].values.tolist()

                    url_index = list_url.index(site_url)

                    password_img_stored = list_password_img[url_index]

                    screen_width = tk_root.winfo_screenwidth()
                    screen_height = tk_root.winfo_screenheight()
                    
                    password_image = ImageGrab.grabclipboard()
                    date_time = datetime.today()
                    datetime_clipped = date_time.strftime("%Y-%m-%d")

                    is_web_address = re.match("http", site_url)
                    if is_web_address:
                        split_web_address = urlsplit(site_url)
                        nickname_from_split = split_web_address.hostname
                        nickname = nickname_from_split.replace('www.', '')
                    else:
                        alphanum = re.findall('[a-z A-Z 0-9]+', site_url)
                        nickname = ''.join(alphanum)
                
                    whichis = '_pwd_'
                    file_extension = '.png'
                    filename_p = nickname+whichis+datetime_clipped+file_extension
                    if os.path.exists("/carrypass_images/"+password_img_stored):
                        if len(password_img_stored) > 0:
                            os.remove("/carrypass_images/"+password_img_stored)
                    else:
                        pass
                    password_image.save(f"/carrypass_images/{filename_p}")
                    
                    locate_password = pyautogui.locateCenterOnScreen(f"/carrypass_images/{filename_p}")
                    password_x_location = screen_width/locate_password[0]
                    password_y_location = screen_height/locate_password[1]

                    conn = sqlite3.connect('/carrypass_database/master.db')
                    c = conn.cursor()
                    c.execute("UPDATE logindata SET password_img=?, pwd_x_ratio=?, pwd_y_ratio=? WHERE url=?", (filename_p, password_x_location, password_y_location, site_url))
                    conn.commit()
                    conn.close()

                    self.root.ids.edititem.ids.password_check.md_bg_color = get_color_from_hex("#aeaeae")
                    self.toast_image_saved()
                    self.show_application()                  

                except:
                    self.toast_image_validation_failed()
                    self.show_application()




        def save_selected_page(self):
            global timeout_start
            self.timeout_app()
            timeout_start = time.time()
            url_from_entry = url_for_id

            if len(logged_in_or_not)>0:

                is_web_address = re.match("http", url_from_entry)
                if is_web_address:
                    split_web_address = urlsplit(url_from_entry)
                    nickname_from_split = split_web_address.hostname
                    nickname = nickname_from_split.replace('www.', '')
                else:
                    alphanum = re.findall('[a-z A-Z 0-9]+', url_from_entry)
                    nickname = ''.join(alphanum)


                random_secret = get_random_password_string(512) 
                
                username = self.root.ids.edititem.ids.username.text
                
                otp_username = onetimepad.encrypt(username, random_secret)  

                random_otp_pad_stored = bytes(otp_username, 'utf-8')


                pepper = os.urandom(64)

                key_one = hashlib.pbkdf2_hmac(
                'sha256', 
                logged_in_or_not[0].encode('utf-8'), 
                pepper, 
                iteration_number_one, 
                dklen=64 
                )
                small_key_one = hashlib.pbkdf2_hmac(
                'sha256', 
                key_one, 
                pepper, 
                iteration_number_two, 
                dklen=32
                )

                usn_whichis = '_username_'
                usn_file_extension = '.bin'
                filename_for_username = nickname+usn_whichis+usn_file_extension
                folder_for_username = '/carrypass_keys/'

                cipher = AES.new(small_key_one, AES.MODE_EAX)
                ciphertext, tag = cipher.encrypt_and_digest(random_otp_pad_stored)

                file_out = open(f"/carrypass_keys/{filename_for_username}", "wb")
                [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
                file_out.close()

                username_file_path = folder_for_username+filename_for_username

                nickname = self.root.ids.edititem.ids.nickname.text

                if self.root.ids.edititem.ids.twopage_switch.active == True:
                    two_page = 'yes'
                elif self.root.ids.edititem.ids.twopage_switch.active == False:
                    two_page = 'no'

                conn = sqlite3.connect('/carrypass_database/master.db')

                # Create a cursor instance
                c = conn.cursor()
                # try:
                c.execute("""UPDATE logindata SET
                    username = :username,
                    pepper = :pepper,
                    ciphertext_two = :ciphertext_two,
                    nickname = :nickname,
                    two_page = :two_page
                    WHERE url = :url""",
                    {
                        'username': random_secret,
                        'pepper': pepper,
                        'ciphertext_two': username_file_path,
                        'nickname': nickname,
                        'two_page': two_page,
                        'url': url_from_entry,
                    })
                

                conn.commit()

                c.close()
                conn.close()
                self.toast_changes_saved()
            else:
                self.deactivate_with_timeout()



        def choose_webbrowser_for_login(self):
            global primary_browser

            conn = sqlite3.connect("/carrypass_database/master.db")
            site_data = create_pandas_table("SELECT url, webbrowser FROM logindata ORDER BY oid", conn)
            list_url = site_data['url'].values.tolist()
            list_webbrowser = site_data['webbrowser'].values.tolist()
            url_index = list_url.index(url_for_id)

            webbrowser_stored = list_webbrowser[url_index]
            primary_browser = webbrowser_stored
            login_url = url_for_id
            if primary_browser == 'Firefox':  
                if os.path.exists('C:/Program Files/Mozilla Firefox/firefox.exe'):     
                    try:
                        firefox_path = 'C:/Program Files/Mozilla Firefox/firefox.exe %s'
                        webbrowser.get(firefox_path).open_new(login_url)

                    except:
                        try:
                            webbrowser.open(login_url, new=2)
                        except:
                            self.toast_cannot_open_browser()
                else:
                    try:
                        webbrowser.open(login_url, new=2)
                    except:
                        self.toast_cannot_open_browser()
            elif primary_browser == 'Firefox - private window':
                if os.path.exists('C:/Program Files/Mozilla Firefox/firefox.exe'):
                    try:
                        firefox_path = 'C:/Program Files/Mozilla Firefox/firefox.exe -private-window %s'
                        webbrowser.get(firefox_path).open_new(login_url)
                    except:
                        try:
                            webbrowser.open(login_url, new=2)
                        except:
                            self.toast_cannot_open_browser()
                else:
                    try:
                        webbrowser.open(login_url, new=2)
                    except:
                        self.toast_cannot_open_browser()
            elif primary_browser == 'Default browser':
                try:
                    webbrowser.open(login_url, new=2)
                except:
                    self.toast_cannot_open_browser()
            elif primary_browser == 'Application login':
                pass
            else:
                try:
                    webbrowser.open(login_url, new=2)
                except:
                    self.toast_cannot_open_browser()



        def open_and_login(self):
                global timeout_start
                self.timeout_app()
                timeout_start = time.time()
                global deciphered_username
                global usn_x_rate
                global usn_y_rate
                global pwd_x_rate
                global pwd_y_rate
                global insecure_login
                if insecure_login:
                    pyautogui.keyDown('alt')
                    pyautogui.press('tab')
                    pyautogui.keyUp('alt')
                    insecure_login = False	
                try:
                    site_url = url_for_id
                    
                    conn = sqlite3.connect("/carrypass_database/master.db")
                    site_data = create_pandas_table("SELECT url, username, salt, pepper, special, two_page, created_time, username_img, password_img, ciphertext, usn_x_ratio, usn_y_ratio, pwd_x_ratio, pwd_y_ratio, ciphertext_two FROM logindata ORDER BY oid", conn)
                    list_url = site_data['url'].values.tolist()
                    list_salt = site_data['salt'].values.tolist()
                    list_two_page = site_data['two_page'].values.tolist()
                    list_created_time = site_data['created_time'].values.tolist()
                    list_username = site_data["username"].values.tolist()
                    list_pepper = site_data['pepper'].values.tolist()
                    list_ciphertext_two = site_data['ciphertext_two'].values.tolist()
                    list_username_img = site_data["username_img"].values.tolist()
                    list_password_img = site_data["password_img"].values.tolist()
                    list_ciphertext = site_data["ciphertext"].values.tolist()

                    list_usn_x = site_data["usn_x_ratio"].values.tolist()
                    list_usn_y = site_data["usn_y_ratio"].values.tolist()
                    list_pwd_x = site_data["pwd_x_ratio"].values.tolist()
                    list_pwd_y = site_data["pwd_y_ratio"].values.tolist()

                    url_index = list_url.index(site_url)
                    site_salt = list_salt[url_index]
                    site_two_page = list_two_page[url_index]
                    site_created_time = list_created_time[url_index]
                    

                    username_stored = list_username[url_index]
                    username_img_stored = list_username_img[url_index]
                    password_img_stored = list_password_img[url_index]
                    site_ciphertext = list_ciphertext[url_index]

                    site_pepper = list_pepper[url_index]
                    site_ciphertext_two = list_ciphertext_two[url_index]

                    usn_x_rate = list_usn_x[url_index]
                    usn_y_rate = list_usn_y[url_index]
                    pwd_x_rate = list_pwd_x[url_index]
                    pwd_y_rate = list_pwd_y[url_index]

                    conn.close()
                    num_date = re.findall("[1-9]+", site_created_time) 
                    joined_date = ''.join(num_date) 
                    added_first = int(joined_date[-5:]) 
                    added_second = int(joined_date[-10:-5]) 
                    datetime_hashed = sha256(site_created_time.encode('ascii')).hexdigest()
                    datetime_bytes = bytes(datetime_hashed, 'utf-8')

                    key = hashlib.pbkdf2_hmac(
                    'sha256', 
                    logged_in_or_not[0].encode('utf-8'), 
                    site_salt+datetime_bytes, 
                    iteration_number_one+added_first, 
                    dklen=64 
                    )
                    small_key = hashlib.pbkdf2_hmac(
                    'sha256', 
                    key, 
                    site_salt, 
                    iteration_number_two+added_second, 
                    dklen=32
                    )
                    file_in = open(site_ciphertext, "rb")
                    nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

                    cipher = AES.new(small_key, AES.MODE_EAX, nonce)
                    decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)
                    login_key = decrypted_key.decode('UTF-8')

                    key_one = hashlib.pbkdf2_hmac(
                    'sha256', 
                    logged_in_or_not[0].encode('utf-8'), 
                    site_pepper, 
                    iteration_number_one, 
                    dklen=64 
                    )
                    small_key_one = hashlib.pbkdf2_hmac(
                    'sha256', 
                    key_one, 
                    site_pepper, 
                    iteration_number_two, 
                    dklen=32
                    )


                    file_in = open(site_ciphertext_two, "rb")
                    nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

                    cipher = AES.new(small_key_one, AES.MODE_EAX, nonce)
                    decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)
                    random_text_for_username_otp = decrypted_key.decode('UTF-8')


                    deciphered_username = onetimepad.decrypt(random_text_for_username_otp, username_stored)

                    if site_two_page == 'yes':
                        self.two_page_login()
                    else:	
                        try:
                            if primary_browser != 'Application login':
                                pyautogui.hotkey('ctrl', 'l')
                                pyautogui.hotkey('esc')
                                pyautogui.hotkey('win', 'up')
                                pyautogui.hotkey('win', 'up')
                                pyautogui.hotkey('ctrl', '0')
                            screen_width = tk_root.winfo_screenwidth()
                            screen_height = tk_root.winfo_screenheight()
                            usernamelocation = pyautogui.locateCenterOnScreen(f"/carrypass_images/{username_img_stored}", confidence=0.9)

                            pyautogui.moveTo(usernamelocation[0], usernamelocation[1]) 

                            pyautogui.click(usernamelocation) 
                            pyautogui.doubleClick()
                            pyautogui.press('delete')
                            pyautogui.press('esc')
                            pyperclip.copy(deciphered_username)
                            pyautogui.hotkey("ctrl", "v")
                        
                            time.sleep(0.2)
                            pyautogui.press('esc')
                            pyperclip.copy("")
                            pyautogui.moveTo(1,1)
                            time.sleep(0.2)
                        except:
                            try:
                                pyautogui.click(screen_width/usn_x_rate, screen_height/usn_y_rate)
                                pyautogui.doubleClick()
                                pyautogui.press('delete')
                                pyautogui.press('esc')
                                pyperclip.copy(deciphered_username)
                                pyautogui.hotkey("ctrl", "v")
                            
                                time.sleep(0.2)
                                pyautogui.press('esc')
                                pyperclip.copy("")
                                pyautogui.moveTo(1,1)
                                time.sleep(0.2)
                            except:
                                pass
                        try:

                            passwordlocation = pyautogui.locateCenterOnScreen(f"/carrypass_images/{password_img_stored}", confidence=0.9)

                            pyautogui.moveTo(passwordlocation[0], passwordlocation[1]) 

                            pyperclip.copy(login_key)
                            pyautogui.click(passwordlocation) 
                            pyautogui.doubleClick()
                            pyautogui.press('delete')
                            pyautogui.press('esc')
                            pyautogui.hotkey("ctrl", "v")
                            pyautogui.press('enter')

                            pyperclip.copy("")

                        except:
                            try:
                                pyautogui.click(screen_width/pwd_x_rate, screen_height/pwd_y_rate)
                                pyperclip.copy(login_key)
                            
                                pyautogui.doubleClick()
                                pyautogui.press('delete')
                                pyautogui.press('esc')
                                pyautogui.hotkey("ctrl", "v")
                            
                                pyautogui.press('enter')

                                self.show_application()
                                self.toast_finished_login()
                                
                                pyperclip.copy("")
                            except:
                                self.show_application()
                                self.toast_no_image_found()
                                
                except:
                    self.show_application()
                    self.toast_mac_check_failed()
                    




        def check_secure_connection_before_open_and_login(self):
                global insecure_login
                global timeout_start
                self.timeout_app()
                timeout_start = time.time()
                self.choose_webbrowser_for_login()
                if primary_browser == "Application login":
                    self.open_and_login()
                else:
                    try:
                        time.sleep(3)
                        pyautogui.hotkey('ctrl', 'l')
                        pyautogui.hotkey('esc')
                        pyautogui.hotkey('win', 'up')
                        pyautogui.hotkey('win', 'up')
                        pyautogui.hotkey('ctrl', '0')
                        pyautogui.hotkey('ctrl', 'c')
                        pyautogui.hotkey('esc')
                        load_address = pyperclip.paste()
                        is_secure_site = re.match("https:", load_address)
                        insecure_site = re.match("http:", load_address)
                        if is_secure_site:
                            self.open_and_login()

                        elif insecure_site:
                            insecure_login = True
                            self.show_application()
                            self.show_isecure_site_openlogin_dialog()
                                            
                        else:
                            insecure_login = True
                            self.show_application()
                            self.show_unclear_site_openlogin_dialog()

                    except:
                        self.show_application()
                        self.toast_login_failed()
                        



        def add_new_record(self):
                try:
                    conn = sqlite3.connect("/carrypass_database/master.db")
                    site_data = create_pandas_table("SELECT url FROM logindata ORDER BY oid", conn)
                    list_url = site_data['url'].values.tolist()
                    conn.close()
                    global timeout_start
                    self.timeout_app()
                    timeout_start = time.time()

                    pyautogui.keyDown('alt')
                    pyautogui.press('tab')
                    pyautogui.keyUp('alt')

                    pyautogui.hotkey('ctrl', 'l')
                    pyautogui.hotkey('ctrl', 'c')
                    pyautogui.hotkey('esc')
                    # global login_message
                    web_address = pyperclip.paste()

                    is_web_address = re.match("http", web_address)

                    stored_list_of_urls = []

                    for url in list_url:
                        split_urls = urlsplit(url)
                        shorturl_from_split = split_urls.hostname
                        short_urls = shorturl_from_split.replace('www.', '')
                        stored_list_of_urls.append(short_urls)
                    
                    nickname_split =urlsplit(web_address)
                    nickname_host = nickname_split.hostname
                    nickname = nickname_host.replace('www.', '')

                    if web_address in list_url:
                        self.show_application()
                        self.toast_record_already_exist()
                    
                    elif nickname in stored_list_of_urls:
                        self.show_application()
                        self.toast_record_already_exist()

                    else:                      
                        pyperclip.copy('')

                        salt = os.urandom(32)
                        date_time = datetime.today()
                        datetime_created = date_time.strftime("%Y-%m-%d %H:%M:%S.%f")
                        num_date = re.findall("[1-9]+", datetime_created) 
                        joined_date = ''.join(num_date) 
                        added_first = int(joined_date[-5:]) 
                        added_second = int(joined_date[-10:-5]) 
                        datetime_hashed = sha256(datetime_created.encode('ascii')).hexdigest()
                        datetime_bytes = bytes(datetime_hashed, 'utf-8')

                        key = hashlib.pbkdf2_hmac(
                        'sha256', 
                        logged_in_or_not[0].encode('utf-8'), 
                        salt+datetime_bytes, 
                        iteration_number_one+added_first, 
                        dklen=64 
                        )
                        small_key = hashlib.pbkdf2_hmac(
                        'sha256', 
                        key, 
                        salt, 
                        iteration_number_two+added_second, 
                        dklen=32
                        )
                        random_password = get_random_special_password_string(43)
                        random_passw_length = len(random_password)


                        date_time = datetime.today()
                        datetime_clipped = date_time.strftime("%Y-%m-%d")

                        split_web_address = urlsplit(web_address)
                        nickname_from_split = split_web_address.hostname
                        nickname = nickname_from_split.replace('www.', '')
                        
                        whichis = '_pwd_'
                        file_extension = '.bin'
                        filename = nickname+whichis+datetime_clipped+file_extension
                        folder = '/carrypass_keys/'

                        pwd_for_site_login = bytes(random_password, 'utf-8')
                        cipher = AES.new(small_key, AES.MODE_EAX)
                        ciphertext, tag = cipher.encrypt_and_digest(pwd_for_site_login)

                        file_out = open(f"/carrypass_keys/{filename}", "wb")
                        [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
                        file_out.close()

                        ciphertext_file_path = folder+filename

                        split_web_address = urlsplit(web_address)
                        nickname_from_split = split_web_address.hostname
                        short_nickname = nickname_from_split.replace('www.', '')

                        random_secret = get_random_password_string(512) 
                        
                        username = ""
                        
                        otp_username = onetimepad.encrypt(username, random_secret)  

                        random_otp_pad_stored = bytes(otp_username, 'utf-8')


                        pepper = os.urandom(64)

                        key_one = hashlib.pbkdf2_hmac(
                        'sha256', 
                        logged_in_or_not[0].encode('utf-8'), 
                        pepper, 
                        iteration_number_one, 
                        dklen=64 
                        )
                        small_key_one = hashlib.pbkdf2_hmac(
                        'sha256', 
                        key_one, 
                        pepper, 
                        iteration_number_two, 
                        dklen=32
                        )

                        usn_whichis = '_username_'
                        usn_file_extension = '.bin'
                        filename_for_username = nickname+usn_whichis+usn_file_extension
                        folder_for_username = '/carrypass_keys/'

                        cipher = AES.new(small_key_one, AES.MODE_EAX)
                        ciphertext, tag = cipher.encrypt_and_digest(random_otp_pad_stored)

                        file_out = open(f"/carrypass_keys/{filename_for_username}", "wb")
                        [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
                        file_out.close()

                        username_file_path = folder_for_username+filename_for_username

                        conn = sqlite3.connect('/carrypass_database/master.db')

                        c = conn.cursor()
                        c.execute("INSERT INTO logindata VALUES (:category, :nickname, :url, :username, :salt, :variant, :pepper, :special, :max_pass_length, :two_page, :created_time, :username_img, :password_img, :ciphertext, 	:usn_x_ratio, :usn_y_ratio, :pwd_x_ratio, :pwd_y_ratio, :ciphertext_two, :webbrowser)",
                        {
                            'category': 'other',
                            'nickname': short_nickname,
                            'url': web_address,
                            'username': random_secret,
                            'salt': salt,
                            'variant': 0,
                            'pepper': pepper,
                            'special': 'yes',
                            'max_pass_length': random_passw_length,
                            'two_page': 'no',
                            'created_time': datetime_created,
                            'username_img': "",
                            'password_img': "",
                            'ciphertext': ciphertext_file_path,
                            'usn_x_ratio' : "",
                            'usn_y_ratio' : "",
                            'pwd_x_ratio' : "",
                            'pwd_y_ratio' : "",
                            'ciphertext_two' : username_file_path,
                            'webbrowser' : 'Default browser',
                        })
                        

                        conn.commit()

                       
                        conn.close()

                        self.list_login_pages()
                        self.root.ids.mainview.ids.search_field.text = ""
                        pyperclip.copy(random_password)
                        self.show_application()
                        self.toast_new_page_added()
                        
                except:
                    self.show_application()
                    self.toast_not_browser()




        def add_new_application(self):

                    conn = sqlite3.connect("/carrypass_database/master.db")
                    site_data = create_pandas_table("SELECT url FROM logindata ORDER BY oid", conn)
                    list_url = site_data['url'].values.tolist()
                    conn.close()
                    global timeout_start
                    self.timeout_app()
                    timeout_start = time.time()

                    web_address = self.root.ids.application.ids.application_name.text


                    alphanum = re.findall('[a-z A-Z 0-9]+', web_address)
                    joined_nick = ''.join(alphanum)
                    space_delete_nick = joined_nick.replace(" ", "")
                    nickname = space_delete_nick+".application"

                    app_url = r"https://"+nickname


                    if app_url in list_url:
                        self.show_application()
                        self.toast_record_already_exist()

                    else:                      
                        pyperclip.copy('')

                        salt = os.urandom(32)
                        date_time = datetime.today()
                        datetime_created = date_time.strftime("%Y-%m-%d %H:%M:%S.%f")
                        num_date = re.findall("[1-9]+", datetime_created) 
                        joined_date = ''.join(num_date) 
                        added_first = int(joined_date[-5:]) 
                        added_second = int(joined_date[-10:-5]) 
                        datetime_hashed = sha256(datetime_created.encode('ascii')).hexdigest()
                        datetime_bytes = bytes(datetime_hashed, 'utf-8')

                        key = hashlib.pbkdf2_hmac(
                        'sha256', 
                        logged_in_or_not[0].encode('utf-8'), 
                        salt+datetime_bytes, 
                        iteration_number_one+added_first, 
                        dklen=64 
                        )
                        small_key = hashlib.pbkdf2_hmac(
                        'sha256', 
                        key, 
                        salt, 
                        iteration_number_two+added_second, 
                        dklen=32
                        )
                        random_password = get_random_special_password_string(43)
                        random_passw_length = len(random_password)


                        date_time = datetime.today()
                        datetime_clipped = date_time.strftime("%Y-%m-%d")

                        alphanum = re.findall('[a-z A-Z 0-9]+', web_address)
                        joined_nick = ''.join(alphanum)
                        space_delete_nick = joined_nick.replace(" ", "")
                        nickname = space_delete_nick+".application"

                        app_url = r"https://"+nickname

                        whichis = '_pwd_'
                        file_extension = '.bin'
                        filename = nickname+whichis+datetime_clipped+file_extension
                        folder = '/carrypass_keys/'

                        pwd_for_site_login = bytes(random_password, 'utf-8')
                        cipher = AES.new(small_key, AES.MODE_EAX)
                        ciphertext, tag = cipher.encrypt_and_digest(pwd_for_site_login)

                        file_out = open(f"/carrypass_keys/{filename}", "wb")
                        [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
                        file_out.close()

                        ciphertext_file_path = folder+filename

                        random_secret = get_random_password_string(512) 
                        
                        username = ""
                        
                        otp_username = onetimepad.encrypt(username, random_secret)  

                        random_otp_pad_stored = bytes(otp_username, 'utf-8')

                        pepper = os.urandom(64)

                        key_one = hashlib.pbkdf2_hmac(
                        'sha256', 
                        logged_in_or_not[0].encode('utf-8'), 
                        pepper, 
                        iteration_number_one, 
                        dklen=64 
                        )
                        small_key_one = hashlib.pbkdf2_hmac(
                        'sha256', 
                        key_one, 
                        pepper, 
                        iteration_number_two, 
                        dklen=32
                        )

                        usn_whichis = '_username_'
                        usn_file_extension = '.bin'
                        filename_for_username = nickname+usn_whichis+usn_file_extension
                        folder_for_username = '/carrypass_keys/'

                        cipher = AES.new(small_key_one, AES.MODE_EAX)
                        ciphertext, tag = cipher.encrypt_and_digest(random_otp_pad_stored)

                        file_out = open(f"/carrypass_keys/{filename_for_username}", "wb")
                        [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
                        file_out.close()

                        username_file_path = folder_for_username+filename_for_username

                        conn = sqlite3.connect('/carrypass_database/master.db')

                        c = conn.cursor()
                        c.execute("INSERT INTO logindata VALUES (:category, :nickname, :url, :username, :salt, :variant, :pepper, :special, :max_pass_length, :two_page, :created_time, :username_img, :password_img, :ciphertext, 	:usn_x_ratio, :usn_y_ratio, :pwd_x_ratio, :pwd_y_ratio, :ciphertext_two, :webbrowser)",
                        {
                            'category': 'other',
                            'nickname': web_address+" - application",
                            'url': app_url,
                            'username': random_secret,
                            'salt': salt,
                            'variant': 0,
                            'pepper': pepper,
                            'special': 'yes',
                            'max_pass_length': random_passw_length,
                            'two_page': 'no',
                            'created_time': datetime_created,
                            'username_img': "",
                            'password_img': "",
                            'ciphertext': ciphertext_file_path,
                            'usn_x_ratio' : "",
                            'usn_y_ratio' : "",
                            'pwd_x_ratio' : "",
                            'pwd_y_ratio' : "",
                            'ciphertext_two' : username_file_path,
                            'webbrowser' : 'Application login',
                        })
                        

                        conn.commit()

                        conn.close()

                        self.list_login_pages()
                        self.root.current = "mainview"
                        self.root.transition.direction = "right"
                        self.root.ids.application.ids.application_name.text = ""
                        self.toast_new_app_added()





        def change_default_browser(self):
            # try:
                site_url = url_for_id
                global timeout_start
                self.timeout_app()
                timeout_start = time.time()

                if self.root.ids.webbrowser.ids.default_browser.active == True:
                    webbrowser_set = 'Default browser'
                elif self.root.ids.webbrowser.ids.firefox.active == True:
                    webbrowser_set = 'Firefox'
                elif self.root.ids.webbrowser.ids.firefox_private.active == True:
                    webbrowser_set = 'Firefox - private window'
                elif self.root.ids.webbrowser.ids.applogin.active == True:
                    webbrowser_set = 'Application login'
                else:
                    self.toast_choose_browser()



                conn = sqlite3.connect('/carrypass_database/master.db')

                c = conn.cursor()
                c.execute("""UPDATE logindata SET 
                webbrowser = :webbrowser
                WHERE url = :url""",
                {
                    'webbrowser': webbrowser_set,
                    'url': site_url,
                })
                
                conn.commit()

                conn.close()
                self.toast_changes_saved()




        def show_webbrowsers_for_page(self):
            global url_for_id

            conn = sqlite3.connect("/carrypass_database/master.db")
            site_data = create_pandas_table("SELECT url, webbrowser FROM logindata ORDER BY oid", conn)
            list_url = site_data['url'].values.tolist()
            list_webbrowser = site_data['webbrowser'].values.tolist()
            url_index = list_url.index(url_for_id)

            webbrowser_stored = list_webbrowser[url_index]
            primary_browser = webbrowser_stored

            if primary_browser == 'Firefox':
                self.root.ids.webbrowser.ids.firefox.active = True
                self.root.ids.webbrowser.ids.applogin.disabled = True
            elif primary_browser == 'Firefox - private window':
                self.root.ids.webbrowser.ids.firefox_private.active = True
                self.root.ids.webbrowser.ids.applogin.disabled = True
            elif primary_browser == 'Default browser':
                self.root.ids.webbrowser.ids.default_browser.active = True
                self.root.ids.webbrowser.ids.applogin.disabled = True
            elif primary_browser == 'Application login':
                self.root.ids.webbrowser.ids.applogin.active = True
                self.root.ids.webbrowser.ids.firefox.disabled = True
                self.root.ids.webbrowser.ids.firefox_private.disabled = True
                self.root.ids.webbrowser.ids.default_browser.disabled = True




        def remove_one(self):  
                    global timeout_start
                    self.timeout_app()
                    timeout_start = time.time()

                    conn = sqlite3.connect('/carrypass_database/master.db')
                    c = conn.cursor()

                    site_data = create_pandas_table("SELECT url, username_img, password_img, ciphertext, ciphertext_two FROM logindata ORDER BY oid", conn)
                    list_url = site_data['url'].values.tolist()

                    list_username_img = site_data["username_img"].values.tolist()
                    list_password_img = site_data["password_img"].values.tolist()
                    list_ciphertext = site_data["ciphertext"].values.tolist()
                    list_ciphertext_two = site_data['ciphertext_two'].values.tolist()


                    url_index = list_url.index(url_for_id)

                    site_ciphertext = list_ciphertext[url_index]
                    site_ciphertext_two = list_ciphertext_two[url_index]

                    username_img_stored = list_username_img[url_index]
                    password_img_stored = list_password_img[url_index]

                    try:
                        if os.path.exists("/carrypass_images/"+username_img_stored):
                            os.remove("/carrypass_images/"+username_img_stored)
                        else:
                            pass

                        if os.path.exists("/carrypass_images/"+password_img_stored):
                            os.remove("/carrypass_images/"+password_img_stored)
                        else:
                            pass


                        if os.path.exists(site_ciphertext):
                            os.remove(site_ciphertext)
                        else:
                            pass                        

                        if os.path.exists(site_ciphertext_two):
                            os.remove(site_ciphertext_two)
                        else:
                            pass                                       
                    except:
                        pass


                    c.execute(f'SELECT oid from logindata WHERE url="{url_for_id}"')

                    tuple = c.fetchone()  
                    if tuple != None: 
                        oid = tuple[0]

                    conn.commit()

                    c.execute("DELETE from logindata WHERE oid=" + str(oid))
                    
                    conn.commit()

                    conn.close()


                    self.list_login_pages()
                    self.root.ids.mainview.ids.search_field.text = ""
                    self.root.current = "mainview"
                    self.root.transition.direction = "right"
                    self.root.ids.edititem.ids.username_check.md_bg_color = get_color_from_hex("#FAFAFA")  
                    self.root.ids.edititem.ids.password_check.md_bg_color = get_color_from_hex("#FAFAFA") 
                    self.toast_record_deleted()



        def password_page_data(self):
                global timeout_start
                global url_for_id
                global site_ciphertext
                self.timeout_app()
                timeout_start = time.time()

                try:
                    conn = sqlite3.connect("/carrypass_database/master.db")
                    site_data = create_pandas_table("SELECT url, special, max_pass_length FROM logindata ORDER BY oid", conn)
                    list_url = site_data['url'].values.tolist()
                    list_special = site_data['special'].values.tolist()
                    list_max_pass_length = site_data['max_pass_length'].values.tolist()

                    url_index = list_url.index(url_for_id)

                    site_special = list_special[url_index]
                    site_max_pass_length = list_max_pass_length[url_index]


                    if site_special == "yes":
                        self.root.ids.editpassword.ids.special_characters.active = True
                    else:
                        self.root.ids.editpassword.ids.special_characters.active = False
                    
                    self.root.ids.editpassword.ids.pwd_length.text = site_max_pass_length
                except:
                    self.deactivate_with_timeout()




        def change_password_preparation(self):
                global timeout_start
                global url_for_id
                global site_ciphertext
                self.timeout_app()
                timeout_start = time.time()
                web_address = url_for_id

                conn = sqlite3.connect("/carrypass_database/master.db")
                site_data = create_pandas_table("SELECT url, username, salt, variant, pepper, special, created_time, username_img, password_img, ciphertext FROM logindata ORDER BY oid", conn)
                list_url = site_data['url'].values.tolist()
                list_salt = site_data['salt'].values.tolist()

                list_created_time = site_data['created_time'].values.tolist()

                list_ciphertext = site_data["ciphertext"].values.tolist()
                url_index = list_url.index(web_address)
                site_salt = list_salt[url_index]

                site_created_time = list_created_time[url_index]
                site_ciphertext = list_ciphertext[url_index]


                conn.close()
                num_date = re.findall("[1-9]+", site_created_time) 
                joined_date = ''.join(num_date) 
                added_first = int(joined_date[-5:]) 
                added_second = int(joined_date[-10:-5]) 
                datetime_hashed = sha256(site_created_time.encode('ascii')).hexdigest()
                datetime_bytes = bytes(datetime_hashed, 'utf-8')

                key = hashlib.pbkdf2_hmac(
                'sha256', 
                logged_in_or_not[0].encode('utf-8'), 
                site_salt+datetime_bytes,
                iteration_number_one+added_first, 
                dklen=64 
                )
                small_key = hashlib.pbkdf2_hmac(
                'sha256', 
                key, 
                site_salt, 
                iteration_number_two+added_second, 
                dklen=32
                )
                file_in = open(site_ciphertext, "rb")
                nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]


                cipher = AES.new(small_key, AES.MODE_EAX, nonce)
                decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)
                login_key = decrypted_key.decode('UTF-8')

                pyperclip.copy(login_key)

                self.show_password_change_dialog()
                self.show_application()



        def change_password(self):
                global site_ciphertext
                special_is_or_not = self.root.ids.editpassword.ids.special_characters.active
                max_length = int(self.root.ids.editpassword.ids.pwd_length.text)

                if os.path.exists("/carrypass_keys/"+site_ciphertext):
                    if len(site_ciphertext) > 0:
                        os.remove("/carrypass_keys/"+site_ciphertext)
                pyperclip.copy('')
                
                salt = os.urandom(32)
                date_time = datetime.today()
                datetime_created = date_time.strftime("%Y-%m-%d %H:%M:%S.%f")
                num_date = re.findall("[1-9]+", datetime_created) 
                joined_date = ''.join(num_date) 
                added_first = int(joined_date[-5:]) 
                added_second = int(joined_date[-10:-5]) 
                datetime_hashed = sha256(datetime_created.encode('ascii')).hexdigest()
                datetime_bytes = bytes(datetime_hashed, 'utf-8')

                key = hashlib.pbkdf2_hmac(
                'sha256',
                logged_in_or_not[0].encode('utf-8'),
                salt+datetime_bytes,
                iteration_number_one+added_first,
                dklen=64
                )
                small_key = hashlib.pbkdf2_hmac(
                'sha256',
                key, 
                salt,
                iteration_number_two+added_second,
                dklen=32
                )
                if special_is_or_not == True:
                    new_password = get_random_special_password_string(max_length)
                    special = "yes"
                else:
                    new_password = get_random_password_string(max_length)
                    special = "no"


                date_time = datetime.today()
                datetime_clipped = date_time.strftime("%Y-%m-%d")

                split_web_address = urlsplit(url_for_id)
                nickname_from_split = split_web_address.hostname
                nickname = nickname_from_split.replace('www.', '')

                whichis = '_pwd_'
                file_extension = '.bin'
                filename = nickname+whichis+datetime_clipped+file_extension
                folder = '/carrypass_keys/'

                pwd_for_site_login = bytes(new_password, 'utf-8')
                cipher = AES.new(small_key, AES.MODE_EAX)
                ciphertext, tag = cipher.encrypt_and_digest(pwd_for_site_login)

                file_out = open(f"/carrypass_keys/{filename}", "wb")
                [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
                file_out.close()

                ciphertext_file_path = folder+filename

                conn = sqlite3.connect('/carrypass_database/master.db')

                c = conn.cursor()
                c.execute("""UPDATE logindata SET 
                salt = :salt,  
                special = :special, 
                max_pass_length = :max_pass_length, 
                created_time = :created_time, 
                ciphertext = :ciphertext
                WHERE url = :url""",
                {
                    'salt': salt,
                    'special': special,
                    'max_pass_length': max_length,
                    'created_time': datetime_created,
                    'ciphertext': ciphertext_file_path,
                    'url': url_for_id,
                })
                
                conn.commit()

                conn.close()
                pyperclip.copy(new_password)

                self.toast_new_password()




        def set_own_password(self):
                global site_ciphertext
                if self.root.ids.editpassword.ids.ownpassword.text:
                    conn = sqlite3.connect("/carrypass_database/master.db")
                    site_data = create_pandas_table("SELECT url, username, salt, variant, pepper, special, created_time, username_img, password_img, ciphertext FROM logindata ORDER BY oid", conn)
                    list_url = site_data['url'].values.tolist()

                    list_ciphertext = site_data["ciphertext"].values.tolist()
                    url_index = list_url.index(url_for_id)

                    site_ciphertext = list_ciphertext[url_index]

                    conn.close()
                    new_password = self.root.ids.editpassword.ids.ownpassword.text
        
                    if os.path.exists("/carrypass_keys/"+site_ciphertext):
                        if len(site_ciphertext) > 0:
                            os.remove("/carrypass_keys/"+site_ciphertext)
                    pyperclip.copy('')
                    
                    salt = os.urandom(32)
                    date_time = datetime.today()
                    datetime_created = date_time.strftime("%Y-%m-%d %H:%M:%S.%f")
                    num_date = re.findall("[1-9]+", datetime_created) 
                    joined_date = ''.join(num_date) 
                    added_first = int(joined_date[-5:]) 
                    added_second = int(joined_date[-10:-5]) 
                    datetime_hashed = sha256(datetime_created.encode('ascii')).hexdigest()
                    datetime_bytes = bytes(datetime_hashed, 'utf-8')

                    key = hashlib.pbkdf2_hmac(
                    'sha256',
                    logged_in_or_not[0].encode('utf-8'),
                    salt+datetime_bytes,
                    iteration_number_one+added_first,
                    dklen=64
                    )
                    small_key = hashlib.pbkdf2_hmac(
                    'sha256',
                    key, 
                    salt,
                    iteration_number_two+added_second,
                    dklen=32
                    )


                    date_time = datetime.today()
                    datetime_clipped = date_time.strftime("%Y-%m-%d")

                    split_web_address = urlsplit(url_for_id)
                    nickname_from_split = split_web_address.hostname
                    nickname = nickname_from_split.replace('www.', '')

                    whichis = '_pwd_'
                    file_extension = '.bin'
                    filename = nickname+whichis+datetime_clipped+file_extension
                    folder = '/carrypass_keys/'

                    pwd_for_site_login = bytes(new_password, 'utf-8')
                    cipher = AES.new(small_key, AES.MODE_EAX)
                    ciphertext, tag = cipher.encrypt_and_digest(pwd_for_site_login)

                    file_out = open(f"/carrypass_keys/{filename}", "wb")
                    [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
                    file_out.close()

                    ciphertext_file_path = folder+filename

                    conn = sqlite3.connect('/carrypass_database/master.db')

                    c = conn.cursor()
                    c.execute("""UPDATE logindata SET 
                    salt = :salt,
                    created_time = :created_time, 
                    ciphertext = :ciphertext
                    WHERE url = :url""",
                    {
                        'salt': salt,
                        'created_time': datetime_created,
                        'ciphertext': ciphertext_file_path,
                        'url': url_for_id,
                    })
                    
                    conn.commit()

                    conn.close()
                    pyperclip.copy(new_password)

                    self.root.ids.editpassword.ids.ownpassword.text = ""
                    self.toast_new_password()
                else:
                    self.toast_no_empty_password()



        def confirm_login_before_password_change(self):
                global timeout_start
                self.timeout_app()
                timeout_start = time.time()
                self.show_login_before_password_change_dialog()



        def login_before_password_change(self):
                global timeout_start
                self.timeout_app()
                timeout_start = time.time()
                global deciphered_username

                try:
                    site_url = url_for_id
                    self.choose_webbrowser_for_login()

                    time.sleep(3)
                    conn = sqlite3.connect("/carrypass_database/master.db")
                    site_data = create_pandas_table("SELECT url, username, salt, pepper, special, two_page, created_time, username_img, password_img, ciphertext, usn_x_ratio, usn_y_ratio, pwd_x_ratio, pwd_y_ratio, ciphertext_two FROM logindata ORDER BY oid", conn)
                    list_url = site_data['url'].values.tolist()
                    list_salt = site_data['salt'].values.tolist()
                    list_created_time = site_data['created_time'].values.tolist()
                    list_username = site_data["username"].values.tolist()
                    list_pepper = site_data['pepper'].values.tolist()
                    list_ciphertext_two = site_data['ciphertext_two'].values.tolist()
                    list_username_img = site_data["username_img"].values.tolist()
                    list_password_img = site_data["password_img"].values.tolist()
                    list_ciphertext = site_data["ciphertext"].values.tolist()
                    list_two_page = site_data['two_page'].values.tolist()

                    list_usn_x = site_data["usn_x_ratio"].values.tolist()
                    list_usn_y = site_data["usn_y_ratio"].values.tolist()
                    list_pwd_x = site_data["pwd_x_ratio"].values.tolist()
                    list_pwd_y = site_data["pwd_y_ratio"].values.tolist()

                    url_index = list_url.index(site_url)
                    site_salt = list_salt[url_index]
                    site_created_time = list_created_time[url_index]
                    

                    username_stored = list_username[url_index]
                    username_img_stored = list_username_img[url_index]
                    password_img_stored = list_password_img[url_index]
                    site_ciphertext = list_ciphertext[url_index]
                    site_two_page = list_two_page[url_index]

                    site_pepper = list_pepper[url_index]
                    site_ciphertext_two = list_ciphertext_two[url_index]

                    usn_x_rate = list_usn_x[url_index]
                    usn_y_rate = list_usn_y[url_index]
                    pwd_x_rate = list_pwd_x[url_index]
                    pwd_y_rate = list_pwd_y[url_index]

                    conn.close()
                    num_date = re.findall("[1-9]+", site_created_time) 
                    joined_date = ''.join(num_date) 
                    added_first = int(joined_date[-5:]) 
                    added_second = int(joined_date[-10:-5]) 
                    datetime_hashed = sha256(site_created_time.encode('ascii')).hexdigest()
                    datetime_bytes = bytes(datetime_hashed, 'utf-8')

                    key = hashlib.pbkdf2_hmac(
                    'sha256',
                    logged_in_or_not[0].encode('utf-8'),
                    site_salt+datetime_bytes, 
                    iteration_number_one+added_first, 
                    dklen=64 
                    )
                    small_key = hashlib.pbkdf2_hmac(
                    'sha256',
                    key,
                    site_salt,
                    iteration_number_two+added_second,
                    dklen=32
                    )
                    file_in = open(site_ciphertext, "rb")
                    nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

                    cipher = AES.new(small_key, AES.MODE_EAX, nonce)
                    decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)
                    login_key = decrypted_key.decode('UTF-8')

                    key_one = hashlib.pbkdf2_hmac(
                    'sha256',
                    logged_in_or_not[0].encode('utf-8'), 
                    site_pepper,
                    iteration_number_one,
                    dklen=64
                    )
                    small_key_one = hashlib.pbkdf2_hmac(
                    'sha256',
                    key_one,
                    site_pepper,
                    iteration_number_two,
                    dklen=32
                    )


                    file_in = open(site_ciphertext_two, "rb")
                    nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

                    cipher = AES.new(small_key_one, AES.MODE_EAX, nonce)
                    decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)
                    random_text_for_username_otp = decrypted_key.decode('UTF-8')


                    deciphered_username = onetimepad.decrypt(random_text_for_username_otp, username_stored)
                    if site_two_page == 'yes':
                        self.two_page_login()
                    else:	
                        try:
                            pyautogui.hotkey('ctrl', 'l')
                            pyautogui.hotkey('esc')
                            pyautogui.hotkey('win', 'up')
                            pyautogui.hotkey('win', 'up')
                            pyautogui.hotkey('ctrl', '0')
                            screen_width = tk_root.winfo_screenwidth()
                            screen_height = tk_root.winfo_screenheight()
                            usernamelocation = pyautogui.locateOnScreen(f"/carrypass_images/{username_img_stored}", confidence=0.9)

                            pyautogui.moveTo(usernamelocation[0]+10, usernamelocation[1]+10) 

                            pyautogui.click(usernamelocation)
                            pyautogui.doubleClick()
                            pyautogui.press('delete')
                            pyautogui.press('esc')
                            pyperclip.copy(deciphered_username)
                            pyautogui.hotkey("ctrl", "v")
                        
                            time.sleep(0.2)
                            pyautogui.press('esc')
                            pyperclip.copy("")
                            time.sleep(0.2)

                        except:
                            try:
                                pyautogui.click(screen_width/usn_x_rate, screen_height/usn_y_rate)
                                pyautogui.doubleClick()
                                pyautogui.press('delete')
                                pyautogui.press('esc')
                                pyperclip.copy(deciphered_username)
                                pyautogui.hotkey("ctrl", "v")
                            
                                time.sleep(0.2)
                                pyautogui.press('esc')
                                pyperclip.copy("")
                                pyautogui.moveTo(1,1)
                                time.sleep(0.2)
                            except:
                                pass

                        try:

                            passwordlocation = pyautogui.locateOnScreen(f"/carrypass_images/{password_img_stored}", confidence=0.9)

                            pyautogui.moveTo(passwordlocation[0]+10, passwordlocation[1]+10) 

                            pyperclip.copy(login_key)
                            pyautogui.click(passwordlocation)
                            pyautogui.doubleClick()
                            pyautogui.press('delete')
                            pyautogui.press('esc')
                            pyautogui.hotkey("ctrl", "v")
                            pyautogui.press('enter')
                            pyperclip.copy("")
                            self.change_password_preparation()
                        except:
                            try:
                                pyautogui.click(screen_width/pwd_x_rate, screen_height/pwd_y_rate)
                                pyperclip.copy(login_key)
                            
                                pyautogui.doubleClick()
                                pyautogui.press('delete')
                                pyautogui.press('esc')
                                pyautogui.hotkey("ctrl", "v")
                            
                                pyautogui.press('enter')
                                pyperclip.copy("")
                                self.change_password_preparation()
                            except:
                                self.show_no_image_dialog()

                except:
                    self.toast_mac_check_failed()




        def display_password(self):
                global timeout_start
                self.timeout_app()
                timeout_start = time.time()

                try:
                    url_from_entry = url_for_id
                    conn = sqlite3.connect("/carrypass_database/master.db")
                    site_data = create_pandas_table("SELECT url, salt, pepper, created_time, ciphertext FROM logindata ORDER BY oid", conn)
                    list_url = site_data['url'].values.tolist()
                    list_salt = site_data['salt'].values.tolist()
                    list_created_time = site_data['created_time'].values.tolist()
                    list_ciphertext = site_data['ciphertext'].values.tolist()
                    url_index = list_url.index(url_from_entry)
                    site_salt = list_salt[url_index]
                    site_created_time = list_created_time[url_index]
                    site_ciphertext = list_ciphertext[url_index]

                    conn.close()
                    num_date = re.findall("[1-9]+", site_created_time) 
                    joined_date = ''.join(num_date) 
                    added_first = int(joined_date[-5:]) 
                    added_second = int(joined_date[-10:-5]) 
                    datetime_hashed = sha256(site_created_time.encode('ascii')).hexdigest()
                    datetime_bytes = bytes(datetime_hashed, 'utf-8')

                    key = hashlib.pbkdf2_hmac(
                    'sha256',
                    logged_in_or_not[0].encode('utf-8'), 
                    site_salt+datetime_bytes,
                    iteration_number_one+added_first, 
                    dklen=64
                    )
                    small_key = hashlib.pbkdf2_hmac(
                    'sha256', 
                    key, 
                    site_salt,
                    iteration_number_two+added_second, 
                    dklen=32
                    )
                    file_in = open(site_ciphertext, "rb")
                    nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]


                    cipher = AES.new(small_key, AES.MODE_EAX, nonce)
                    decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)
                    login_key = decrypted_key.decode('UTF-8')
                    
                    pyperclip.copy(login_key)
                    self.toast_password_on_clipboard()
                
                except:
                    self.deactivate_with_timeout()





###### NOTES



        def query_notes_database(self):	
            conn = sqlite3.connect('/carrypass_database/master.db')
            c = conn.cursor()

            try:
                records = create_pandas_table("SELECT textone, texttwo FROM notes ORDER BY oid", conn)

                list_textone = records["textone"].values.tolist()
                list_texttwo = records["texttwo"].values.tolist()

                secret_record = list_textone[0]
            

            except:
                c.execute("""INSERT INTO notes (textone, texttwo) VALUES ('Empty notepad', 'Empty notepad')""")


            conn.commit()

            c.close()
            conn.close()




        def create_note_one_at_start(self):
            one_note = ' '

            secret_text_one = get_random_password_string(4096)

            cipher_one = onetimepad.encrypt(one_note, secret_text_one)

            random_text_one_stored = bytes(cipher_one, 'utf-8')

            salt_one = os.urandom(64)

            key_one = hashlib.pbkdf2_hmac(
            'sha256', 
            logged_in_or_not[0].encode('utf-8'), 
            salt_one, 
            iteration_number_one, 
            dklen=64 
            )
            small_key_one = hashlib.pbkdf2_hmac(
            'sha256', 
            key_one, 
            salt_one, 
            iteration_number_two, 
            dklen=32
            )

            nickname_one = 'secretnote_one'
            file_extension = '.bin'
            filename = nickname_one+file_extension

            cipher = AES.new(small_key_one, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(random_text_one_stored)

            file_out = open(f"/carrypass_keys/{filename}", "wb")
            [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
            file_out.close()


            conn = sqlite3.connect('/carrypass_database/master.db')

            c = conn.cursor()

            c.execute("""UPDATE notes SET
                textone = :textone,
                salt_one = :salt_one
                WHERE oid = :oid""",
                {
                    'textone': secret_text_one,
                    'salt_one': salt_one,
                    'oid': 1,
                })


            conn.commit()

            c.close()
            conn.close()




        def create_note_two_at_start(self):
            two_note = ' '

            secret_text_two = get_random_password_string(4096)

            cipher_two = onetimepad.encrypt(two_note, secret_text_two)

            random_text_two_stored = bytes(cipher_two, 'utf-8')

            salt_two = os.urandom(64)

            key_two = hashlib.pbkdf2_hmac(
            'sha256', 
            logged_in_or_not[0].encode('utf-8'), 
            salt_two, 
            iteration_number_one, 
            dklen=64 
            )
            small_key_two = hashlib.pbkdf2_hmac(
            'sha256', 
            key_two, 
            salt_two, 
            iteration_number_two,
            dklen=32
            )

            nickname_two = 'secretnote_two'
            file_extension = '.bin'
            filename = nickname_two+file_extension

            cipher = AES.new(small_key_two, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(random_text_two_stored)

            file_out = open(f"/carrypass_keys/{filename}", "wb")
            [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
            file_out.close()


            conn = sqlite3.connect('/carrypass_database/master.db')

            c = conn.cursor()

            c.execute("""UPDATE notes SET
                texttwo = :texttwo,
                salt_two = :salt_two
                WHERE oid = :oid""",
                {
                    'texttwo': secret_text_two,
                    'salt_two': salt_two,
                    'oid': 1,
                })



            conn.commit()

            c.close()
            conn.close()




        def reveal_secret_text_one(self):

            global secret_note
            secret_note = ''
            global timeout_start
            self.timeout_app()
            timeout_start = time.time()
            try:

                conn = sqlite3.connect("/carrypass_database/master.db")
                site_data = create_pandas_table("SELECT textone, salt_one FROM notes ORDER BY oid", conn)

                list_textone = site_data['textone'].values.tolist()

                list_salt_one = site_data['salt_one'].values.tolist()

                secret_textone = list_textone[0]

                secret_salt_one = list_salt_one[0]

                conn.close()

                key_one = hashlib.pbkdf2_hmac(
                'sha256',
                logged_in_or_not[0].encode('utf-8'), 
                secret_salt_one, 
                iteration_number_one, 
                dklen=64 
                )
                small_key_one = hashlib.pbkdf2_hmac(
                'sha256', 
                key_one, 
                secret_salt_one, 
                iteration_number_two, 
                dklen=32
                )


                file_in = open("/carrypass_keys/secretnote_one.bin", "rb")
                nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

                cipher = AES.new(small_key_one, AES.MODE_EAX, nonce)
                decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)
                random_text_one_for_otp = decrypted_key.decode('UTF-8')


                deciphered_one = onetimepad.decrypt(random_text_one_for_otp, secret_textone)

                self.root.ids.mainview.ids.privatenotes.text = deciphered_one
                self.root.ids.mainview.ids.notestopbar.left_action_items = [["numeric-1-box", lambda x: self.reveal_secret_text_one(), "Open Note 1", "Open Note 1"]]
                self.root.ids.mainview.ids.notestopbar.right_action_items = [["numeric-2-box-outline", lambda x: self.reveal_secret_text_two(), "Open Note 2", "Open Note 2"]]

                secret_note = 'one'
            
            except:
                self.deactivate_with_timeout()



        def reveal_secret_text_two(self):
 
            global secret_note
            secret_note = ''
            global timeout_start
            self.timeout_app()
            timeout_start = time.time()
            try:

                conn = sqlite3.connect("/carrypass_database/master.db")
                site_data = create_pandas_table("SELECT texttwo, salt_two FROM notes ORDER BY oid", conn)

                list_texttwo = site_data['texttwo'].values.tolist()

                list_salt_two = site_data['salt_two'].values.tolist()

                secret_texttwo = list_texttwo[0]

                secret_salt_two = list_salt_two[0]

                conn.close()


                key_two = hashlib.pbkdf2_hmac(
                'sha256',
                logged_in_or_not[0].encode('utf-8'),
                secret_salt_two, 
                iteration_number_one, 
                dklen=64 
                )
                small_key_two = hashlib.pbkdf2_hmac(
                'sha256', 
                key_two, 
                secret_salt_two,
                iteration_number_two,
                dklen=32
                )


                file_in = open("/carrypass_keys/secretnote_two.bin", "rb")
                nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

                cipher = AES.new(small_key_two, AES.MODE_EAX, nonce)
                decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)
                random_text_two_for_otp = decrypted_key.decode('UTF-8')

                deciphered_two = onetimepad.decrypt(random_text_two_for_otp, secret_texttwo)

                self.root.ids.mainview.ids.privatenotes.text = deciphered_two
                self.root.ids.mainview.ids.notestopbar.left_action_items = [["numeric-1-box-outline", lambda x: self.reveal_secret_text_one(), "Open Note 1", "Open Note 1"]]
                self.root.ids.mainview.ids.notestopbar.right_action_items = [["numeric-2-box", lambda x: self.reveal_secret_text_two(), "Open Note 2", "Open Note 2"]]

                secret_note = 'two'
            
            except:
                self.deactivate_with_timeout()




        def store_secret_text_one(self):

            global timeout_start
            global secret_note
            
            self.timeout_app()
            timeout_start = time.time()

            try:
                one_note = self.root.ids.mainview.ids.privatenotes.text
                

                secret_text_one = get_random_password_string(4096)

                cipher_one = onetimepad.encrypt(one_note, secret_text_one)

                random_text_one_stored = bytes(cipher_one, 'utf-8')

                salt_one = os.urandom(64)

                key_one = hashlib.pbkdf2_hmac(
                'sha256', 
                logged_in_or_not[0].encode('utf-8'), 
                salt_one, 
                iteration_number_one, 
                dklen=64 
                )
                small_key_one = hashlib.pbkdf2_hmac(
                'sha256',
                key_one, 
                salt_one, 
                iteration_number_two,
                dklen=32
                )

                nickname_one = 'secretnote_one'
                file_extension = '.bin'
                filename = nickname_one+file_extension

                cipher = AES.new(small_key_one, AES.MODE_EAX)
                ciphertext, tag = cipher.encrypt_and_digest(random_text_one_stored)

                file_out = open(f"/carrypass_keys/{filename}", "wb")
                [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
                file_out.close()


                conn = sqlite3.connect('/carrypass_database/master.db')


                c = conn.cursor()

                c.execute("""UPDATE notes SET
                    textone = :textone,
                    salt_one = :salt_one
                    WHERE oid = :oid""",
                    {
                        'textone': secret_text_one,
                        'salt_one': salt_one,
                        'oid': 1,
                    })
                
                self.root.ids.mainview.ids.privatenotes.text = ""
                self.root.ids.mainview.ids.notestopbar.left_action_items = [["numeric-1-box-outline", lambda x: self.reveal_secret_text_one(), "Open Note 1", "Open Note 1"]]

                secret_note = ""

                conn.commit()

                c.close()
                conn.close()
                self.toast_note_saved()

            except:
                self.deactivate_with_timeout()




        def store_secret_text_two(self):

            global timeout_start
            global secret_note
            
            self.timeout_app()
            timeout_start = time.time()

            try:
                two_note = self.root.ids.mainview.ids.privatenotes.text
                

                secret_text_two = get_random_password_string(4096)

                cipher_two = onetimepad.encrypt(two_note, secret_text_two)

                random_text_two_stored = bytes(cipher_two, 'utf-8')


                salt_two = os.urandom(64)

                key_two = hashlib.pbkdf2_hmac(
                'sha256',
                logged_in_or_not[0].encode('utf-8'), 
                salt_two, 
                iteration_number_one, 
                dklen=64 
                )
                small_key_two = hashlib.pbkdf2_hmac(
                'sha256', 
                key_two, 
                salt_two, 
                iteration_number_two,
                dklen=32
                )

                nickname_two = 'secretnote_two'
                file_extension = '.bin'
                filename = nickname_two+file_extension

                cipher = AES.new(small_key_two, AES.MODE_EAX)
                ciphertext, tag = cipher.encrypt_and_digest(random_text_two_stored)

                file_out = open(f"/carrypass_keys/{filename}", "wb")
                [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
                file_out.close()


                conn = sqlite3.connect('/carrypass_database/master.db')

                c = conn.cursor()

                c.execute("""UPDATE notes SET
                    texttwo = :texttwo,
                    salt_two = :salt_two
                    WHERE oid = :oid""",
                    {
                        'texttwo': secret_text_two,
                        'salt_two': salt_two,
                        'oid': 1,
                    })


                self.root.ids.mainview.ids.privatenotes.text = ""
                self.root.ids.mainview.ids.notestopbar.right_action_items = [["numeric-2-box-outline", lambda x: self.reveal_secret_text_two(), "Open Note 2", "Open Note 2"]]

                secret_note = ""

                conn.commit()

                c.close()
                conn.close()
                self.toast_note_saved()

            except:
                self.deactivate_with_timeout()





        def remove_note_one(self):
            self.root.ids.mainview.ids.notestopbar.right_action_items = [["numeric-2-box-outline", lambda x: self.reveal_secret_text_two(), "Open Note 2", "Open Note 2"]]
            self.root.ids.mainview.ids.notestopbar.left_action_items = [["numeric-1-box-outline", lambda x: self.reveal_secret_text_one(), "Open Note 1", "Open Note 1"]]
            global timeout_start
            global secret_note
            secret_note = ""
            self.timeout_app()
            timeout_start = time.time()

            one_note = ' '

            secret_text_one = get_random_password_string(4096)

            cipher_one = onetimepad.encrypt(one_note, secret_text_one)

            random_text_one_stored = bytes(cipher_one, 'utf-8')

            salt_one = os.urandom(64)

            key_one = hashlib.pbkdf2_hmac(
            'sha256',
            logged_in_or_not[0].encode('utf-8'),
            salt_one,
            iteration_number_one, 
            dklen=64 
            )
            small_key_one = hashlib.pbkdf2_hmac(
            'sha256', 
            key_one, 
            salt_one,
            iteration_number_two,
            dklen=32
            )

            nickname_one = 'secretnote_one'
            file_extension = '.bin'
            filename = nickname_one+file_extension

            cipher = AES.new(small_key_one, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(random_text_one_stored)

            file_out = open(f"/carrypass_keys/{filename}", "wb")
            [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
            file_out.close()


            conn = sqlite3.connect('/carrypass_database/master.db')

            c = conn.cursor()

            c.execute("""UPDATE notes SET
                textone = :textone,
                salt_one = :salt_one
                WHERE oid = :oid""",
                {
                    'textone': secret_text_one,
                    'salt_one': salt_one,
                    'oid': 1,
                })


            conn.commit()

            c.close()
            conn.close()

            self.root.ids.mainview.ids.privatenotes.text = ""

            self.toast_note_deleted()




        def remove_note_two(self):
            self.root.ids.mainview.ids.notestopbar.right_action_items = [["numeric-2-box-outline", lambda x: self.reveal_secret_text_two(), "Open Note 2", "Open Note 2"]]
            self.root.ids.mainview.ids.notestopbar.left_action_items = [["numeric-1-box-outline", lambda x: self.reveal_secret_text_one(), "Open Note 1", "Open Note 1"]]
            global timeout_start
            global secret_note
            secret_note = ""
            self.timeout_app()
            timeout_start = time.time()

            two_note = ' '

            secret_text_two = get_random_password_string(4096)

            cipher_two = onetimepad.encrypt(two_note, secret_text_two)

            random_text_two_stored = bytes(cipher_two, 'utf-8')


            salt_two = os.urandom(64)

            key_two = hashlib.pbkdf2_hmac(
            'sha256',
            logged_in_or_not[0].encode('utf-8'),
            salt_two,
            iteration_number_one,
            dklen=64
            )
            small_key_two = hashlib.pbkdf2_hmac(
            'sha256',
            key_two,
            salt_two,
            iteration_number_two,
            dklen=32
            )

            nickname_two = 'secretnote_two'
            file_extension = '.bin'
            filename = nickname_two+file_extension

            cipher = AES.new(small_key_two, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(random_text_two_stored)

            file_out = open(f"/carrypass_keys/{filename}", "wb")
            [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
            file_out.close()


            conn = sqlite3.connect('/carrypass_database/master.db')

            c = conn.cursor()

            c.execute("""UPDATE notes SET
                texttwo = :texttwo,
                salt_two = :salt_two
                WHERE oid = :oid""",
                {
                    'texttwo': secret_text_two,
                    'salt_two': salt_two,
                    'oid': 1,
                })


            conn.commit()

            c.close()
            conn.close()


            self.root.ids.mainview.ids.privatenotes.text = ""

            self.toast_note_deleted()





        def create_qr_image(self):
            global timeout_start
            self.timeout_app()
            timeout_start = time.time()

            try:
                conn = sqlite3.connect("/carrypass_database/master.db")
                site_data = create_pandas_table("SELECT two_f_a_salt, qr_base FROM twofa_newdevice ORDER BY oid", conn)

                list_two_f_a_salt = site_data['two_f_a_salt'].values.tolist()
                list_qr_base = site_data['qr_base'].values.tolist()


                secret_two_f_a_salt = list_two_f_a_salt[0]
                secret_qr_base = list_qr_base[0]


                conn.close()

                key_one = hashlib.pbkdf2_hmac(
                'sha256', 
                logged_in_or_not[0].encode('utf-8'), 
                secret_two_f_a_salt, 
                iteration_number_one, 
                dklen=64 
                )
                small_key_one = hashlib.pbkdf2_hmac(
                'sha256', 
                key_one, 
                secret_two_f_a_salt, 
                iteration_number_two, 
                dklen=32
                )


                file_in = open("/carrypass_keys/qr_base.bin", "rb")
                nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

                cipher = AES.new(small_key_one, AES.MODE_EAX, nonce)
                decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)
                base_for_otp = decrypted_key.decode('UTF-8')

                deciphered_base = onetimepad.decrypt(base_for_otp, secret_qr_base)


                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_L,
                    box_size=6,
                    border=1,
                )
                qr.add_data(pyotp.totp.TOTP(deciphered_base).provisioning_uri(name='Portable Password Manager', issuer_name='CarryPass'))
                qr.make(fit=True)

                img = qr.make_image(fill_color="black", back_color="white")
                img.save("/carrypass_images/qr_twofa.png")	

                self.root.ids.mainview.ids.qr_image.source = "/carrypass_images/qr_twofa.png"
            except:
                self.deactivate_with_timeout()




        def delete_qr_image(self):
                global timeout_start
                self.timeout_app()
                timeout_start = time.time()
                if os.path.exists("/carrypass_images/qr_twofa.png"):
                    os.remove("/carrypass_images/qr_twofa.png")
                
                self.root.ids.mainview.ids.qr_image.source = 'carrypass_blue.png'




        def save_onedevice_settings(self):
                if int(self.root.ids.devicesettings.ids.trustthisdevice.text) > 29:
                    global timeout
                    global timeout_start
                    global selected_device_id
                    self.timeout_app()
                    timeout_start = time.time()

                    if self.root.ids.devicesettings.ids.twofa_switch.active == True:
                        new_yes_no_value = "yes"
                    else:
                        new_yes_no_value = "no"

                    conn = sqlite3.connect("/carrypass_database/master.db")
                    newdevice_data = create_pandas_table("SELECT two_f_a, two_f_a_salt, time_of_trust FROM twofa_newdevice ORDER BY oid", conn)

                    list_two_f_a_salt = newdevice_data['two_f_a_salt'].values.tolist()

                    secret_two_f_a_salt = list_two_f_a_salt[0]

                    conn.close()

                    if len(logged_in_or_not) < 1:
                        self.deactivate_with_timeout()
                    else:

                        key_one = hashlib.pbkdf2_hmac(
                        'sha256',
                        logged_in_or_not[0].encode('utf-8'), 
                        secret_two_f_a_salt, 
                        iteration_number_one, 
                        dklen=64 
                        )
                        small_key_one = hashlib.pbkdf2_hmac(
                        'sha256', 
                        key_one, 
                        secret_two_f_a_salt, 
                        iteration_number_two,
                        dklen=32
                        )


                        random_secret_for_yesno = get_random_password_string(64)

                        otp_for_twofa_yes_no = onetimepad.encrypt(new_yes_no_value, random_secret_for_yesno) 

                        random_otp_for_time_stored = bytes(otp_for_twofa_yes_no, 'utf-8')


                        stringed_device = str(self.root.ids.devicesettings.ids.devicename.text)
                        alphanum = re.findall('[a-z A-Z 0-9]+', stringed_device)
                        device_name_stripped = ''.join(alphanum)

                        yes_no_file_extension = '.bin'
                        filename_for_yes_no = device_name_stripped+yes_no_file_extension
                        folder_for_yes_no = '/carrypass_keys/'
                        yes_no_file_path = folder_for_yes_no+filename_for_yes_no
                        

                        cipher = AES.new(small_key_one, AES.MODE_EAX)
                        ciphertext, tag = cipher.encrypt_and_digest(random_otp_for_time_stored)

                        file_out = open(yes_no_file_path, "wb")
                        [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
                        file_out.close()


                        conn = sqlite3.connect("/carrypass_database/master.db")

                        c = conn.cursor()

                        c.execute("UPDATE devices SET device_nickname=?, timeoftrust=?, twofa=?, twofa_filename=?  WHERE device_id=?", (self.root.ids.devicesettings.ids.devicetag.text, int(self.root.ids.devicesettings.ids.trustthisdevice.text), random_secret_for_yesno, yes_no_file_path, selected_device_id))
                       
                        conn.commit()

                        c.close()
                        conn.close()

                        timeout = int(self.root.ids.devicesettings.ids.trustthisdevice.text)
                        
                        self.query_login_data()
                        self.list_login_pages()
                        self.list_all_devices()
                        self.toast_changes_saved()
                else:
                    self.toast_less_than_30()
  



        def remove_one_device(self):
                current_device_name = socket.gethostname()
                device_name = self.root.ids.devicesettings.ids.devicename.text
                device_id = selected_device_id
                if current_device_name == device_name:
                    self.toast_cannot_delete_device()
                else:
                    global timeout_start
                    self.timeout_app()
                    timeout_start = time.time()


                    conn = sqlite3.connect('/carrypass_database/master.db')

                    devices_all = create_pandas_table("SELECT device_id, device_nickname, device_name, salt, timeoftrust, twofa, twofa_filename FROM devices ORDER BY oid", conn)
                
                    c = conn.cursor()


                    c.execute("DELETE from devices WHERE device_name=?", (device_name,))
                    
                    conn.commit()

                    conn.close()


                    devices_names_list = []
                    for device in devices_all['device_name']:
                        devices_names_list.append(device)


                    devices_twofa_filename_list = []
                    for twofa_filename in devices_all['twofa_filename']:
                        devices_twofa_filename_list.append(twofa_filename)
                    
                    device_index = devices_names_list.index(device_name)

                    current_twofa_filename = devices_twofa_filename_list[device_index]


                    if os.path.exists(current_twofa_filename):
                        os.remove(current_twofa_filename)
                    else:
                        pass


                    self.list_all_devices()


                    self.toast_device_deleted()

                    self.root.current = "mainview"
                    self.root.transition.direction = "right"





        def open_newdevice_settings(self):
                    global timeout_start
                    self.timeout_app()
                    timeout_start = time.time()
                    try:
                        self.root.current = "futuresettings"
                        self.root.transition.direction = "left"
                        conn = sqlite3.connect("/carrypass_database/master.db")
                        newdevice_data = create_pandas_table("SELECT two_f_a, two_f_a_salt, time_of_trust FROM twofa_newdevice ORDER BY oid", conn)

                        list_two_f_a = newdevice_data['two_f_a'].values.tolist()
                        list_two_f_a_salt = newdevice_data['two_f_a_salt'].values.tolist()
                        list_time_of_trust = newdevice_data['time_of_trust'].values.tolist()


                        secret_two_f_a = list_two_f_a[0]
                        secret_two_f_a_salt = list_two_f_a_salt[0]
                        secret_time_of_trust = list_time_of_trust[0]

                        conn.close()


                        key_one = hashlib.pbkdf2_hmac(
                        'sha256', 
                        logged_in_or_not[0].encode('utf-8'), 
                        secret_two_f_a_salt, 
                        iteration_number_one, 
                        dklen=64 
                        )
                        small_key_one = hashlib.pbkdf2_hmac(
                        'sha256', 
                        key_one, 
                        secret_two_f_a_salt, 
                        iteration_number_two, 
                        dklen=32
                        )


                        file_in = open("/carrypass_keys/newdevice_yesno.bin", "rb")
                        nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

                        
                        cipher = AES.new(small_key_one, AES.MODE_EAX, nonce)
                        decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)
                        base_for_yesno_otp = decrypted_key.decode('UTF-8')

                        deciphered_new_machine_twofa = onetimepad.decrypt(base_for_yesno_otp, secret_two_f_a)

                        
                        file_in = open("/carrypass_keys/time_of_trust.bin", "rb")
                        nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

                        
                        cipher = AES.new(small_key_one, AES.MODE_EAX, nonce)
                        decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)
                        base_for_timeoftrust_otp = decrypted_key.decode('UTF-8')

                        deciphered_new_machine_timeoftrust = onetimepad.decrypt(base_for_timeoftrust_otp, secret_time_of_trust)

                        self.root.ids.futuresettings.ids.timeoftrust.text = deciphered_new_machine_timeoftrust

                        if deciphered_new_machine_twofa == "yes":
                            self.root.ids.futuresettings.ids.twofa_switch.active = True
                        else:
                            self.root.ids.futuresettings.ids.twofa_switch.active = False
                    except:
                        self.deactivate_with_timeout()




        def save_newdevice_settings(self):
                    global timeout_start
                    self.timeout_app()
                    timeout_start = time.time()

                    user_input_time_of_trust = self.root.ids.futuresettings.ids.timeoftrust.text
                    if self.root.ids.futuresettings.ids.twofa_switch.active == True:
                        user_input_twofa_yesno = "yes"
                    else:
                        user_input_twofa_yesno = "no"

                    if len(logged_in_or_not)>0:
                        conn = sqlite3.connect("/carrypass_database/master.db")
                        newdevice_data = create_pandas_table("SELECT two_f_a, two_f_a_salt, time_of_trust FROM twofa_newdevice ORDER BY oid", conn)

                        list_two_f_a = newdevice_data['two_f_a'].values.tolist()
                        list_two_f_a_salt = newdevice_data['two_f_a_salt'].values.tolist()
                        list_time_of_trust = newdevice_data['time_of_trust'].values.tolist()


                        secret_two_f_a = list_two_f_a[0]
                        secret_two_f_a_salt = list_two_f_a_salt[0]
                        secret_time_of_trust = list_time_of_trust[0]

                        conn.close()


                        key_one = hashlib.pbkdf2_hmac(
                        'sha256', 
                        logged_in_or_not[0].encode('utf-8'),
                        secret_two_f_a_salt, 
                        iteration_number_one, 
                        dklen=64 
                        )
                        small_key_one = hashlib.pbkdf2_hmac(
                        'sha256',
                        key_one,
                        secret_two_f_a_salt,
                        iteration_number_two,
                        dklen=32
                        )

                        twofa_yes_no_for_newdevice = user_input_twofa_yesno

                        random_secret_for_yesno = get_random_password_string(64)

                        otp_twofa_yes_no_for_newdevice = onetimepad.encrypt(twofa_yes_no_for_newdevice, random_secret_for_yesno) 

                        random_otp_for_time_stored = bytes(otp_twofa_yes_no_for_newdevice, 'utf-8')


                        newdevice_yes_no_filename = 'newdevice_yesno'
                        yes_no_file_extension = '.bin'
                        filename_for_yes_no = newdevice_yes_no_filename+yes_no_file_extension
                        folder_for_yes_no = '/carrypass_keys/'
                        yes_no_file_path = folder_for_yes_no+filename_for_yes_no

                        cipher = AES.new(small_key_one, AES.MODE_EAX)
                        ciphertext, tag = cipher.encrypt_and_digest(random_otp_for_time_stored)

                        file_out = open(yes_no_file_path, "wb")
                        [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
                        file_out.close()


                        time_of_trust = user_input_time_of_trust

                        random_secret_for_time = get_random_password_string(512)

                        otp_for_time_trust = onetimepad.encrypt(time_of_trust, random_secret_for_time)  

                        random_otp_for_time_stored = bytes(otp_for_time_trust, 'utf-8')

                        qr_base_filename = 'time_of_trust'
                        qr_base_file_extension = '.bin'
                        filename_for_qr_base = qr_base_filename+qr_base_file_extension
                        folder_for_qr_base = '/carrypass_keys/'
                        qr_base_file_path = folder_for_qr_base+filename_for_qr_base
                        

                        cipher = AES.new(small_key_one, AES.MODE_EAX)
                        ciphertext, tag = cipher.encrypt_and_digest(random_otp_for_time_stored)

                        file_out = open(qr_base_file_path, "wb")
                        [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
                        file_out.close()


                        conn = sqlite3.connect('/carrypass_database/master.db')

                        c = conn.cursor()

                        c.execute("""UPDATE twofa_newdevice SET
                        two_f_a = :two_f_a,
                        time_of_trust = :time_of_trust
                        WHERE oid = :oid""",
                        {
                            'two_f_a': random_secret_for_yesno,
                            'time_of_trust': random_secret_for_time,
                            'oid': 1,
                        })

                        conn.commit()
                        c.close()

                        conn.close()

                        self.toast_changes_saved()
                    else:
                        self.deactivate_with_timeout()




        def deny_all_newdevices(self):
                    global timeout_start
                    self.timeout_app()
                    timeout_start = time.time()

                    user_input_time_of_trust = "0"
                    
                    user_input_twofa_yesno = "yes"

                    if len(logged_in_or_not)>0:

                        conn = sqlite3.connect("/carrypass_database/master.db")
                        newdevice_data = create_pandas_table("SELECT two_f_a, two_f_a_salt, time_of_trust FROM twofa_newdevice ORDER BY oid", conn)

                        list_two_f_a = newdevice_data['two_f_a'].values.tolist()
                        list_two_f_a_salt = newdevice_data['two_f_a_salt'].values.tolist()
                        list_time_of_trust = newdevice_data['time_of_trust'].values.tolist()


                        secret_two_f_a = list_two_f_a[0]
                        secret_two_f_a_salt = list_two_f_a_salt[0]
                        secret_time_of_trust = list_time_of_trust[0]

                        conn.close()


                        key_one = hashlib.pbkdf2_hmac(
                        'sha256', 
                        logged_in_or_not[0].encode('utf-8'), 
                        secret_two_f_a_salt, 
                        iteration_number_one, 
                        dklen=64
                        )
                        small_key_one = hashlib.pbkdf2_hmac(
                        'sha256', 
                        key_one, 
                        secret_two_f_a_salt, 
                        iteration_number_two, 
                        dklen=32
                        )

                        twofa_yes_no_for_newdevice = user_input_twofa_yesno

                        random_secret_for_yesno = get_random_password_string(64)

                        otp_twofa_yes_no_for_newdevice = onetimepad.encrypt(twofa_yes_no_for_newdevice, random_secret_for_yesno) 

                        random_otp_for_time_stored = bytes(otp_twofa_yes_no_for_newdevice, 'utf-8')


                        newdevice_yes_no_filename = 'newdevice_yesno'
                        yes_no_file_extension = '.bin'
                        filename_for_yes_no = newdevice_yes_no_filename+yes_no_file_extension
                        folder_for_yes_no = '/carrypass_keys/'
                        yes_no_file_path = folder_for_yes_no+filename_for_yes_no

                        cipher = AES.new(small_key_one, AES.MODE_EAX)
                        ciphertext, tag = cipher.encrypt_and_digest(random_otp_for_time_stored)

                        file_out = open(yes_no_file_path, "wb")
                        [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
                        file_out.close()


                        time_of_trust = user_input_time_of_trust

                        random_secret_for_time = get_random_password_string(512)

                        otp_for_time_trust = onetimepad.encrypt(time_of_trust, random_secret_for_time)

                        random_otp_for_time_stored = bytes(otp_for_time_trust, 'utf-8')

                        qr_base_filename = 'time_of_trust'
                        qr_base_file_extension = '.bin'
                        filename_for_qr_base = qr_base_filename+qr_base_file_extension
                        folder_for_qr_base = '/carrypass_keys/'
                        qr_base_file_path = folder_for_qr_base+filename_for_qr_base
                        

                        cipher = AES.new(small_key_one, AES.MODE_EAX)
                        ciphertext, tag = cipher.encrypt_and_digest(random_otp_for_time_stored)

                        file_out = open(qr_base_file_path, "wb")
                        [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
                        file_out.close()

                    
                        conn = sqlite3.connect('/carrypass_database/master.db')

                    
                        c = conn.cursor()

                        c.execute("""UPDATE twofa_newdevice SET
                        two_f_a = :two_f_a,
                        time_of_trust = :time_of_trust
                        WHERE oid = :oid""",
                        {
                            'two_f_a': random_secret_for_yesno,
                            'time_of_trust': random_secret_for_time,
                            'oid': 1,
                        })

                        conn.commit()
                        c.close()

                        conn.close()


                        self.root.ids.futuresettings.ids.timeoftrust.text = "0"
                        self.root.ids.futuresettings.ids.twofa_switch.active = True

                        self.toast_changes_saved()
                    else:
                        self.deactivate_with_timeout()



        def restore_onedevice_settings_to_factory(self):
                global timeout
                global timeout_start
                global selected_device_id
                self.timeout_app()
                timeout_start = time.time()
                
                new_yes_no_value = "no"

                conn = sqlite3.connect("/carrypass_database/master.db")
                newdevice_data = create_pandas_table("SELECT two_f_a, two_f_a_salt, time_of_trust FROM twofa_newdevice ORDER BY oid", conn)

                list_two_f_a_salt = newdevice_data['two_f_a_salt'].values.tolist()

                secret_two_f_a_salt = list_two_f_a_salt[0]

                conn.close()


                key_one = hashlib.pbkdf2_hmac(
                'sha256',
                logged_in_or_not[0].encode('utf-8'),
                secret_two_f_a_salt,
                iteration_number_one,
                dklen=64 
                )
                small_key_one = hashlib.pbkdf2_hmac(
                'sha256', 
                key_one, 
                secret_two_f_a_salt, 
                iteration_number_two, 
                dklen=32
                )


                random_secret_for_yesno = get_random_password_string(64)

                otp_for_twofa_yes_no = onetimepad.encrypt(new_yes_no_value, random_secret_for_yesno)

                random_otp_for_time_stored = bytes(otp_for_twofa_yes_no, 'utf-8')


                stringed_device = str(self.root.ids.devicesettings.ids.devicename.text)
                alphanum = re.findall('[a-z A-Z 0-9]+', stringed_device)
                device_name_stripped = ''.join(alphanum)

                yes_no_file_extension = '.bin'
                filename_for_yes_no = device_name_stripped+yes_no_file_extension
                folder_for_yes_no = '/carrypass_keys/'
                yes_no_file_path = folder_for_yes_no+filename_for_yes_no
                

                cipher = AES.new(small_key_one, AES.MODE_EAX)
                ciphertext, tag = cipher.encrypt_and_digest(random_otp_for_time_stored)

                file_out = open(yes_no_file_path, "wb")
                [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
                file_out.close()


                conn = sqlite3.connect("/carrypass_database/master.db")

                c = conn.cursor()

                c.execute("UPDATE devices SET device_nickname=?, timeoftrust=?, twofa=?, twofa_filename=?  WHERE device_id=?", (self.root.ids.devicesettings.ids.devicetag.text, 28800, random_secret_for_yesno, yes_no_file_path, selected_device_id))

                
                conn.commit()

                c.close()
                conn.close()

                timeout = 28800

                self.root.ids.devicesettings.ids.trustthisdevice.text = "28800"
                self.root.ids.devicesettings.ids.twofa_switch.active = False
                
                self.query_login_data()
                self.list_login_pages()
                self.list_all_devices()
                self.toast_changes_saved()
    





        def new_machine(self):
                    conn = sqlite3.connect("/carrypass_database/master.db")
                    newdevice_data = create_pandas_table("SELECT two_f_a, two_f_a_salt, time_of_trust FROM twofa_newdevice ORDER BY oid", conn)

                    list_two_f_a = newdevice_data['two_f_a'].values.tolist()
                    list_two_f_a_salt = newdevice_data['two_f_a_salt'].values.tolist()
                    list_time_of_trust = newdevice_data['time_of_trust'].values.tolist()


                    secret_two_f_a = list_two_f_a[0]
                    secret_two_f_a_salt = list_two_f_a_salt[0]
                    secret_time_of_trust = list_time_of_trust[0]

                    conn.close()

                    device_name = socket.gethostname()
                    device_id = uuid.getnode()

                    device_identifier = str(device_id)+device_name

                    device_id_one = hashlib.pbkdf2_hmac(
                    'sha256', 
                    device_identifier.encode('utf-8'),
                    secret_two_f_a_salt, 
                    10000, 
                    dklen=64 
                    )
                    device_id_hashed = hashlib.pbkdf2_hmac(
                    'sha256', 
                    device_id_one, 
                    secret_two_f_a_salt, 
                    5000, 
                    dklen=32
                    )


                    key_one = hashlib.pbkdf2_hmac(
                    'sha256',
                    logged_in_or_not[0].encode('utf-8'),
                    secret_two_f_a_salt, 
                    iteration_number_one, 
                    dklen=64 
                    )
                    small_key_one = hashlib.pbkdf2_hmac(
                    'sha256',
                    key_one,
                    secret_two_f_a_salt,
                    iteration_number_two,
                    dklen=32
                    )

                    file_in = open("/carrypass_keys/newdevice_yesno.bin", "rb")
                    nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

                    cipher = AES.new(small_key_one, AES.MODE_EAX, nonce)
                    decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)
                    base_for_yesno_otp = decrypted_key.decode('UTF-8')

                    deciphered_new_machine_twofa = onetimepad.decrypt(base_for_yesno_otp, secret_two_f_a)


                    file_in = open("/carrypass_keys/time_of_trust.bin", "rb")
                    nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]


                    cipher = AES.new(small_key_one, AES.MODE_EAX, nonce)
                    decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)
                    base_for_timeoftrust_otp = decrypted_key.decode('UTF-8')

                    deciphered_new_machine_timeoftrust = onetimepad.decrypt(base_for_timeoftrust_otp, secret_time_of_trust)


                    random_secret_for_yesno = get_random_password_string(64)

                    otp_for_new_device_twofa_yes_no = onetimepad.encrypt(deciphered_new_machine_twofa, random_secret_for_yesno)

                    random_otp_for_time_stored = bytes(otp_for_new_device_twofa_yes_no, 'utf-8')

                    stringed_device = str(device_name)
                    alphanum = re.findall('[a-z A-Z 0-9]+', stringed_device)
                    device_name_stripped = ''.join(alphanum)


                    yes_no_file_extension = '.bin'
                    filename_for_yes_no = device_name_stripped+yes_no_file_extension
                    folder_for_yes_no = '/carrypass_keys/'
                    new_yes_no_file_path = folder_for_yes_no+filename_for_yes_no
                    

                    cipher = AES.new(small_key_one, AES.MODE_EAX)
                    ciphertext, tag = cipher.encrypt_and_digest(random_otp_for_time_stored)

                    file_out = open(new_yes_no_file_path, "wb")
                    [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
                    file_out.close()


                    conn = sqlite3.connect("/carrypass_database/master.db")
                    c = conn.cursor()
                    c.execute("INSERT INTO devices VALUES (:device_id, :device_nickname, :device_name, :salt, :timeoftrust, :twofa, :twofa_filename)",
                    {
                        'device_id': device_id_hashed,
                        'device_nickname': 'device tag',
                        'device_name': device_name,
                        'salt': secret_two_f_a_salt,
                        'timeoftrust': deciphered_new_machine_timeoftrust,
                        'twofa': random_secret_for_yesno,
                        'twofa_filename': new_yes_no_file_path,
                    })
                    
                    conn.commit()
                    c.close()
                
                    conn.close()


                    self.one_time_password()




        def release_one_time_pass(self):
            global timeout_start
            global timeout
            self.timeout_app()
            timeout_start = time.time()
            
            conn = sqlite3.connect("/carrypass_database/master.db")
            site_data = create_pandas_table("SELECT two_f_a_salt, qr_base FROM twofa_newdevice ORDER BY oid", conn)

            list_two_f_a_salt = site_data['two_f_a_salt'].values.tolist()
            list_qr_base = site_data['qr_base'].values.tolist()


            secret_two_f_a_salt = list_two_f_a_salt[0]
            secret_qr_base = list_qr_base[0]


            conn.close()

            if len(logged_in_or_not) < 1:
                self.deactivate_with_timeout()
            else:
                key_one = hashlib.pbkdf2_hmac(
                'sha256',
                logged_in_or_not[0].encode('utf-8'),
                secret_two_f_a_salt, 
                iteration_number_one, 
                dklen=64 
                )
                small_key_one = hashlib.pbkdf2_hmac(
                'sha256', 
                key_one, 
                secret_two_f_a_salt, 
                iteration_number_two, 
                dklen=32
                )


                file_in = open("/carrypass_keys/qr_base.bin", "rb")
                nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

                cipher = AES.new(small_key_one, AES.MODE_EAX, nonce)
                decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)
                base_for_otp = decrypted_key.decode('UTF-8')

                deciphered_base = onetimepad.decrypt(base_for_otp, secret_qr_base)
                totp = pyotp.TOTP(deciphered_base)
                global onetime_login

                otp_start = self.root.ids.otplogin.ids.onetimepass.text


                if otp_start == str(totp.now()):
                    self.root.current = "mainview"
                    self.root.transition.direction = "up"
                    self.root.ids.otplogin.ids.onetimepass.text = ""

                else:
                    self.root.ids.otplogin.ids.onetimepass.text = ""
                    self.deactivate()
                    self.toast_incorrect_totp()




        def have_i_been_pawned(self):
                global timeout_start
                self.timeout_app()
                timeout_start = time.time()
                try:
                    conn = sqlite3.connect("/carrypass_database/master.db")
                    site_data = create_pandas_table("SELECT nickname, url, username, salt, variant, pepper, special, created_time, username_img, password_img, ciphertext FROM logindata ORDER BY oid", conn)

                    list_nick = site_data['nickname'].values.tolist()
                    list_url = site_data['url'].values.tolist()
                    list_salt = site_data['salt'].values.tolist()

                    list_created_time = site_data['created_time'].values.tolist()

                    list_ciphertext = site_data["ciphertext"].values.tolist()

                    conn.close()

                    pwnd = 0

                    list_of_pwned_nicknames = []
                    list_of_pwned_urls = []

                    for pwnd_url in list_url:

                        num_date = re.findall("[1-9]+", list_created_time[pwnd]) 
                        joined_date = ''.join(num_date) 
                        added_first = int(joined_date[-5:]) 
                        added_second = int(joined_date[-10:-5]) 
                        datetime_hashed = sha256(list_created_time[pwnd].encode('ascii')).hexdigest()
                        datetime_bytes = bytes(datetime_hashed, 'utf-8')

                        key = hashlib.pbkdf2_hmac(
                        'sha256',
                        logged_in_or_not[0].encode('utf-8'), 
                        list_salt[pwnd]+datetime_bytes, 
                        iteration_number_one+added_first, 
                        dklen=64 
                        )
                        small_key = hashlib.pbkdf2_hmac(
                        'sha256', 
                        key, 
                        list_salt[pwnd], 
                        iteration_number_two+added_second, 
                        dklen=32
                        )
                        file_in = open(list_ciphertext[pwnd], "rb")
                        nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

                        cipher = AES.new(small_key, AES.MODE_EAX, nonce)
                        decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)
                        login_key = decrypted_key.decode('UTF-8')


                        try:
                            if pwnedpasswords.check(login_key):
                                list_of_pwned_urls.append(list_url[pwnd])
                                list_of_pwned_nicknames.append(list_nick[pwnd])

                        except:
                            if pwnedpasswords.check(login_key, anonymous=False):
                                list_of_pwned_urls.append(list_url[pwnd])
                                list_of_pwned_nicknames.append(list_nick[pwnd]) 


                        pwnd += 1
            


                    def add_each_loginpage(nick, url):
                        self.root.ids.mainview.ids.rv_url.data.append(
                            {
                                "viewclass": "TwoLineListItem",
                                "text": nick,
                                "secondary_text": url,
                                "theme_text_color": 'Custom',
                                "text_color": get_color_from_hex("#ff0000"),
                                "on_press": lambda x=nick, y=url: self.edit_item(x, y),
                            }
                        )

                    self.root.ids.mainview.ids.rv_url.data = []

                    list_number = 0

                    for item in list_of_pwned_urls:
                        add_each_loginpage(list_of_pwned_nicknames[list_number], list_of_pwned_urls[list_number])
                        list_number += 1
                

                except:
                    self.toast_no_internet()






        def show_isecure_site_dialog(self):
            if not self.insecure_dialog:
                self.insecure_dialog = MDDialog(
                    title="Insecure connection - HTTP",
                    text="This is not a secure connection. Others may see your password and username. Do you want to attempt login through this connection ?",
                    auto_dismiss = False,
                    buttons=[
                        MDFlatButton(
                            text="CANCEL",
                            theme_text_color="Custom",
                            text_color=self.theme_cls.primary_color,
                            on_press = lambda *args: self.insecure_dialog.dismiss(),
                            
                        ),
                        MDFlatButton(
                            text="OK",
                            theme_text_color="Custom",
                            text_color=self.theme_cls.primary_color,
                            on_press = lambda *args: self.insecure_dialog.dismiss(),
                            on_release = lambda x: self.launch_robot(),
                            
                            
                        ),
                    ],
                )
            self.insecure_dialog.open()





        def show_unclear_site_dialog(self):
            if not self.unclear_dialog:
                self.unclear_dialog = MDDialog(
                    title="website URL unclear",
                    text="The URL is unclear and the window may not be a webbrowser at all. If you trust the connection you may continue. Do you want to attempt login through this connection ?",
                    auto_dismiss = False,
                    buttons=[
                        MDFlatButton(
                            text="CANCEL",
                            theme_text_color="Custom",
                            text_color=self.theme_cls.primary_color,
                            on_press = lambda *args: self.unclear_dialog.dismiss(),
                            
                        ),
                        MDFlatButton(
                            text="OK",
                            theme_text_color="Custom",
                            text_color=self.theme_cls.primary_color,
                            on_press = lambda *args: self.unclear_dialog.dismiss(),
                            on_release = lambda x: self.launch_robot(),
                            
                            
                        ),
                    ],
                )
            self.unclear_dialog.open()





        def show_isecure_site_openlogin_dialog(self):
            if not self.insecure_dialog:
                self.insecure_dialog = MDDialog(
                    title="Insecure connection - HTTP",
                    text="This is not a secure connection. Others may see your password and username. Do you want to attempt login through this connection ?",
                    auto_dismiss = False,
                    buttons=[
                        MDFlatButton(
                            text="CANCEL",
                            theme_text_color="Custom",
                            text_color=self.theme_cls.primary_color,
                            on_press = lambda *args: self.insecure_dialog.dismiss(),
                            
                        ),
                        MDFlatButton(
                            text="OK",
                            theme_text_color="Custom",
                            text_color=self.theme_cls.primary_color,
                            on_press = lambda *args: self.insecure_dialog.dismiss(),
                            on_release = lambda x: self.open_and_login(),
                            
                            
                        ),
                    ],
                )
            self.insecure_dialog.open()




        def show_unclear_site_openlogin_dialog(self):
            if not self.unclear_dialog:
                self.unclear_dialog = MDDialog(
                    title="website URL unclear",
                    text="The URL is unclear and the window may not be a webbrowser at all. If you trust the connection you may continue. Do you want to attempt login through this connection ?",
                    auto_dismiss = False,
                    buttons=[
                        MDFlatButton(
                            text="CANCEL",
                            theme_text_color="Custom",
                            text_color=self.theme_cls.primary_color,
                            on_press = lambda *args: self.unclear_dialog.dismiss(),
                            
                        ),
                        MDFlatButton(
                            text="OK",
                            theme_text_color="Custom",
                            text_color=self.theme_cls.primary_color,
                            on_press = lambda *args: self.unclear_dialog.dismiss(),
                            on_release = lambda x: self.open_and_login(),
                            
                            
                        ),
                    ],
                )
            self.unclear_dialog.open()




        def show_no_image_dialog(self):
            if not self.no_image_dialog:
                self.no_image_dialog = MDDialog(
                    title="No images for this site",
                    text="No images could be found for this page. Select the page from My Pages and add the images for the username location and password location.",
                    auto_dismiss = False,
                    buttons=[
                        MDFlatButton(
                            text="OK",
                            theme_text_color="Custom",
                            text_color=self.theme_cls.primary_color,
                            on_release = lambda *args: self.no_image_dialog.dismiss(),
                            
                            
                        ),
                    ],
                )
            self.no_image_dialog.open()




        def show_application_startup_dialog(self):
            if not self.application_startup:
                self.application_startup = MDDialog(
                    title="Master User has been created",
                    text="To complete the initialisation process, restart the application.",
                    auto_dismiss = False,
                    buttons=[
                        MDFlatButton(
                            text="OK",
                            theme_text_color="Custom",
                            text_color=self.theme_cls.primary_color,
                            on_press = lambda *args: self.application_startup.dismiss(),
                            on_release = lambda x: self.application_shutdown(),
                            
                            
                        ),
                    ],
                )
            self.application_startup.open()




        def show_save_usn_img_dialog(self):
            if not self.save_usn_image_dialog:
                self.save_usn_image_dialog = MDDialog(
                    title="Captured username image?",
                    text="Are you satisfied with the captured image of the username entry?",
                    auto_dismiss = False,
                    buttons=[
                        MDFlatButton(
                            text="NO",
                            theme_text_color="Custom",
                            text_color=self.theme_cls.primary_color,
                            on_release = lambda *args: self.save_usn_image_dialog.dismiss(),
                            
                        ),
                        MDFlatButton(
                            text="YES",
                            theme_text_color="Custom",
                            text_color=self.theme_cls.primary_color,
                            on_press = lambda *args: self.save_usn_image_dialog.dismiss(),
                            on_release = lambda x: self.save_username_image(),
                            
                            
                        ),
                    ],
                )
            self.save_usn_image_dialog.open()




        def show_save_pwd_img_dialog(self):
            if not self.save_pwd_image_dialog:
                self.save_pwd_image_dialog = MDDialog(
                    title="Captured password image?",
                    text="Are you satisfied with the captured image of the password entry?",
                    auto_dismiss = False,
                    buttons=[
                        MDFlatButton(
                            text="NO",
                            theme_text_color="Custom",
                            text_color=self.theme_cls.primary_color,
                            on_release = lambda *args: self.save_pwd_image_dialog.dismiss(),
                            
                        ),
                        MDFlatButton(
                            text="YES",
                            theme_text_color="Custom",
                            text_color=self.theme_cls.primary_color,
                            on_press = lambda *args: self.save_pwd_image_dialog.dismiss(),
                            on_release = lambda x: self.save_password_image(),
                            
                            
                        ),
                    ],
                )
            self.save_pwd_image_dialog.open()





        def show_delete_record_dialog(self):
            global timeout_start
            self.timeout_app()
            timeout_start = time.time()
            if len(logged_in_or_not)>0:
                if not self.delete_record_dialog:
                    self.delete_record_dialog = MDDialog(
                        title="Delete record?",
                        text="Deleting a record is permanent. Do you want to continue?",
                        auto_dismiss = False,
                        buttons=[
                            MDFlatButton(
                                text="CANCEL",
                                theme_text_color="Custom",
                                text_color=self.theme_cls.primary_color,
                                on_release = lambda *args: self.delete_record_dialog.dismiss(),
                                
                            ),
                            MDFlatButton(
                                text="DELETE",
                                theme_text_color="Custom",
                                text_color=self.theme_cls.primary_color,
                                on_press = lambda x: self.remove_one(),
                                on_release = lambda *args: self.delete_record_dialog.dismiss(),
                                
                                
                            ),
                        ],
                    )
                self.delete_record_dialog.open()
            else:
                self.deactivate_with_timeout()





        def show_delete_note_one_dialog(self):
            if not self.delete_noteone_dialog:
                self.delete_noteone_dialog = MDDialog(
                    title="Delete note one?",
                    text="Deleting a note is permanent. Do you want to continue?",
                    auto_dismiss = False,
                    buttons=[
                        MDFlatButton(
                            text="CANCEL",
                            theme_text_color="Custom",
                            text_color=self.theme_cls.primary_color,
                            on_release = lambda *args: self.delete_noteone_dialog.dismiss(),
                            
                        ),
                        MDFlatButton(
                            text="DELETE",
                            theme_text_color="Custom",
                            text_color=self.theme_cls.primary_color,
                            on_press = lambda x: self.remove_note_one(),
                            on_release = lambda *args: self.delete_noteone_dialog.dismiss(),
                            
                            
                        ),
                    ],
                )
            self.delete_noteone_dialog.open()





        def show_delete_note_two_dialog(self):
            if not self.delete_notetwo_dialog:
                self.delete_notetwo_dialog = MDDialog(
                    title="Delete note two?",
                    text="Deleting a note is permanent. Do you want to continue?",
                    auto_dismiss = False,
                    buttons=[
                        MDFlatButton(
                            text="CANCEL",
                            theme_text_color="Custom",
                            text_color=self.theme_cls.primary_color,
                            on_release = lambda *args: self.delete_notetwo_dialog.dismiss(),
                            
                        ),
                        MDFlatButton(
                            text="DELETE",
                            theme_text_color="Custom",
                            text_color=self.theme_cls.primary_color,
                            on_press = lambda x: self.remove_note_two(),
                            on_release = lambda *args: self.delete_notetwo_dialog.dismiss(),
                            
                            
                        ),
                    ],
                )
            self.delete_notetwo_dialog.open()





        def show_delete_device_dialog(self):
            global timeout_start
            self.timeout_app()
            timeout_start = time.time()
            if len(logged_in_or_not)>0:
                if not self.delete_device_dialog:
                    self.delete_device_dialog = MDDialog(
                        title="Delete device?",
                        text="Deleting a device and its settings is permanent. Do you want to continue?",
                        auto_dismiss = False,
                        buttons=[
                            MDFlatButton(
                                text="CANCEL",
                                theme_text_color="Custom",
                                text_color=self.theme_cls.primary_color,
                                on_release = lambda *args: self.delete_device_dialog.dismiss(),
                                
                            ),
                            MDFlatButton(
                                text="DELETE",
                                theme_text_color="Custom",
                                text_color=self.theme_cls.primary_color,
                                on_press = lambda x: self.remove_one_device(),
                                on_release = lambda *args: self.delete_device_dialog.dismiss(),
                                
                                
                            ),
                        ],
                    )
                self.delete_device_dialog.open()
            else:
                self.deactivate_with_timeout()






        def show_password_change_dialog(self):
            if not self.password_change_dialog:
                self.password_change_dialog = MDDialog(
                    title="Ready to change the password?",
                    text="You should be logged into the site before you continue. Your old password is copied to the clipboard, so you may paste it where it is required. When you click YES your old password will be lost permanently. Do you wish to continue ?",
                    auto_dismiss = False,
                    buttons=[
                        MDFlatButton(
                            text="CANCEL",
                            theme_text_color="Custom",
                            text_color=self.theme_cls.primary_color,
                            on_release = lambda *args: self.password_change_dialog.dismiss(),
                            
                        ),
                        MDFlatButton(
                            text="YES",
                            theme_text_color="Custom",
                            text_color=self.theme_cls.primary_color,
                            on_press = lambda *args: self.password_change_dialog.dismiss(),
                            on_release = lambda x: self.change_password(),
                            
                            
                        ),
                    ],
                )
            self.password_change_dialog.open()




        def show_login_before_password_change_dialog(self):
            if not self.login_before_passwordchange:
                self.login_before_passwordchange = MDDialog(
                    title="Attempt login?",
                    text="You should be logged into the site before you continue. Would you like CarryPass to attempt login ?",
                    auto_dismiss = False,
                    buttons=[
                        MDFlatButton(
                            text="NO",
                            theme_text_color="Custom",
                            text_color=self.theme_cls.primary_color,
                            on_press = lambda *args: self.login_before_passwordchange.dismiss(),
                            on_release = lambda x: self.change_password_preparation(),
                            
                        ),
                        MDFlatButton(
                            text="YES",
                            theme_text_color="Custom",
                            text_color=self.theme_cls.primary_color,
                            on_press = lambda *args: self.login_before_passwordchange.dismiss(),
                            on_release = lambda x: self.login_before_password_change(),
                            
                            
                        ),
                    ],
                )
            self.login_before_passwordchange.open()

            



        def show_toast(self):
            toast('Test Kivy Toast')


        def toast_finished_login(self):
            toast('Finished login attempt')


        def toast_image_saved(self):
            toast('Image saved')


        def toast_changes_saved(self):
            toast('Changes saved')


        def toast_new_page_added(self):
            toast('Login page added to records')


        def toast_new_app_added(self):
            toast('Application added to records')


        def toast_cannot_open_browser(self):
            toast('Cannot open selected browser')


        def toast_mac_check_failed(self):
            toast('MAC check failed')


        def toast_login_failed(self):
            toast('Login attempt failed')


        def toast_not_browser(self):
            toast('This is not a browser window')


        def toast_choose_browser(self):
            toast('Browser type cannot be empty')


        def toast_record_already_exist(self):
            toast('This page already exists in records')


        def toast_record_deleted(self):
            toast('Record deleted')


        def toast_new_password(self):
            toast('New password is on the clipboard')


        def toast_no_image_found(self):
            toast('No entry box image found')


        def toast_password_on_clipboard(self):
            toast('The password is copied to the clipboard')



        def toast_no_empty_password(self):
            toast('The password field cannot be empty')



        def toast_image_validation_failed(self):
            toast('Image validation failed. Try again.')


        def toast_processing_request(self):
            toast('Processing request ...')


        def toast_note_saved(self):
            toast('Note saved')


        def toast_note_deleted(self):
            toast('Note deleted')


        def toast_open_a_note(self):
            toast('Open one of the notes first')


        def toast_less_than_30(self):
            toast("An existing device's time of trust cannot be less than 30 seconds")


        def toast_cannot_delete_device(self):
            toast('Current device cannot be deleted from records')


        def toast_device_deleted(self):
            toast('Device deleted')


        def toast_incorrect_totp(self):
            toast('One Time Password is incorrect')


        def toast_no_internet(self):
            toast('No internet connection')



if __name__ == '__main__':
        if hasattr(sys, '_MEIPASS'):
            resource_add_path(os.path.join(sys._MEIPASS))
        CarryPassApp().run()
