# CarryPass

CarryPass is the offline password manager with 256-bit AES encryption and time-based one time password as a second factor of authentication for those who appreciate privacy.

<p align="center">
<img src="https://github.com/racz-zoltan/carrypass/blob/main/carrypass_demo_image.png">
</p>


## Installation

Exctract the files to a USB storage device, and launch the CarryPass.exe application.
The application creates three folders in the root folder of your device:

1. carrypass_database
2. carrypass_images
3. carrypass_keys

#### carrypass_database

The folder contains the database in a single file format on the device. The database is not encrypted.

#### carrypass_images

The folder contains the images needed for login automation. No browser extension or plug-in is required for login automation as CarryPass manages the login process on the screen.

#### carrypass_keys

The folder contains the encrypted usernames, passwords, master password, private notes and 2FA settings of the application.

## Usage

### Home Screen

You can add login page URLs and desktop applications with login credentials, generate strong passwords for each, and check if any of your passwords have been pawned (previously exposed in data breaches).

### Private Notes

You can write private notes that are also encrypted with AES.

### Trust Settings

You can scale trust across your devices. Depending on how much you trust each device where you use CarryPass, 
you can control idle timeout of the application, or require time-based one time password for login.

You can also control future devices, that will only be connected with the application later. You can control
the behaviour of the application in relation with that future device; how long idle timeout should be, or whether to require
a second factor of authentication for login or not.


## Videos





