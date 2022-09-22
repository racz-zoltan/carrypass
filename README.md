# CarryPass

CarryPass is the offline password manager with 256-bit AES encryption and time-based one time password for those who appreciate privacy.

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


## Two factor authentication

> Besides using it for the application, you should always consider setting up two factor authentication for every site you register with if there is such an option.

## Backups

> You are encouraged to make regular backups of the 'carrypass_' folders.

## No data recovery

> If you forget the master password, or in case 2FA is set up for the application and the one time password is not available for any reason, there is no way to recover data stored by the application.

## Internet connection

> Only pwned password check needs internet connection. These checks are not automated so the application does not perform regular checks to report passwords that have been exposed in data breaches. 
You can control when to perform these checks, or decide if you want to use this feature at all.

## Lost or stolen device

> You should always assume that your passwords have been compromised if you lose the device where your passwords are stored, or the device is stolen. In that case you are advised to change all your passwords.


## Videos

I believe that a picture is worth a thousand words, not to mention a video.
Visuals of the features are available on the [CarryPass demos]([https://www.youtube.com/channel/UCtSK10tYJpb1mhcC2K_osEQ](https://www.dailymotion.com/video/x8dgjq0?playlist=x7kt5t)) Dailymotion channel.





