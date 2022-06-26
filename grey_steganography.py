from PIL import Image
import os
from pyfiglet import figlet_format
from termcolor import cprint 
from rich.console import Console
from rich.table import Table
from rich import print
from os import path
import getpass
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random
import base64
import sys
import pyperclip

headerText = "zUr6SIdCYemg"
console = Console()

def encrypt(key, source, encode=True):
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = Random.new().read(AES.block_size)  # generate IV
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
    source += bytes([padding])*padding  # Python 2.x: source += chr(padding) * padding
    data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt
    return base64.b64encode(data).decode() if encode else data

def decrypt(key, source, decode=True):
    if decode:
        source = base64.b64decode(source.encode())
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = source[:AES.block_size]  # extract the IV from the beginning
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])  # decrypt
    padding = data[-1]  # pick the padding value from the end; Python 2.x: ord(data[-1])
    if data[-padding:] != bytes([padding])*padding:  # Python 2.x: chr(padding) * padding
        raise ValueError("Invalid padding...")
    return data[:-padding]  # remove the padding

def convertToRGB(img):
    try:
        rgba_image = img
        rgba_image.load()
        background = Image.new("RGB", rgba_image.size, (255, 255, 255))
        background.paste(rgba_image, mask = rgba_image.split()[3])
        print("[yellow]Converted image to RGB [/yellow]")
        return background
    except Exception as e:
        print(e)
        print("[red]Couldn't convert image to RGB [/red]- %s"%e)

def getPixelCount(img):
    try:
        width, height = Image.open(img).size
        return width*height
    except Exception as e:
        raise Exception("not_image")

def encodeImage(image,message,filename):
    with console.status("[green]Encoding image..") as status:
        try:
            width, height = image.size
            pix = image.getdata()
            print(pix[0])
            print(pix[1])

            current_pixel = 0
            tmp = 0
            x = 0
            y = 0
            for ch in message:
                binary_value = format(ord(ch), '08b')
                
                # For each character, get 3 pixels at a time
                p1 = pix[current_pixel]
                p2 = pix[current_pixel+1]
                p3 = pix[current_pixel+2]

                three_pixels = [val for val in p1+p2+p3]

                for i in range(0,8):
                    current_bit = binary_value[i]

                    # 0 - Even
                    # 1 - Odd
                    if current_bit == '0':
                        if three_pixels[i]%2 != 0:
                            three_pixels[i] = three_pixels[i] - 1 if three_pixels[i] == 255 else three_pixels[i] + 1
                    elif current_bit == '1':
                        if three_pixels[i]%2 == 0:
                            three_pixels[i] = three_pixels[i] - 1 if three_pixels[i] == 255 else three_pixels[i] + 1

                current_pixel += 3
                tmp += 1

                # Set 9th value
                if(tmp == len(message)):
                    # Make as 1 (odd) - stop reading
                    if three_pixels[-1]%2 == 0:
                        three_pixels[-1] = three_pixels[-1] - 1 if three_pixels[-1] == 255 else three_pixels[-1] + 1
                else:
                    # Make as 0 (even) - continue reading
                    if three_pixels[-1]%2 != 0:
                        three_pixels[-1] = three_pixels[-1] - 1 if three_pixels[-1] == 255 else three_pixels[-1] + 1

                three_pixels = tuple(three_pixels)
                
                st = 0
                end = 3

                for i in range(0,3):

                    image.putpixel((x,y), three_pixels[st:end])
                    st += 3
                    end += 3

                    if (x == width - 1):
                        x = 0
                        y += 1
                    else:
                        x += 1

            encoded_filename = filename.split('.')[0] + "_encoded.png"
            image.save(encoded_filename)
            print("\n")
            print("[yellow]Original File: [u]%s[/u][/yellow]"%filename)
            print("[green]Image encoded and saved as [u][bold]%s[/green][/u][/bold]"%encoded_filename)

        except Exception as e:
            print("[red]An error occured - [/red]%s"%e)
            sys.exit(0)

def decodeImage(image):
    with console.status("[green]Decoding image..") as status:
        try:
            pix = image.getdata()
            current_pixel = 0
            decoded = ""
            while True:
                # Get 3 pixels each time
                binary_value = ""
                p1 = pix[current_pixel]
                p2 = pix[current_pixel+1]
                p3 = pix[current_pixel+2]
                three_pixels = [val for val in p1+p2+p3]

                for i in range(0,8):
                    if three_pixels[i]%2 == 0:
                        # add 0
                        binary_value += "0"
                    elif three_pixels[i]%2 != 0:
                        # add 1
                        binary_value += "1"


                # Convert binary value to ascii and add to string
                binary_value.strip()
                ascii_value = int(binary_value,2)
                decoded += chr(ascii_value)
                current_pixel += 3

                if three_pixels[-1]%2 != 0:
                    # stop reading
                    break

            return decoded
        except Exception as e:
            print("[red]An error occured - [/red]%s"%e)
            sys.exit()



def main():
    print("[cyan]Choose one: [/cyan]")
    try:
        encode_decode_option = input("1. Encode\n2. Decode\n>>")
        if encode_decode_option != "":
            try:
                encode_decode_option = int(encode_decode_option)
            except:
                raise Exception("wrong_option")
        else:
            raise Exception("no_option")

        if encode_decode_option == 1:
            print("[cyan]Image path (with extension): [/cyan]")
            img_path = input(">>")
            if(not(path.exists(img_path))):
                raise Exception("path_error")
            
            message = ""
            while True:
                print("[cyan]Message to be hidden: [/cyan]")
                message = input(">>")
                if message == "":
                    print("[red]No Message provided[/red] please enter some message to be hidden")
                else:
                    message = headerText + message
                    break
            if((len(message) + len(headerText))*3 > getPixelCount(img_path)):
                raise Exception("big_msg")
            
            password = ""
            while True:
                print("[cyan]Password to encrypt (leave empty if you want no password): [/cyan]")
                password = getpass.getpass(">>")
                if password == "":
                    break
                print("[cyan]Re-enter Password: [/cyan]")
                confirm_password = getpass.getpass(">>")
                if(password != confirm_password):
                    print("[red]Passwords don't match try again [/red]")
                else:
                    break

            cipher = ""
            if password != "":
                cipher = encrypt(key=password.encode(),source=message.encode())
                cipher = headerText + cipher
            else:
                cipher = message
                
            image = Image.open(img_path)
            print("[yellow]Image Mode: [/yellow]%s"%image.mode)
            if image.mode != 'RGB':
                image = convertToRGB(image)
            newimg = image.copy()
            encodeImage(image=newimg,message=cipher,filename=image.filename)

        elif encode_decode_option == 2:
            print("[cyan]Image path (with extension): [/cyan]")
            img_path = input(">>")
            if(not(path.exists(img_path))):
                raise Exception("path_error")
            
            print("[cyan]Enter password (leave empty if no password): [/cyan]")
            password = getpass.getpass(">>")
            image = Image.open(img_path)
            cipher = decodeImage(image)
            header = cipher[:len(headerText)]

            if header.strip() != headerText:
                print("[red]Invalid data![/red]")
                sys.exit(0)

            decrypted = ""
            if password != "":
                cipher = cipher[len(headerText):]
                print("cipher : ",cipher)
                try:
                    decrypted = decrypt(key=password.encode(),source=cipher)
                    header = decrypted.decode()[:len(headerText)]
                except Exception as e:
                    print("[red]Wrong password![/red]")
                    sys.exit(0)
            else:
                decrypted = cipher
            
            if header != headerText:
                raise Exception("wrong_pass")
            
            if type(decrypted) != str and decrypted.decode()[:len(headerText)] == headerText:
                decrypted = decrypted[len(headerText):] # Removing headertext from cipher
            elif type(decrypted) == str:
                decrypted = decrypted[len(headerText):]
            else:
                raise Exception("wrong_pass")

            # print output
            if password != "":
                print("[magenta]Decoded Text: [/magenta]\n[green][bold]%s[/bold][/green]"%decrypted.decode())
                pyperclip.copy(decrypted.decode())
            else:
                print("[magenta]Decoded Text: [/magenta]\n[green][bold]%s[/bold][/green]"%decrypted)
                pyperclip.copy(decrypted)
            print("[cyan]Copied! to clipboard[/cyan]")

        elif encode_decode_option == "":
            raise Exception("no_option")
        else:
            raise Exception("wrong_option")
    except Exception as error:
        if type(error) == type(Exception("path_error")) and error.args == Exception("path_error").args:
            print("Image Not Found!")
        elif type(error) == type(Exception("big_msg")) and error.args == Exception("big_msg").args:
            print("Given message is too long to be encoded in the image.")
        elif type(error) == type(Exception("not_image")) and error.args == Exception("not_image").args:
            print("This is not an image [red]:([/red]")
        elif type(error) == type(Exception("wrong_option")) and error.args == Exception("wrong_option").args:
            print("[red]Wrong[/red] option choose by you :(")
        elif type(error) == type(Exception("no_option")) and error.args == Exception("no_option").args:
            print("[red]No option choose by you :([/red]")
        elif type(error) == type(Exception("wrong_pass")) and error.args == Exception("wrong_pass").args:
            print("[red]Wrong password![/red]")
        else:
            print(error)
            print("Something Wrong")


if __name__ == '__main__':
    os.system('cls' if os.name == 'nt' else 'clear')
    cprint(figlet_format('Mr Grey', font='starwars'),'yellow', attrs=['bold'])
    print("This tool allows you to hide texts inside an image. You can also protect these texts with a password using AES-256.")
    print()
    main()