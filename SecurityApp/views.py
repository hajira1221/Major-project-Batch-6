from django.shortcuts import render
from django.template import RequestContext
from django.contrib import messages
from django.http import HttpResponse
from django.core.files.storage import FileSystemStorage
import os
import random
from datetime import date
import ecdsa
from hashlib import sha256
import pickle
import re
import pyaes, pbkdf2, binascii, os, secrets
import pymysql
import smtplib
import hashlib
from ecies.utils import generate_eth_key, generate_key
from ecies import encrypt, decrypt
from PIL import Image

global username, otp, email


def getECCKeys():
    if os.path.exists("SecurityApp/static/keys/pvt.key"):
        with open("SecurityApp/static/keys/pvt.key", 'rb') as f:
            private_key = f.read()
        with open("SecurityApp/static/keys/pri.key", 'rb') as f:
            public_key = f.read()
        private_key = private_key.decode()
        public_key = public_key.decode()
    else:
        secret_key = generate_eth_key()
        private_key = secret_key.to_hex()
        public_key = secret_key.public_key.to_hex()
        with open("SecurityApp/static/keys/pvt.key", 'wb') as f:
            f.write(private_key.encode())
        with open("SecurityApp/static/keys/pri.key", 'wb') as f:
            f.write(public_key.encode())
    return private_key, public_key


def generateKeys():
    if os.path.exists("SecurityApp/static/keys/key.pckl"):
        with open("SecurityApp/static/keys/key.pckl", 'rb') as f:
            keys = pickle.load(f)
        secret_key = keys[0]
        private_key = keys[1]
    else:
        secret_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=sha256)
        private_key = secret_key.get_verifying_key()
        keys = [secret_key, private_key]
        with open("SecurityApp/static/keys/key.pckl", 'wb') as f:
            pickle.dump(keys, f)
    private_key = private_key.to_string()[0:32]
    return private_key


def encryptAES(plaintext, key):
    aes = pyaes.AESModeOfOperationCTR(
        key,
        pyaes.Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223)
    )
    ciphertext = aes.encrypt(plaintext)
    return ciphertext


def decryptAES(enc, key):
    aes = pyaes.AESModeOfOperationCTR(
        key,
        pyaes.Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223)
    )
    decrypted = aes.decrypt(enc)
    return decrypted


def ECCEncrypt(plainText, public_key):
    ecc_encrypt = encrypt(public_key, plainText)
    return ecc_encrypt


def ECCDecrypt(encrypt, private_key):
    ecc_decrypt = decrypt(private_key, encrypt)
    return ecc_decrypt



def generateBits(message):
    msg_bit = []
    for bit in message:
        binary_bit = format(ord(bit), '08b')
        msg_bit.extend([int(b) for b in binary_bit])
    return msg_bit


def bits2msg(msg_bits):
    msg = []
    for i in range(0, len(msg_bits), 8):
        byte = "".join(map(str, msg_bits[i:i + 8]))
        msg.append(chr(int(byte, 2)))
    return "".join(msg)


def hideMessage(filename, secret_message):
    cover_image = Image.open(filename).convert("RGB")
    width, height = cover_image.size
    message_bits = generateBits(secret_message)
    bit_index = 0
    total_bits = len(message_bits)

    for y in range(height):
        for x in range(width):
            if bit_index < total_bits:
                r, g, b = cover_image.getpixel((x, y))
                r = (r & ~1) | message_bits[bit_index]
                cover_image.putpixel((x, y), (r, g, b))
                bit_index += 1
            else:
                break
        if bit_index >= total_bits:
            break

    for x in range(width):
        for y in range(height):
            if bit_index < total_bits:
                r, g, b = cover_image.getpixel((x, y))
                g = (g & ~1) | message_bits[bit_index]
                cover_image.putpixel((x, y), (r, g, b))
                bit_index += 1
            else:
                break
        if bit_index >= total_bits:
            break

    if bit_index < total_bits:
        raise ValueError("Error: Message too large for selected image capacity.")

    return cover_image


def extractMessage(filepath):
    cover_image = Image.open(filepath)
    width, height = cover_image.size
    extracted_bits = []
    potential_message = ""

    for y in range(height):
        for x in range(width):
            r, g, b = cover_image.getpixel((x, y))
            extracted_bits.append(r & 1)
            if len(extracted_bits) < 100:
                potential_message = bits2msg(extracted_bits[:len(extracted_bits)//8*8])
            else:
                break
        if len(extracted_bits) >= 100:
            potential_message = potential_message.split("#")[0]
            break

    for x in range(width):
        for y in range(height):
            r, g, b = cover_image.getpixel((x, y))
            extracted_bits.append(g & 1)
            if len(extracted_bits) > 1000:
                potential_message = bits2msg(extracted_bits[:len(extracted_bits)//8*8])
                if "#" in potential_message:
                    potential_message = potential_message.split("#")[0]
                    break
        if "#" in potential_message:
            potential_message = potential_message.split("#")[0]
            break
    return potential_message



def ImageStegAction(request):
    if request.method == 'POST':
        username = request.session.get('username', None)
        if not username:
            return HttpResponse("<h3>Please login first to perform steganography.</h3>")

        message = request.POST.get('t1', '').strip()
        message += " #"

        uploaded_file = request.FILES['t2']
        filename = uploaded_file.name
        image_data = uploaded_file.read()

        file_path = "SecurityApp/static/files/" + filename
        if os.path.exists(file_path):
            os.remove(file_path)

        with open(file_path, "wb") as file:
            file.write(image_data)

        cover_image = hideMessage(file_path, message)
        cover_image.save(file_path)

        with open(file_path, "rb") as file:
            encrypted_data = file.read()

        hashcode = hashlib.sha256(encrypted_data).hexdigest()
        dd = str(date.today())

        con = pymysql.connect(host='127.0.0.1', port=3306, user='root',
                              password='hajira123$', database='cybersecurity', charset='utf8')
        cur = con.cursor()
        cur.execute("INSERT INTO files VALUES(%s, %s, %s, %s, %s)",
                    (username, filename, hashcode, dd, 'Steganography'))
        con.commit()
        cur.close()
        con.close()

        context = {'data': '<font size="3" color="blue">Message successfully hidden in given image</font>'}
        return render(request, 'ImageSteg.html', context)



def Download(request):
    if request.method == 'GET':
        name = request.GET.get('requester', False)
        with open("SecurityApp/static/files/" + name, "rb") as file:
            data = file.read()
        private_key, public_key = getECCKeys()
        decrypted_data = ECCDecrypt(data, private_key)
        private_key = generateKeys()
        decrypted_data = decryptAES(decrypted_data, private_key)
        response = HttpResponse(decrypted_data, content_type='application/force-download')
        response['Content-Disposition'] = 'attachment; filename=' + name
        return response


def AccessData(request):
    if request.method == 'GET':
        username = request.session.get('username', None)
        if not username:
            return HttpResponse("<h3>Please login first to access data.</h3>")

        output = '<table border=1 align=center width=100%><tr><th>File Owner Name</th><th>Filename</th><th>Hashcode</th><th>Upload Date</th><th>File Security Type</th><th>Steg Image</th><th>Download File</th></tr>'
        con = pymysql.connect(host='127.0.0.1', port=3306, user='root',
                              password='hajira123$', database='cybersecurity', charset='utf8')
        with con:
            cur = con.cursor()
            cur.execute("select * FROM files where username=%s", (username,))
            rows = cur.fetchall()
            for row in rows:
                name, fname, hashcode, upload_date, upload_type = row
                output += f'<tr><td>{name}</td><td>{fname}</td><td>{hashcode}</td><td>{upload_date}</td><td>{upload_type}</td>'
                if upload_type == "Steganography":
                    output += f'<td><img src="static/files/{fname}" height="200" width="200"/></td>'
                    message = extractMessage("SecurityApp/static/files/" + fname)
                    output += f'<td><font color="blue">Hidden Message = {message}</font></td></tr>'
                else:
                    output += f'<td><font color="red">--</font></td><td><a href="Download?requester={fname}"><font color="red">Download</font></a></td></tr>'
        output += "</table><br/><br/><br/><br/>"
        context = {'data': output}
        return render(request, 'UserScreen.html', context)


def ImageSteg(request):
    return render(request, 'ImageSteg.html', {})


def HybridEncryptionAction(request):
    if request.method == 'POST':
        username = request.session.get('username', None)
        if not username:
            return HttpResponse("<h3>Please login first to perform encryption.</h3>")

        myfile = request.FILES['t1'].read()
        fname = request.FILES['t1'].name
        dd = str(date.today())

        private_key = generateKeys()
        encrypted_data = encryptAES(myfile, private_key)
        private_key, public_key = getECCKeys()
        encrypted_data = ECCEncrypt(encrypted_data, public_key)

        with open("SecurityApp/static/files/" + fname, "wb") as file:
            file.write(encrypted_data)

        hashcode = hashlib.sha256(encrypted_data).hexdigest()
        db_connection = pymysql.connect(host='127.0.0.1', port=3306, user='root',
                                        password='hajira123$', database='cybersecurity', charset='utf8')
        db_cursor = db_connection.cursor()
        db_cursor.execute("INSERT INTO files VALUES(%s, %s, %s, %s, %s)",
                          (username, fname, hashcode, dd, 'Hybrid Encryption'))
        db_connection.commit()
        context = {'data': '<font color="blue">Hybrid Encrypted file successfully saved at server network</font>'}
        return render(request, 'HybridEncryption.html', context)


def HybridEncryption(request):
    return render(request, 'HybridEncryption.html', {})



def UserLogin(request):
    return render(request, 'UserLogin.html', {})


def index(request):
    return render(request, 'index.html', {})


def Register(request):
    return render(request, 'Register.html', {})


def RegisterAction(request):
    username = request.POST.get('t1', False)
    password = request.POST.get('t2', False)
    contact = request.POST.get('t3', False)
    email = request.POST.get('t4', False)
    address = request.POST.get('t5', False)
    status = "none"

    con = pymysql.connect(host='127.0.0.1', port=3306, user='root',
                          password='hajira123$', database='cybersecurity', charset='utf8')
    with con:
        cur = con.cursor()
        cur.execute("select username FROM register")
        rows = cur.fetchall()
        for row in rows:
            if row[0] == username:
                status = '<font color="blue">Username already exists</font>'
                break
    if status == "none":
        db_connection = pymysql.connect(host='127.0.0.1', port=3306, user='root',
                                        password='hajira123$', database='cybersecurity', charset='utf8')
        db_cursor = db_connection.cursor()
        db_cursor.execute("INSERT INTO register VALUES(%s,%s,%s,%s,%s)",
                          (username, password, contact, email, address))
        db_connection.commit()
        status = '<font color="blue">Signup process completed</font>'
    context = {'data': status}
    return render(request, 'Register.html', context)


def sendOTP(email, otp_value):
    em = [email]
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as connection:
        email_address = 'kaleem202120@gmail.com'
        email_password = 'xyljzncebdxcubjq'
        connection.login(email_address, email_password)
        connection.sendmail(from_addr=email_address, to_addrs=em, msg="Subject : Your OTP : " + otp_value)


def UserLoginAction(request):
    global otp, email
    uname = request.POST.get('username', False)
    password = request.POST.get('password', False)
    index = 0
    con = pymysql.connect(host='127.0.0.1', port=3306, user='root',
                          password='hajira123$', database='cybersecurity', charset='utf8')
    with con:
        cur = con.cursor()
        cur.execute("select username, password, email FROM register")
        rows = cur.fetchall()
        for row in rows:
            if row[0] == uname and password == row[1]:
                email = row[2]
                index = 1
                break
    if index == 1:
        otp = str(random.randint(1000, 9999))
        sendOTP(email, otp)
        request.session['pending_username'] = uname  
        context = {'data': '<font color="blue">OTP sent to your mail</font>'}
        return render(request, 'OTP.html', context)
    else:
        context = {'data': '<font color="blue">login failed</font>'}
        return render(request, 'UserLogin.html', context)


def OTPAction(request):
    global otp
    user_otp = request.POST.get('t1', False)
    if otp == user_otp:
        username = request.session.get('pending_username')
        request.session['username'] = username  
        context = {'data': f'<font color="blue">OTP Successfully Validated<br/>Welcome {username}</font>'}
        return render(request, 'UserScreen.html', context)
    else:
        context = {'data': '<font color="blue">login failed</font>'}
        return render(request, 'OTP.html', context)


def Logout(request):
    request.session.flush()
    return render(request, 'UserLogin.html', {'data': 'You have been logged out.'})
