import base64
import datetime
import binascii
from typing import TypeVar
from dataclasses import dataclass

import pyotp
import bcrypt
import secrets
import jmespath
import pyperclip
from loguru import logger
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


@dataclass
class Data:
    password: str
    login_salt: bytes

    PATCH_TO_FILE: str = ""
    DATA_FILE: str = f"{PATCH_TO_FILE}data.txt"
    CODES_FILE: str = f"{PATCH_TO_FILE}codes.txt"

    all_encode_line = TypeVar("all_encode_line", bound=list[list[str]] or dict)


# It encrypts and decrypts data.
class FileCrypt:

    @logger.catch
    @staticmethod
    def chek_password(password: str) -> bool:
        """
        It reads the first 60 bytes of the file, and then reads the next 16 bytes of the file

        :param password: str - the password to be checked
        :return: a boolean value.

        """
        if password == "":
            password = " "

        if password:
            with open(Data.DATA_FILE, "rb") as file:
                hashAndSalt = file.read()
                hashAndSalt = hashAndSalt[:60]
                login_salt = hashAndSalt[-32:]

            valid = bcrypt.checkpw(password.encode(), hashAndSalt)
            if valid:
                Data.password = password
                Data.login_salt = login_salt

        return valid

    @logger.catch
    @staticmethod
    def generate_new_pass(password: str) -> None:
        """
        It generates a new password, decrypts the data, re-encrypts the data with the new password, and then
        writes the data to the file.

        :param password: str - the password you want to use

        """
        if password == "":
            password = " "

        login_salt = secrets.token_hex(16).encode()
        hashAndSalt = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        with open(Data.DATA_FILE, "wb") as file:
            file.write(hashAndSalt + login_salt)

        with open(Data.CODES_FILE, "r") as codes_file:
            all_lines: list[str] = []
            for line_encode in codes_file:
                line: str = FileCrypt.decrypt_file_codes(line_encode.encode())
                all_lines.append(line)

        FileCrypt.chek_password(password)

        with open(Data.CODES_FILE, "w") as file:
            file.write('')

        for line in all_lines:
            FileCrypt.add_encryption_data(line.encode())

    @logger.catch
    @staticmethod
    def add_encryption_data(user_secrets: bytes, change: bool = False) -> None:
        """
        It takes a string, encrypts it, and writes it to a file.

        :param user_secrets: The user's secrets that are to be encrypted

        """

        password = Data.password.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256,
            length=32,
            salt=Data.login_salt,
            iterations=100000,
            backend=default_backend(),
        )

        encryption_key = (base64.urlsafe_b64encode(kdf.derive(password)))
        encryption_key_fernet = Fernet(encryption_key)
        encrypt_info = encryption_key_fernet.encrypt(user_secrets)

        with open(Data.CODES_FILE, "a") as file:
            file.write(encrypt_info.decode() + "\n")

    @logger.catch
    @staticmethod
    def decrypt_file_codes(crypt_info: bytes) -> str:
        """
        It takes a byte string, decrypts it, and returns a string

        :param crypt_info: bytes
        :return: The decrypted file codes.

        """

        kdf1 = PBKDF2HMAC(
            algorithm=hashes.SHA256,
            length=32,
            salt=Data.login_salt,
            iterations=100000,
            backend=default_backend(),
        )

        decryption_key = (
            base64.urlsafe_b64encode(
                kdf1.derive(
                    Data.password.encode())))
        decryption_key_fernet = Fernet(decryption_key)

        try:
            decrypt_info = decryption_key_fernet.decrypt(crypt_info).decode()
        except InvalidToken:
            logger.warning("Error failed to decrypting")
            return "Error_failed_to_decrypting"
        return decrypt_info

    @logger.catch
    @staticmethod
    def get_all_lines(json_flag: bool = False) -> Data.all_encode_line:
        """
        It reads a file, decrypts each line, splits the line into a list, and appends the list to a list of
        lists
        :return: A list of lists.

        """
        list_btn = []
        dict_btn = {}
        try:
            with open(Data.CODES_FILE, "r") as file:
                for num, line_endcode in enumerate(file):
                    line = FileCrypt.decrypt_file_codes(line_endcode.encode())
                    line = line.split()
                    if json_flag == True:
                        line = {f'account_{num}': line}
                        dict_btn.update(line)
                    else:
                        list_btn.append(line)

                if json_flag == True:
                    return dict_btn
                else:
                    return list_btn
        except FileNotFoundError:
            return None

class SecretEditor:

    @logger.catch
    @staticmethod
    def edit_code(old_code: list, new_code: list):

        all_lines: dict = FileCrypt.get_all_lines(True)
        edited_list: list[str] = []

        for account in all_lines:
            if old_code == jmespath.search(f"{account}[*]", all_lines):
                if new_code != []:
                    all_lines[account] = new_code
                    for key, val in all_lines.items():
                        edited_list.append(" ".join(val))
                    break

                elif new_code == []:
                    del all_lines[account]
                    for key, val in all_lines.items():
                        edited_list.append(" ".join(val))
                    break

        with open(Data.CODES_FILE, "w") as file:
            file.write('')

        for line in edited_list:
            FileCrypt.add_encryption_data(line.encode())

class SecretAdder:
    def __init__(self):
        pass

    @logger.catch
    @staticmethod
    def text_input(_: bytes):
        FileCrypt.add_encryption_data(_)


    def qr_input(self):
        # TODO document why this method is empty
        pass

    def img_input(self):
        # TODO document why this method is empty
        pass

# It takes a string as input, and returns a list of strings as output.
class SecretChecker:

    @logger.catch
    def start(self, request: str) -> list:
        """
        It takes a string as input, and returns a list of strings as output

        :param request: The request that was sent to the function
        :return: A list of param current secret

        """
        return self.get_secret(request)

    @logger.catch
    def get_secret(self, request: str) -> str:
        """
        It takes a string as an argument, and returns a string

        :param request: The name of the secret you want to retrieve
        :return: The return value is the result of the check_totp method.

        """
        for line in FileCrypt.get_all_lines():
            if line[0] == request:
                try:
                    return self.check_totp(line[1])
                except IndexError:
                    logger.warning("Index Error")

    @logger.catch
    def check_totp(self, secret: str) -> tuple:
        """
        It takes a secret key as a string, generates a TOTP code, copies it to the clipboard, and returns
        the code and the time remaining until the next code is generated.

        :param secret: The secret key that is used to generate the TOTP
        :return: The current TOTP code and the time remaining until the next code is generated.

        """
        try:
            totp = pyotp.TOTP(secret)
            time_remaining = totp.interval - datetime.datetime.now().timestamp() % totp.interval

            pyperclip.copy(totp.now())

            return totp.now(), round(time_remaining, 1)
        except binascii.Error:
            logger.warning("Error generating TOTP")
            return "Error", "Error"