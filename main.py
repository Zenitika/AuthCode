import os
import sys
from tkinter import ttk
from tkinter import font
from dataclasses import dataclass

import webbrowser
import customtkinter
from loguru import logger

from logic import FileCrypt, SecretChecker, SecretEditor, SecretAdder, Data



@dataclass
class SettingsData:
    text_color: str


# It creates a window, sets the window's size, and then calls two other
# functions.
class CoreGui():
    def start(self):
        """
        It creates a window, sets the window's size, and then calls two other functions.

        """

        self.app = customtkinter.CTk() # Попробовать настроить Title bar где иконка и название. И добавить ещё больше настроек которые будут хранится в файле

        self.app.title("2FA")
        self.app.iconbitmap("icon.ico")

        self.app.minsize(300, 200)
        self.app.maxsize(300, 500)

        SettingsData.text_color = "aquamarine"

        self.app.grid_rowconfigure((3, 1), weight=0)
        self.app.grid_columnconfigure((1, 1), weight=1)

        customtkinter.set_appearance_mode("dark")
        customtkinter.set_default_color_theme("green")

        RenderGui.element_auth_gui_param(self)
        RenderGui.show_auth_gui(self)

        self.app.mainloop()


class LogicGui(CoreGui):
    """
    It takes a string, encrypts it, and then adds it to a list.

    :param frame: the frame that is currently being displayed

    """

    def password_check(self):
        """
        If the password is correct, the password check window is destroyed and the main menu is displayed.
        If the password is incorrect, a label is displayed.

        """
        _ = self.entry.get()

        if FileCrypt.chek_password(_):
            self.button.destroy()
            self.label.destroy()
            self.entry.destroy()
            self.label1.destroy()
            RenderGui.element_main_menu_param(self)
            RenderGui.show_main_menu_gui(self)
        else:
            self.label1.grid(
                row=2, column=1, padx=(
                    10, 10), pady=(
                    0, 1), sticky="ew")

    def create_new_password(self):
        """
        It takes the text from the entry widget, and passes it to the generate_new_pass function in the
        FileCrypt class.

        """
        _ = str(self.entry_password.get())
        FileCrypt.generate_new_pass(_)

    def insert_title(self, request: str = ''):
        """
        It takes the first element of each list in the list of lists and inserts it into the textbox.

        """
        all_lines = FileCrypt.get_all_lines()
        if all_lines is not None:
            for line_list in all_lines:
                if request == "Edit":
                    self.textbox_for_code.insert(
                        customtkinter.END, f"{line_list[0]} {line_list[1]}\n")
                else:
                    self.textbox_for_title.insert(
                        customtkinter.END, f"{line_list[0]}\n")
            if request != "Edit":
                self.textbox_for_title.configure(state="disabled")

    def get_code(self, request: str):
        """
        It takes a request, checks if it's valid, and if it is, it returns a tuple of the code and the time
        it expires in.

        :param request: The request is a dictionary that contains the following keys:

        """
        _ = SecretChecker()

        response = _.start(request)
        if response:
            self.label_for_time.configure(
                text=f"Expires in: {response[1]} sec")
            self.code_label.configure(text=f"Code: {response[0]}")

    def add_new_secret(self):
        """
        It takes a string, encrypts it, and then adds it to a list

        """
        dialog = customtkinter.CTkInputDialog(
            text="Enter new secret:", title="Add new secret")
        _ = dialog.get_input()
        if _ is not None:
            SecretAdder.text_input(_.encode())
            self.refresh("btn_frame")

    def go_edit_page(self):
        self.btn_frame.destroy()
        self.code_frame.destroy()
        RenderGui.element_edit(self)
        RenderGui.show_edit_gui(self)

    def go_help_page(self):
        """
        It destroys the current frame and then calls two other functions to create a new frame and populate
        it with widgets.

        """
        self.btn_frame.destroy()
        self.code_frame.destroy()
        RenderGui.element_help_param(self)
        RenderGui.show_help_gui(self)

    def refresh(self, current_frame: str):
        if current_frame == "btn_frame":
            self.textbox_for_title.destroy()
            self.textbox_for_title = customtkinter.CTkTextbox(self.code_frame)
            self.textbox_for_title.grid(
                row=0, column=0, columnspan=2, padx=(
                    10, 10), pady=(
                    10, 10), sticky="we")
            self.insert_title()
        elif current_frame == "edit_frame":
            self.textbox_for_code.destroy()
            self.textbox_for_code = customtkinter.CTkTextbox(self.edit_frame)
            self.textbox_for_code.grid(
                row=0, column=0, columnspan=2, padx=(
                    10, 10), pady=(
                    10, 10), sticky="we")
            self.insert_title("Edit")

    def optionmenu_callback(self, choice: str):
        """
        It sets the appearance mode and color theme of the GUI.

        :param choice: The choice that was selected

        """
        match choice:
            case "Light":
                customtkinter.set_appearance_mode("light")
                customtkinter.set_default_color_theme("blue")
                SettingsData.text_color = "black"

            case "Light green":
                customtkinter.set_appearance_mode("light")
                customtkinter.set_default_color_theme("green")
                SettingsData.text_color = "black"

            case "Dark":
                customtkinter.set_appearance_mode("dark")
                customtkinter.set_default_color_theme("green")
                SettingsData.text_color = "aquamarine"

            case "Dark blue":
                customtkinter.set_appearance_mode("dark")
                customtkinter.set_default_color_theme("dark-blue")
                SettingsData.text_color = "aquamarine"

    def go_back_to_main_menu(self, frame):
        """
        It destroys the current frame and then calls the main menu frame.

        :param frame: the frame that is currently being displayed

        """
        frame.destroy()
        RenderGui.element_main_menu_param(self)
        RenderGui.show_main_menu_gui(self)

    def open_instruction_link(self):
        """
        It opens a new tab in the default browser and navigates to the specified URL

        """
        webbrowser.open('https://github', new=2)

    def change_password(self):
        """
        It takes the text from the entry box and passes it to the generate_new_pass function in the
        FileCrypt class.

        """
        FileCrypt.generate_new_pass(self.entry_for_new_pass.get())

    def decrypt_file(self):
        """
        It decrypts the file.

        """
        FileCrypt.decrypt_file_codes()

    def apply_change_code(self):
        old_code: str = self.entry_for_elder_pass.get()
        new_code: str = self.entry_for_new_pass.get()
        SecretEditor.edit_code(old_code.split(), new_code.split())
        self.refresh("edit_frame")


# It's a class that creates a GUI for a program.
class RenderGui(LogicGui, CoreGui):

    def element_auth_gui_param(self):
        """
        It params a label, an entry, a label1, and a button.

        """

        self.label = customtkinter.CTkLabel(master=self.app,
                                            text="Enter your password",
                                            width=120,
                                            height=25,
                                            text_font=100,
                                            text_color=SettingsData.text_color,
                                            corner_radius=8)

        self.entry = customtkinter.CTkEntry(master=self.app,
                                            show = "*",
                                            width=120,
                                            placeholder_text="Password")

        self.label1 = customtkinter.CTkLabel(master=self.app,
                                             text="Wrong password",
                                             width=120,
                                             height=25,
                                             text_color="red",
                                             corner_radius=8)

        self.button = customtkinter.CTkButton(master=self.app,
                                              text="Check",
                                              width=120,
                                              height=25,
                                              text_font=1,
                                              command=self.password_check)

    def show_auth_gui(self):
        """
        It creates a label, entry, and button, and then places them in the window.

        """

        self.entry.grid(
            row=1, column=1, padx=(
                10, 10), pady=(
                10, 10), sticky="ew")

        self.label.grid(
            row=0, column=1, padx=(
                10, 10), pady=(
                100, 0), sticky="ew")

        self.button.grid(
            row=3, column=1, padx=(
                10, 10), pady=(
                10, 10), sticky="ew")

    def element_main_menu_param(self):
        """
        It params a bunch of buttons and labels and textboxes and stuff.
        """

        self.app.grid_rowconfigure(0, weight=0)
        self.app.grid_rowconfigure(1, weight=1)
        self.app.grid_columnconfigure(0, weight=100)
        self.app.grid_columnconfigure(1, weight=1)

        self.btn_frame = customtkinter.CTkFrame(self.app)
        self.code_frame = customtkinter.CTkFrame(self.app)

        self.code_frame.grid_rowconfigure((0, 0), weight=1)
        self.code_frame.grid_rowconfigure((0, 0), weight=1)
        self.code_frame.grid_columnconfigure((0, 0), weight=1)
        self.code_frame.grid_columnconfigure((0, 0), weight=1)

        self.app.minsize(450, 0)
        self.app.maxsize(450, 0)

        self.add_button = customtkinter.CTkButton(master=self.btn_frame,
                                                  text="Add new secret",
                                                  width=120,
                                                  height=25,
                                                  text_font=1,
                                                  command=self.add_new_secret)

        self.edit_button = customtkinter.CTkButton(master=self.btn_frame,
                                                   text="Edit secret",
                                                   width=120,
                                                   height=25,
                                                   text_font=1,
                                                   command=self.go_edit_page)

        self.settings_button = customtkinter.CTkButton(
            master=self.btn_frame,
            text="Settings",
            width=120,
            height=25,
            text_font=1,
            command=lambda: self.go_help_page())

        self.delete_all_data_btn = customtkinter.CTkButton(
            master=self.btn_frame,
            text="Delete All Data",
            width=120,
            height=25,
            text_font=1,
            command=self.password_check)

        self.code_label = customtkinter.CTkLabel(master=self.btn_frame,
                                                 text="",
                                                 width=120,
                                                 height=25,
                                                 text_font=1)

        self.label_for_title = customtkinter.CTkLabel(
            master=self.code_frame,
            text="Enter account name: ",
            width=120,
            height=25,
            text_font=100,
            text_color=SettingsData.text_color,
            corner_radius=8)

        self.label_for_time = customtkinter.CTkLabel(
            master=self.code_frame,
            text="Expires in: ",
            width=120,
            height=25,
            text_font=100,
            text_color=SettingsData.text_color,
            corner_radius=8)

        self.entry_for_title = customtkinter.CTkEntry(
            master=self.code_frame, width=230, placeholder_text="Your choice...")

        self.button_code = customtkinter.CTkButton(
            master=self.code_frame,
            text="Get your code",
            width=230,
            height=25,
            text_font=1,
            command=lambda: self.get_code(
                self.entry_for_title.get()))

        self.textbox_for_title = customtkinter.CTkTextbox(self.code_frame)

    def show_main_menu_gui(self):
        """
        It's a function that creates a GUI for a program.

        """

        self.btn_frame.grid(
            row=0, column=0, padx=(
                10, 10), pady=(
                10, 10), sticky="ewn")

        self.add_button.grid(
            row=0, column=0, padx=(
                10, 10), pady=(
                10, 10), sticky="new")
        self.edit_button.grid(
            row=1, column=0, padx=(
                10, 10), pady=(
                10, 10), sticky="nsew")

        self.settings_button.grid(
            row=0, column=1, padx=(
                10, 10), pady=(
                10, 10), sticky="new")

        self.delete_all_data_btn.grid(
            row=0, column=3, padx=(
                10, 10), pady=(
                10, 10), sticky="new")
        self.code_label.grid(
            row=1, column=3, padx=(
                10, 10), pady=(
                10, 10), sticky="new")

        self.code_frame.grid(
            row=1, column=0, padx=(
                10, 10), pady=(
                10, 10), sticky="new")

        self.label_for_title.grid(
            row=1, column=0, padx=(
                10, 10), pady=(
                10, 10), sticky="w")

        self.label_for_time.grid(
            row=2, column=0, padx=(
                10, 10), pady=(
                10, 10), sticky="w")

        self.entry_for_title.grid(
            row=1, column=1, padx=(
                10, 10), pady=(
                10, 10), sticky="w")

        self.button_code.grid(
            row=2, column=1, padx=(
                10, 10), pady=(
                10, 10), sticky="w")

        self.textbox_for_title.grid(
            row=0, column=0, columnspan=2, padx=(
                10, 10), pady=(
                10, 10), sticky="we")

        self.textbox_for_title.insert("0.0", "")

        self.insert_title()

    def element_help_param(self):
        """
        It params a frame with a bunch of buttons and labels.

        """

        self.app.minsize(435, 0)
        self.app.maxsize(435, 0)

        self.help_frame = customtkinter.CTkFrame(self.app)

        self.combobox = customtkinter.CTkOptionMenu(
            master=self.help_frame,
            values=[
                "Dark",
                "Dark blue",
                "Light",
                "Light green"],
            command=self.optionmenu_callback,
        )

        self.back_button = customtkinter.CTkButton(
            master=self.help_frame,
            text="Go back",
            width=120,
            height=25,
            text_font=1,
            command=lambda: self.go_back_to_main_menu(
                self.help_frame))

        self.instruction_button = customtkinter.CTkButton(
            master=self.help_frame,
            text="Instruction",
            width=120,
            height=25,
            text_font=1,
            command=self.open_instruction_link)

        self.change_password_btn = customtkinter.CTkButton(
            master=self.help_frame,
            text="Change password",
            width=120,
            height=25,
            text_font=1,
            command=self.change_password)

        self.decrypt_file_with_codes = customtkinter.CTkButton(
            master=self.help_frame,
            text="Decrypt file with codes",
            width=120,
            height=25,
            text_font=1,
            command=self.decrypt_file)

        self.label_for_copyright = customtkinter.CTkLabel(master=self.help_frame,
                                                          text="Created by Zenitika",
                                                          width=120,
                                                          height=25,
                                                          text_color=SettingsData.text_color,
                                                          corner_radius=8)

        self.entry_for_new_pass = customtkinter.CTkEntry(
            master=self.help_frame, width=230, placeholder_text="Enter new password: ")

    def show_help_gui(self):
        """
        It creates a GUI window with a combobox, a button, and an entry widget.

        """
        self.help_frame.grid(
            row=0, column=0, padx=(
                10, 10), pady=(
                10, 10), sticky="ewn")

        self.combobox.grid(
            row=0, column=0, padx=(
                10, 10), pady=(
                10, 10), sticky="ewn")

        self.change_password_btn.grid(
            row=1, column=0, padx=(
                10, 10), pady=(
                10, 10), sticky="ewn")

        self.back_button.grid(
            row=2, column=0, padx=(
                10, 10), pady=(
                10, 10), sticky="ewn")

        self.instruction_button.grid(
            row=0, column=1, padx=(
                10, 10), pady=(
                10, 10), sticky="ewn")

        self.entry_for_new_pass.grid(
            row=1, column=1, padx=(
                10, 10), pady=(
                10, 10), sticky="ewn")

        self.decrypt_file_with_codes.grid(
            row=2, column=1, padx=(
                10, 10), pady=(
                10, 10), sticky="ewn")

    def element_edit(self):

        self.app.minsize(430, 0)
        self.app.maxsize(430, 0)

        self.edit_frame = customtkinter.CTkFrame(self.app)

        self.back_button = customtkinter.CTkButton(
            master=self.edit_frame,
            text="Go back",
            width=120,
            height=25,
            text_font=1,
            command=lambda: self.go_back_to_main_menu(
                self.edit_frame))

        self.code_label = customtkinter.CTkLabel(
            master=self.edit_frame,
            text="Enter current code",
            width=120,
            height=25,
            text_color=SettingsData.text_color,
            text_font=1)

        self.apply_change = customtkinter.CTkButton(
            master=self.edit_frame,
            text="Change this code",
            width=120,
            height=25,
            text_font=1,
            command=self.apply_change_code)

        self.textbox_for_code = customtkinter.CTkTextbox(self.edit_frame)

        self.entry_for_elder_pass = customtkinter.CTkEntry(
            master=self.edit_frame, width=230, placeholder_text="Enter not changed code")

        self.entry_for_new_pass = customtkinter.CTkEntry(
            master=self.edit_frame, width=230, placeholder_text="Enter changed code")

    def show_edit_gui(self):
        self.edit_frame.grid(
            row=0, column=0, padx=(
                10, 10), pady=(
                10, 10), sticky="ewn")

        self.textbox_for_code.grid(
            row=0, column=0, columnspan=2, padx=(
                10, 10), pady=(
                10, 10), sticky="we")

        self.textbox_for_code.insert("0.0", "")

        self.insert_title("Edit")

        self.code_label.grid(
            row=1, column=0, padx=(
                10, 10), pady=(
                10, 10), sticky="ewn")

        self.apply_change.grid(
            row=2, column=0, padx=(
                10, 10), pady=(
                10, 10), sticky="ewn")

        self.back_button.grid(
            row=3, column=0, padx=(
                10, 10), pady=(
                10, 10), sticky="ewn")

        self.entry_for_elder_pass.grid(
            row=1, column=1, padx=(
                10, 10), pady=(
                10, 10), sticky="ewn")

        self.entry_for_new_pass.grid(
            row=2, column=1, padx=(
                10, 10), pady=(
                10, 10), sticky="ewn")


# Creating a new instance of the LogicGui class and calling the start
# method on it.
if __name__ == '__main__':
    if getattr(sys, 'frozen', False):
        proc_name = sys.argv[0]
        Data.PATCH_TO_FILE = fr"{os.path.dirname(proc_name)}"

    elif __file__:
        Data.PATCH_TO_FILE = fr"{os.path.dirname(os.path.realpath(__file__))}"

    logger.add(
        f"{Data.PATCH_TO_FILE}\logs_gui.log",
        level='WARNING',
        format='<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>: <cyan>{function}</cyan>: <cyan>{line}</cyan> - <level>{message}</level>',
        filter=None,
        colorize=False,
        serialize=False,
        backtrace=True,
        diagnose=True,
        enqueue=False,
        catch=True)

    _ = LogicGui()
    _.start()