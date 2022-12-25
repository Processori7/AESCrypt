# -*- coding: utf-8 -*-
import os
import sys
import pyAesCrypt
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
import logging

while True:
    try:
        class Form(QMainWindow):
            def __init__(self, parent=None):
                super().__init__(parent)

                self.plainTextEdit = QPlainTextEdit()
                self.plainTextEdit.setFont(QFont('Arial', 14))

                self.plainTextEdit.appendHtml("<br>Добро пожаловать!<br><br>Выберите, что вы хотите сделать:<br>")

                crypt = QPushButton("Зашивровать")
                crypt.clicked.connect(self.crypt)

                decrypt = QPushButton("Расшифровать")
                decrypt.clicked.connect(self.decrypt)

                layoutV = QVBoxLayout()
                layoutV.addWidget(crypt)
                layoutV.addWidget(decrypt)

                layoutH = QHBoxLayout()
                layoutH.addLayout(layoutV)
                layoutH.addWidget(self.plainTextEdit)

                centerWidget = QWidget()
                centerWidget.setLayout(layoutH)
                self.setCentralWidget(centerWidget)

                self.resize(740, 480)
                self.setWindowTitle("WinRestore")

            def crypt(self):
                try:
                    filename, filetype = QFileDialog.getOpenFileName(self,
                                                                     "Выбрать файл",
                                                                     ".",
                                                                     "All Files(*)")
                    dir_name = filename
                    if dir_name =='':
                        self.plainTextEdit.appendHtml("<br>Ошибка! Выберите файл!<br>")
                    else:
                        password, okPressed = QInputDialog.getText(self, "Введите пароль", "Введите пароль:", QLineEdit.Password, "")
                        if okPressed and password != '':
                            bufferSize = 512 * 1024
                            if password:
                                # encrypt
                                pyAesCrypt.encryptFile(dir_name, dir_name + ".aes", password, bufferSize)
                                os.remove(filename)
                                self.plainTextEdit.appendHtml("<br>Файл зашифрован: " + filename)
                        else:
                            self.plainTextEdit.appendHtml("<br>Ошибка! Проверьте пароль!<br>")
                except:
                    self.plainTextEdit.appendHtml("<br>Ошибка! Проверьте пароль!<br>")

            def decrypt(self):
                try:
                    filename, filetype = QFileDialog.getOpenFileName(self,
                                                                     "Выбрать файл",
                                                                     ".",
                                                                     "All Files(*)")

                    dir_name = filename

                    if dir_name =='':
                        self.plainTextEdit.appendHtml("Ошибка! Выберите файл!<br>")
                    else:
                        password, okPressed = QInputDialog.getText(self, "Введите пароль", "Введите пароль:", QLineEdit.Password,
                                                                   "")
                        if okPressed and password != '':
                            bufferSize = 512 * 1024
                            if password:
                                pyAesCrypt.decryptFile(
                                    str(dir_name),
                                    str(os.path.splitext(dir_name)[0]),
                                    password,
                                    bufferSize
                                )
                                os.remove(filename)
                                self.plainTextEdit.appendHtml("<br>Файл расшифрован" + filename)
                            else:
                                self.plainTextEdit.appendHtml("<br>Не верный пароль<br>")
                        else:
                            self.plainTextEdit.appendHtml("<br>Ошибка! Проверьте пароль!<br>")
                except:
                    self.plainTextEdit.appendHtml("<br>Ошибка! Проверьте пароль!<br>")

    except:
        logging.basicConfig(filename='error.log', level=(logging.INFO), filemode='w')
        log = logging.getLogger('ex')
        log.exception("Ошибка")

        if __name__ == '__main__':
            app = QApplication(sys.argv)
            ex = Form()
            ex.show()
            sys.exit(app.exec_())


    if __name__ == '__main__':
        app = QApplication(sys.argv)
        ex = Form()
        ex.show()
        sys.exit(app.exec_())