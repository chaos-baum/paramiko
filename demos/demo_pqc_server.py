# demos/demo_pqc_server.py
# -*- coding: utf-8 -*-

"""
Ein einfacher PQC-fähiger SSH-Server zum Testen der Classic McEliece KEX-Implementierung.
"""

import socket
import sys
import threading
import traceback
import paramiko

# Laden Sie einen Host-Schlüssel. Für dieses Demo verwenden wir einen
# Standard-RSA-Schlüssel. In einem vollständig quantensicheren Szenario
# müsste dies durch einen PQC-Signaturschlüssel ersetzt werden.
try:
    host_key = paramiko.RSAKey(filename="demos/server_rsa_key")
except IOError:
    print(
        "*** Kann Host-Schlüssel 'demo_rsa.key' nicht finden. Bitte zuerst generieren."
    )
    sys.exit(1)

# Setzen Sie das Logging auf, um die KEX-Aushandlung zu sehen.
# Dies ist entscheidend, um zu überprüfen, ob Ihr McEliece-KEX verwendet wird.
paramiko.util.log_to_file("pqc_server.log")

# Ein einfacher Benutzername und ein Passwort für die Demo.
USER = "robot"
PASS = "p@ssword"


class Server(paramiko.ServerInterface):
    """
    Eine einfache Implementierung der Server-Schnittstelle von Paramiko.
    Sie authentifiziert einen einzelnen Benutzer.
    """

    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if (username == USER) and (password == PASS):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True


def main():
    """Hauptfunktion zum Starten des Servers."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", 2200))
        sock.listen(100)
        print("Lausche auf Verbindungen...")
    except Exception as e:
        print("*** Fehler beim Binden/Lauschen: {}".format(e))
        traceback.print_exc()
        sys.exit(1)

    while True:
        try:
            client_sock, addr = sock.accept()
            print("Verbindung von {} erhalten".format(addr))

            # Transport starten
            t = paramiko.Transport(client_sock)
            t.set_gss_host(socket.getfqdn(""))
            t.load_server_moduli()

            # Fügen Sie den Host-Schlüssel hinzu.
            t.add_server_key(host_key)

            server_interface = Server()

            # Server starten - hier findet die KEX-Aushandlung statt!
            try:
                t.start_server(server=server_interface)
            except paramiko.SSHException:
                print("*** SSH-Aushandlungsfehler.")
                continue

            # Warten auf Authentifizierung
            chan = t.accept(20)
            if chan is None:
                print("*** Kein Kanal von Client erhalten.")
                continue
            print("Authentifiziert!")

            server_interface.event.wait(10)
            if not server_interface.event.is_set():
                print("*** Client hat nie eine Shell angefordert.")
                continue

            # Einfache "Shell"
            chan.send("Erfolgreich mit Classic McEliece KEX verbunden!\r\n\r\n")
            chan.send("Geben Sie etwas ein, oder 'exit' zum Beenden.\r\n")

            while True:
                chan.send(b"$> ")
                command = b""
                while not command.endswith(b"\r"):
                    transport_byte = chan.recv(1024)
                    chan.send(transport_byte)  # Echo
                    command += transport_byte

                # Bytes zu String dekodieren
                command_str = command.strip().decode("utf-8")
                chan.send(b"\r\n")
                print("Befehl erhalten: '{}'".format(command_str))

                if command_str == "exit":
                    chan.close()
                    break
                else:
                    chan.send(b"Befehl nicht gefunden.\r\n")

        except Exception as e:
            print("*** Ausnahme: {}".format(e))
            traceback.print_exc()
            try:
                t.close()
            except:
                pass


if __name__ == "__main__":
    main()
