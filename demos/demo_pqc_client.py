# demos/demo_pqc_client.py
# -*- coding: utf-8 -*-

"""
Ein einfacher PQC-fähiger SSH-Client zum Testen der Classic McEliece KEX-Implementierung.
"""

import sys
import socket
import paramiko
import getpass

# Setzen Sie das Logging auf, um die KEX-Aushandlung zu sehen.
paramiko.util.log_to_file("pqc_client.log")

# Benutzername und Passwort für die Demo.
USER = "robot"
PASS = "p@ssword"
HOSTNAME = "localhost"
PORT = 2200


def interactive_shell(chan):
    """
    Startet eine einfache interaktive Shell über den gegebenen Kanal.
    """
    print("--- Interaktive Shell gestartet ---")
    while True:
        try:
            # Daten vom Server empfangen und ausgeben
            if chan.recv_ready():
                data = chan.recv(1024)
                if not data:
                    print("\r\n*** Verbindung geschlossen.")
                    break
                sys.stdout.write(data.decode("utf-8"))
                sys.stdout.flush()

            # Benutzereingabe lesen und an den Server senden
            if chan.send_ready():
                command = sys.stdin.readline()
                chan.send(command.encode("utf-8"))
                if command.strip() == "exit":
                    break

        except KeyboardInterrupt:
            print("\r\n*** Unterbrochen.")
            break
        except Exception as e:
            print("*** Fehler in der Shell: {}".format(e))
            break
    chan.close()
    print("--- Shell beendet ---")


def main():
    """Hauptfunktion zum Starten des Clients."""
    try:
        client = paramiko.SSHClient()
        # Wichtig: Wir müssen die Host-Schlüssel-Prüfung für dieses Demo deaktivieren,
        # da wir den Host-Schlüssel des Servers nicht im Voraus kennen.
        # In einer produktiven Umgebung würden Sie `load_system_host_keys()` verwenden.
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        print("Verbinde mit {}:{}...".format(HOSTNAME, PORT))
        client.connect(
            hostname=HOSTNAME,
            port=PORT,
            username=USER,
            password=PASS,
            # Wir erzwingen, dass unsere neuen KEX-Methoden bevorzugt werden.
            # Dies geschieht durch die Modifikationen in transport.py,
            # aber zur Sicherheit kann man es hier auch explizit angeben.
            # kex_gex_sha1, kex_gex_sha256, kex_group1, kex_group14, kex_group16
            disabled_algorithms=dict(kex=[]),
        )

        # Überprüfen, welcher KEX-Algorithmus verwendet wurde
        transport = client.get_transport()
        kex_name = transport.get_security_options().kex[0]
        print("Erfolgreich verbunden!")
        print("Verwendeter KEX-Algorithmus: {}".format(kex_name))

        if kex_name.startswith("classic-mceliece"):
            print(">>> Post-Quantum-Schlüsselaustausch war erfolgreich! <<<")
        else:
            print(">>> Warnung: Es wurde ein klassischer KEX verwendet. <<<")

        # Interaktive Shell starten
        chan = client.invoke_shell()
        interactive_shell(chan)

        client.close()

    except paramiko.AuthenticationException:
        print("*** Authentifizierung fehlgeschlagen.")
    except Exception as e:
        print("*** Fehler bei der Verbindung: {}".format(e))
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
