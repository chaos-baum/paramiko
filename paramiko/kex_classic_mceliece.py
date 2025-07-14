# paramiko/kex_classic_mceliece.py
# -*- coding: utf-8 -*-

from hashlib import sha256, sha512
import oqs

from .message import Message
from .ssh_exception import SSHException
from oqs import MechanismNotEnabledError


# Benutzerdefinierte Nachrichtennummern für unseren neuen KEX.
# Der Bereich 30-49 ist für KEX-Protokolle reserviert.
MSG_KEX_OQS_INIT = 32
MSG_KEX_OQS_REPLY = 33
c_MSG_KEX_OQS_INIT = bytes([MSG_KEX_OQS_INIT])
c_MSG_KEX_OQS_REPLY = bytes([MSG_KEX_OQS_REPLY])


class KexClassicMcEliece:
    """
    Basisklasse für einen reinen PQC-Schlüsselaustausch mit Classic McEliece.
    Subklassen müssen `name`, `kem_name` und `hash_algo` definieren.
    """

    # Diese Attribute müssen in den Subklassen definiert werden.
    name = None
    kem_name = None
    hash_algo = None
    public_key_size = None

    def __init__(self, transport):
        self.transport = transport
        self.client_kem_instance = None
        self.client_public_key = None

        if self.kem_name not in oqs.get_enabled_kem_mechanisms():
            raise MechanismNotEnabledError(
                f"\n\n*** KEM-Algorithm '{self.kem_name}' not activated! ***\n"
            )

    def start_kex(self):
        """Startet den Schlüsselaustausch."""
        if self.transport.server_mode:
            self.transport._expect_packet(MSG_KEX_OQS_INIT)
            return

        # Client-Modus:
        self.client_kem_instance = oqs.KeyEncapsulation(self.kem_name)
        self.client_public_key = self.client_kem_instance.generate_keypair()

        m = Message()
        m.add_byte(c_MSG_KEX_OQS_INIT)
        m.add_bytes(self.client_public_key)
        self.transport._send_message(m)
        self.transport._expect_packet(MSG_KEX_OQS_REPLY)

    def parse_next(self, ptype, m):
        """Verarbeitet die nächste eingehende KEX-Nachricht."""
        if self.transport.server_mode:
            if ptype == MSG_KEX_OQS_INIT:
                return self._parse_kex_init(m)
        else:  # Client-Modus
            if ptype == MSG_KEX_OQS_REPLY:
                return self._parse_kex_reply(m)
        raise SSHException("Invalid Packettype {} ".format(ptype))

    def _parse_kex_init(self, m):
        """Server-Seite: Verarbeitet die INIT-Nachricht des Clients."""
        client_public_key = m.get_bytes(self.public_key_size)

        server_kem = oqs.KeyEncapsulation(self.kem_name)
        ciphertext, shared_secret = server_kem.encap_secret(client_public_key)

        server_host_key = self.transport.get_server_key()
        host_key_blob = server_host_key.asbytes()
        self._calculate_exchange_hash(host_key_blob, client_public_key, shared_secret)

        signature = server_host_key.sign_ssh_data(self.transport.H)

        m_reply = Message()
        m_reply.add_byte(c_MSG_KEX_OQS_REPLY)
        m_reply.add_string(host_key_blob)
        m_reply.add_string(ciphertext)
        m_reply.add_string(signature)
        self.transport._send_message(m_reply)

        k_as_int = int.from_bytes(shared_secret, "big")
        self.transport._set_K_H(k_as_int, self.transport.H)
        self.transport._activate_outbound()

    def _parse_kex_reply(self, m):
        """Client-Seite: Verarbeitet die REPLY-Nachricht des Servers."""
        host_key_blob = m.get_string()
        ciphertext = m.get_string()
        signature_blob = m.get_string()

        shared_secret = self.client_kem_instance.decap_secret(ciphertext)

        self._calculate_exchange_hash(
            host_key_blob, self.client_public_key, shared_secret
        )

        self.transport._verify_key(host_key_blob, signature_blob)

        k_as_int = int.from_bytes(shared_secret, "big")
        self.transport._set_K_H(k_as_int, self.transport.H)
        self.transport._activate_outbound()

        self.client_kem_instance.free()

    def _calculate_exchange_hash(self, host_key_blob, client_public_key, shared_secret):
        if self.transport.server_mode:
            V_C = self.transport.remote_version
            V_S = self.transport.local_version
            I_C = self.transport.remote_kex_init
            I_S = self.transport.local_kex_init
        else:
            V_C = self.transport.local_version
            V_S = self.transport.remote_version
            I_C = self.transport.local_kex_init
            I_S = self.transport.remote_kex_init

        m = Message()
        m.add_string(V_C)
        m.add_string(V_S)
        m.add_string(I_C)
        m.add_string(I_S)
        m.add_string(host_key_blob)
        m.add_bytes(client_public_key)
        m.add_string(shared_secret)

        self.transport.H = self.hash_algo(m.asbytes()).digest()


class KexClassicMcEliece348864(KexClassicMcEliece):
    """NIST Security Level 1"""

    name = "classic-mceliece-348864-sha256"
    kem_name = "Classic-McEliece-348864"
    hash_algo = sha256
    public_key_size = 261120


class KexClassicMcEliece460896(KexClassicMcEliece):
    """NIST Security Level 3"""

    name = "classic-mceliece-460896-sha512"
    kem_name = "Classic-McEliece-460896"
    hash_algo = sha512
    public_key_size = 524160


class KexClassicMcEliece6688128(KexClassicMcEliece):
    """NIST Security Level 5"""

    name = "classic-mceliece-6688128-sha512"
    kem_name = "Classic-McEliece-6688128"
    hash_algo = sha512
    public_key_size = 1044992


class KexClassicMcEliece6960119(KexClassicMcEliece):
    """NIST Security Level 5"""

    name = "classic-mceliece-6960119-sha512"
    kem_name = "Classic-McEliece-6960119"
    hash_algo = sha512
    public_key_size = 1047319


class KexClassicMcEliece8192128(KexClassicMcEliece):
    """NIST Security Level 5"""

    name = "classic-mceliece-8192128-sha512"
    kem_name = "Classic-McEliece-8192128"
    hash_algo = sha512
    public_key_size = 1357824
