from ecies.utils import generate_eth_key
from ecies import encrypt, decrypt
import base64

llaves = {}


def agregar_llave(nombrep: str, llavep: str):
    llaves[nombrep] = llavep


def devolver_llave(nombred: str):
    return llaves[nombred]


class ObjetoSeguro:
    def __init__(self, nombre: str):
        self.nombre = nombre
        self.__gen_llaves()
        self.__privKeyHex, \
        self.pubKeyHex = self.__gen_llaves()
        self.__usario_destino = ""
        self.__id = 0
        self.__registro = {}
        self.__mensaje_recibido = ""
        agregar_llave(self.nombre, self.pubKeyHex)
        archivo_de_registro = "RegistroMsj_" + self.nombre + ".txt"
        archivo_de_registro = open(archivo_de_registro, 'w')
        archivo_de_registro.close()

    def __gen_llaves(self):
        privkey = generate_eth_key()
        privkey0x = privkey.to_hex()
        pubkey0x = privkey.public_key.to_hex()
        return privkey0x, pubkey0x

    def saludar(self, name: str, msj: str) -> bytes:
        self.__usario_destino = name
        llave_pub_d = self.llave_publica()
        return self.__cifrar_msj(llave_pub_d, msj)

    def esperar_respuesta(self, msj: bytes):
        msj = self.__decodificar64(self.__descifrar_msj(msj))
        print("El texto claro recibido es ", msj)
        self.__almacenar_msj(msj)
        self.__mensaje_recibido = msj

    def __almacenar_msj(self, msj: str) -> dict:
        archivo = "RegistroMsj_" + self.nombre + ".txt"
        self.__registro[self.__id] = {
            "ID": self.__id,
            "MSJ": msj
            }
        with open(archivo, 'a') as f:
            f.write(str(self.__registro[self.__id]) + str("\n"))
        self.__id += 1
        return {"ID": self.__id}

    def consultar_msj(self, id: int):
        archivo = "RegistroMsj_" + self.nombre + ".txt"
        cont = 0
        with open(archivo, 'r') as buscar:
            for line in buscar:
                if cont == id:
                    print(line)
                    return line
                cont += 1
        return "error1"

    def responder(self, nombre: str):
        self.__usario_destino = nombre
        msj = self.__mensaje_recibido
        llave_pub = self.llave_publica()
        return self.__cifrar_msj(llave_pub, msj + " Mensaje Respuesta")

    def llave_publica(self) -> str:
        return devolver_llave(self.__usario_destino)

    def __codificar64(self, msj: str) -> bytes:
        msj_bytes = msj.encode('ascii')
        return base64.b64encode(msj_bytes)

    def __decodificar64(self, msj: bytes) -> str:
        msj_bytes = base64.b64decode(msj)
        return msj_bytes.decode('ascii')

    def __cifrar_msj(self, pub_key: str, msj: str) -> bytes:
        return encrypt(pub_key, self.__codificar64(msj))

    def __descifrar_msj(self, msj: bytes) -> bytes:
        return decrypt(self.__privKeyHex, msj)


ANA = ObjetoSeguro("ANA")
DAVID = ObjetoSeguro("DAVID")

mensaje_c = ANA.saludar("DAVID", "Mi nombre es ANA")
DAVID.esperar_respuesta(mensaje_c)
respuesta = DAVID.responder("ANA")
ANA.esperar_respuesta(respuesta)

ANA.consultar_msj(0)
