# RSA11 CCQ Sergi Guimerà Roig
import sympy as sp  # utilitzem sympy per tots els càlculs


class RSA:
    """classe per claus privades RSA on els n primers entren com a paràmetre"""
    def __init__(self, p=2, q=3, e=2**16 +1):
        # assignem els valors als atributs
        self.e = e
        self.p, self.q = p, q
        self.n = self.p * self.q # calculem n
        
        phi_n = (self.p - 1) * (self.q - 1)   
        self.k = sp.mod_inverse(self.e, phi_n) # calculem k (d)
        # print(f"k: {self.k}")

    def encrypt(self, m=""):
        pass
    
    def decrypt(self, C=""):
        L = len(str(self.n))
        blocks = [C[i:i + L] for i in range(0, len(C), L)]  # Separa en blocks de long L
        P = ""
        for Ci in blocks:
            Ci = int(Ci)
            Pi = pow(Ci, self.k, self.n)  # Decrypt block
            Pi = str(Pi).zfill(L - 1)  # Assegura L-1 digits
            P += Pi

        # cas expecial de ASCII
        if int(P[:3]) > 254:
            P = "0" + P

        # print(f"Multiple de 3: {len(P)%3==0}")
        # passar a text
        plaintext = ""
        for i in range(0, len(P), 3):
            ascii_code = int(P[i:i + 3])
            plaintext += chr(ascii_code)
        # print(plaintext)
        return plaintext


    
    def __repr__(self):
        return str(self.__dict__)


def factoritza(n):
    return sp.factorint(n).keys()

def read_file(file_path = "./missatge-encriptat"):
    """retorna la 3-tupla n, e, P
    n, e com a int
    P com a string
    """
    with open(file=file_path) as f:
        n = f.readline().strip()
        e = f.readline().strip()
        P = f.readline().strip()
        return int(n), int(e), P
    
def write_file(file_path):
    pass

if __name__=="__main__":

    n, e, P = read_file()  # llegim el missatge xifrat

    p, q = factoritza(n=n)  # factoritzem n

    rsa = RSA(p=p, q=q, e=e)  # creem un objecte RSA per calcular totes les variables necessaries per RSA

    m = rsa.decrypt(P)  # desxifrem el missatge

    # guardem tots els resultats en un fitxer
    write_file(file_path="./")

