# RSA11 CCQ Sergi Guimerà Roig
import sympy as sp  # utilitzem sympy per tots els càlculs


class RSA:
    """classe per claus privades RSA on els n primers entren com a paràmetre"""
    def __init__(self, p=None, q=None, e=2**16 +1, len_modul=11):
        # assignem els valors als atributs
        self.e = e
        if not p or not q:
            self.p, self.q, self.n = self.__find_primes(len_modul=len_modul)
        else:
            self.p, self.q = p, q
            self.n = self.p * self.q # calculem n

        phi_n = (self.p - 1) * (self.q - 1)   
        self.k = sp.mod_inverse(self.e, phi_n) # calculem k (d)

    
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

        # passar a text
        plaintext = ""
        for i in range(0, len(P), 3):
            ascii_code = int(P[i:i + 3])
            plaintext += chr(ascii_code)

        return plaintext
    
    def encrypt(self, m=""):
        # Codifiquem l’alfabet en termes del codi ASCII decimal, usant sempre tres xifres
        # Expressem el text pla per xifrar en una ´unica string num`erica
        P = ''.join(f"{ord(c):03d}" for c in m)

        # Tallem en blocs de L-1 digits
        L = len(str(self.n))
        block_size = L - 1
        blocks = [P[i:i + block_size] for i in range(0, len(P), block_size)]

        # Afegim 0 al de la dreta si necessari
        if len(blocks[-1]) < block_size:
            blocks[-1] = blocks[-1].ljust(block_size, '0')

        # Xifrem: Ci = Pi^e mod n
        encrypted_blocks = []
        for block in blocks:
            P = int(block)
            C = pow(P, self.e, self.n)
            encrypted_blocks.append(f"{C:0{L}d}")

        # concatenar
        encrypted_message = ''.join(encrypted_blocks)
        return encrypted_message
    
    def pgp(self, m=""):
        sign = m
        sign += "\n"
        sign += "- - - - - - - - - -PGP- - - - - - - - - -"
        sign += "\n"
        sign += str(self.n)
        sign += "\n"
        sign += str(self.e)
        sign += "\n"
        sign += self.encrypt(m=m)
        return sign

    def __generate_prime(self, lim_inf, lim_sup):
        while True:
            p = sp.randprime(lim_inf, lim_sup)
            if sp.gcd(p-1, self.e) == 1:
                return p

    def __find_primes(self, len_modul):
        """
        encuentra dos números primeros de longitud bits_modulo/2
        tq ...
        """
        lim_inf, lim_sup = 10**(len_modul // 2 - 1), 10**(len_modul // 2 + 1) - 1
        
        while True:
            p = self.__generate_prime(lim_inf, lim_sup)
            q = self.__generate_prime(lim_inf, lim_sup)
            n = p*q
            if len(str(n))==len_modul and p!=q:
                return p, q, n
    
    def __repr__(self):
        return str(self.__dict__)


def factoritza(n):
    return sp.factorint(n).keys()



def read_file(file_path = "./missatge-encriptat"):
    """retorna la 3-tupla n, e, C
    n, e com a int
    C com a string
    """
    with open(file=file_path) as f:
        n = f.readline().strip()
        e = f.readline().strip()
        C = f.readline().strip()
    return int(n), int(e), C
    
def write_file(file_path="./a", text=""):
    with open(file=file_path, mode="w") as f:
        f.write(text)

if __name__=="__main__":

    n, e, C = read_file()  # llegim el missatge xifrat

    p, q = factoritza(n=n)  # factoritzem n

    rsa = RSA(p=p, q=q, e=e)  # creem un objecte RSA per calcular totes les variables necessaries per RSA

    P = rsa.decrypt(C=C)  # desxifrem el missatge
    # print(P)

    # fem un altre objecte RSA amb uns altres números primers per firma PGP
    pgp = RSA(e=3)
    to_save = "\n".join(["Factors_de_n " + str("_") + " " + str("_"), "Clau_privada_k " + str(rsa.k),"P "+P])
    signed_text = pgp.pgp(m=to_save)

    # guardem tots els resultats en un fitxer
    # write_file(file_path="./missatge-firmat.txt", text=signed_text)

    # confirmem que s'ha firmat bé
    # n, e, C = read_file(file_path="./check_pgp")
    # p, q = factoritza(n=n)
    # rsa = RSA(p=p, q=q, e=e)
    # P = rsa.decrypt(C=C)
    # print(P)



