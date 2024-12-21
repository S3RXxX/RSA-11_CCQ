# RSA11 CCQ Sergi Guimerà Roig
import sympy as sp  # utilitzem sympy per tots els càlculs


class RSA:
    """classe per claus privades RSA on els n primers entren com a paràmetre"""
    def __init__(self, p=None, q=None, e=2**16 +1, n=None, len_modul=11):
        # assignem els valors als atributs
        self.e = e
        if (not p or not q):
            self.p, self.q, self.n = self.__find_primes(len_modul=len_modul)
        else:
            self.p, self.q = p, q
            self.n = self.p * self.q # calculem n
        
        if not n:
            pass
        else:
            self.n=n
            

        phi_n = (self.p - 1) * (self.q - 1)   
        self.k = sp.mod_inverse(self.e, phi_n) # calculem k (d)

    def __preprocess_string(self, m=""):
        # Codifiquem l’alfabet en termes del codi ASCII decimal, usant sempre tres xifres
        # Expressem el text pla per xifrar en una única string numèrica
        return ''.join(f"{ord(c):03d}" for c in m)
    
    def __decrypt(self, C="", mode="cipher"):
        """funció auxiliar per tasques on entren els missatges a recuperar
        desxifrar / verificar firma
        C és una string de números
        mode pot ser cipher o sign"""

        L = len(str(self.n))
        blocks = [C[i:i + L] for i in range(0, len(C), L)]  # Separa en blocks de long L
        P = ""
        for Ci in blocks:
            Ci = int(Ci)
            if mode=="cipher":
                Pi = pow(Ci, self.k, self.n)  # Decrypt block
            elif mode=="sign":
                Pi = pow(Ci, self.e, self.n)  # Decrypt block sign 
            else:
                raise AssertionError("Incorrect mode for decrypt")
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
    
    def __encrypt(self, P="", mode="cipher"):
        """funció auxiliar per tasques on entren els missatges textuals
        xifrar / signar
        P és una string de números
        mode pot ser cipher o sign"""

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
            if mode=="cipher":
                C = pow(P, self.e, self.n)  # com és xifrar elevem al públic
            elif mode=="sign":
                C = pow(P, self.k, self.n)  # com és firmar elevem al privat
            else:
                raise AssertionError("Incorrect mode for encrypt")
            
            encrypted_blocks.append(f"{C:0{L}d}")

        # concatenar
        encrypted_message = ''.join(encrypted_blocks)
        return encrypted_message
    
    def __sign(self, m):
        P = self.__preprocess_string(m)
        return self.__encrypt(P=P, mode="sign")
    
    def encrypt(self, m=""):
        P = self.__preprocess_string(m=m)
        return self.__encrypt(P=P, mode="cipher")

    def decrypt(self, C=""):
        return self.__decrypt(C=C, mode="cipher")

    def read_sign(self, F=""):
        return self.__decrypt(C=F, mode="sign")
    
    def pgp(self, m=""):
        sign = "- - - - - - - - - -PGP- - - - - - - - - -"
        sign += "\n"
        sign += str(self.n)
        sign += "\n"
        sign += str(self.e)
        sign += "\n"
        sign += self.__sign(m=m)
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


#########################
### funcions auxiliars ##
#########################
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
    
    k=rsa.k  # llegim la clau privada per després
    
    P = rsa.decrypt(C=C)  # desxifrem el missatge
    print(P)

    # fem un altre objecte RSA amb uns altres números primers per firma PGP
    pgp = RSA(e=3)
    
    to_sign = "Sergi Guimerà :)"
    signed_text = pgp.pgp(m=to_sign)
    to_save = "\n".join(["Factors_de_n_trobats" + " " + str(p) + " " + str(q), "Clau_privada_k " + str(k),"P "+P, signed_text])

    # guardem tots els resultats en un fitxer
    # write_file(file_path="./missatge-firmat.txt", text=to_save)

    # confirmem que s'ha firmat bé
    # n, e, C = read_file(file_path="./check_pgp.txt")
    # rsa = RSA(e=e, n=n)
    # P = rsa.read_sign(F=C)
    # print("signed message read", P)



