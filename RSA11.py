# RSA11 CCQ Sergi Guimerà Roig
import sympy as sp  # utilitzem sympy per tots els càlculs


class RSA:
    """classe per claus privades RSA on els n primers entren com a paràmetre"""
    def __init__(self, p=None, q=None, e=2**16 +1, len_modul=11):
        # assignem els valors als atributs
        self.e = e
        if not p or not q:
            self.p, self.q = self.__find_primes(len_modul=len_modul)
        else:
            self.p, self.q = p, q
            
        self.n = self.p * self.q # calculem n
        print(len(str(self.n)), self.n)

        phi_n = (self.p - 1) * (self.q - 1)   
        self.k = sp.mod_inverse(self.e, phi_n) # calculem k (d)
        # print(f"k: {self.k}")
    
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
    
    def pgp(self, m=""):
        pass

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
        lim_inf, lim_sup = 10**(len_modul//2 - 1), 10**(len_modul//2)-1
        
        p = self.__generate_prime(lim_inf, lim_sup)
        q = self.__generate_prime(lim_inf, lim_sup)
        while p == q:
            q = self.__generate_prime(lim_inf, lim_sup)          
        return p, q
    
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
    
def write_file(file_path):
    pass

if __name__=="__main__":

    n, e, C = read_file()  # llegim el missatge xifrat

    p, q = factoritza(n=n)  # factoritzem n

    rsa = RSA(p=p, q=q, e=e)  # creem un objecte RSA per calcular totes les variables necessaries per RSA

    P = rsa.decrypt(C=C)  # desxifrem el missatge
    print(P)

    # fem un altre objecte RSA amb uns altres números primers per firma PGP
    pgp = RSA(e=3)
    # pgp.pgp()

    # provar longitud = 11
    while True:
        RSA(e=3)

    # guardem tots els resultats en un fitxer
    # write_file(file_path="./")

