"""
This command line program implements the RSA encryption scheme. It supports
generating keys using the Miller Rabin test of primality, as well as encrypting
and decrypting messages and .txt files. It was completed as part of the 
requirements for Discrete Structures at CU Boulder. 

"""
import math
import random
import typing

"""
General comments about variable names.

When n, e, and d are used in function signatures, they refer
to these:
    - a public key is an integer tuple (n, e).
    - a private key is an integer tuple (n, d).
"""

def Convert_Binary_String(_int: int) -> str:
    """Converts _int to bitstring"""
    l = []
    while _int > 0:
        k = _int % 2
        l.insert(0,k)
        _int = _int // 2
    
    ret = ''
    for ch in l:
        ret += str(ch)
        
    return ret

def FME(b: int, n: int, m: int) -> int:
    """Returns b ** n mod m
    Fast Modular Exponentiation
    """
    result = 1
    square = b
    while n > 0:
        k = n % 2
        n = int(n/2)
        if k == 1:
            result = result*square % m
        square = square*square % m
    
    return result

def Euclidean_Alg(a: int, b: int) -> int:
    """Returns gcd(a,b)"""
    # ensure a > b
    if b > a:
        tmp = a
        a = b
        b = tmp
        
    while b > 0:
        k = a % b
        a = b
        b = k
        
    return a

def EEA(a: int, b: int) -> tuple[int,int,int]:
    """Returns gcd(a,b) and Bézout coeffs
    Example: EEA(77,43) -> (1,19,-34)
    """
    # ensure a > b
    if b > a:
        tmp = a
        a = b
        b = tmp
    
    s1, t1 = 1, 0
    s2, t2 = 0, 1

    while b > 0:
        k = a % b
        q = a // b

        a = b
        b = k

        s1hat, t1hat = s2, t2
        s2hat, t2hat = s1-q*s2, t1-q*t2

        s1, t1 = s1hat, t1hat
        s2, t2 = s2hat, t2hat

    return (a, s1, t1)

def Find_Public_Key_e(p: int, q: int) -> tuple[int,int]:
    """Calculates public key
    ASSUME p and q are prime
    """
    n = p*q
    
    modulus = (p-1)*(q-1)
    
    # will choose from list of possible e's
    lst = list(range(2,modulus))

    for i in range(2,modulus):
        e = random.choice(lst)  
        gcd = Euclidean_Alg(e, modulus)
        if gcd == 1 and e != p and e != q:
            break
        else:
            lst.remove(e)
            
    return (n, e)

def Find_Private_Key_d(e: int, p: int, q: int) -> int:
    """Calculates d"""
    m = (p-1)*(q-1)
    EEA_result = EEA(e,m)
    d = EEA_result[2]
    
    # in case d is negative
    while d < 0:
        d += m
    
    return d

def Encode(n: int, e: int, message: str) -> list[str]:
    """Encodes message using public key"""
    block_size = find_block_size(n)
    
    cipher_text = []
    
    translated_message = Convert_Text(message)
    

    for ch in translated_message:
        enciphered_message = FME(ch,e,n)
        enciphered_message = str(enciphered_message)
        while len(enciphered_message) < block_size:
            # prepend zeros to have uniform block size
            enciphered_message='0'+enciphered_message
        cipher_text.append(enciphered_message)

    return cipher_text

def Convert_Text(_string: str) -> list[int]:
    """Converts each char in string to ASCII int"""
    integer_list = []
    
    for ch in _string:
        integer_list.append(ord(ch))

    return integer_list

def Convert_Num(_list: list[int]) -> str:
    """Coverts ASCII ints in _list to string"""
    _string = ''
    for i in _list:
        _string += chr(i)
    return _string

def Decode(n: int, d: int, cipher_text: list[int]) -> str:
    """Uses priv key to decode cipher_text"""
    decrypted_text = []    
    for number in cipher_text:
        decrypted_text.append(FME(number, d, n))
    message = Convert_Num(decrypted_text)

    return message

def generate_primes(n: int) -> list[int]:
    """Generates all primes up to n using sieve of eratosthenes"""
    
    # l are odd numbers from 3 to sqrt(n)
    l = list(range(3,math.ceil(math.sqrt(n)),2))
    
    # odd numbers up to n
    i = list(range(3,n,2))
    
    for p in l:
        a = p
        while p < n:
            # generate next multiple of p
            p += a                
            # sieve out p from i
            if p in i:          
                i.remove(p)

    i.insert(0,2)

    return i

def generate_primes_in_range(m: int, n: int) -> list[int]:
    """Generates primes in [m,n]"""
    primes = generate_primes(n)
    primes_in_range = [prime for prime in primes if prime > m]
    return primes_in_range

def find_block_size(n: int) -> int:
    """Determines number digits in n"""
    block_size = 0
    while n > 1:
        n = n/10
        block_size += 1
    return block_size

def encrypt_file(filepath: str, n: int, e: int) -> None:
    """Encrypts .txt file and writes _encrypted.txt to same folder as input file"""
    block_size = find_block_size(n)
    M = []
    with open(filepath, 'r') as file:
        while True:
            block = file.read(block_size)
            if len(block) < block_size:
                block2 = block
                M.append(block2)
            else:
                M.append(block)
            if not block:
                break
    M.pop()
    index = filepath.find('.')
    new_filepath = filepath[:index]
    with open(new_filepath + '_encrypted.txt', 'w') as file:
        for block in M:
            C = Encode(n,e,block)
            for ch in C:
                str_ch = str(ch)
                # prepend 0's to have uniform block size
                while len(str_ch) < block_size:
                    str_ch = '0' + str_ch
                file.write(str_ch)

def decrypt_file(filepath: str, n: int, d: int) -> None:
    """Decrypts a .txt file, writes _decrypted.txt to same folder as input file"""
    block_size = find_block_size(n)
    C = []
    with open(filepath, 'r') as file:
        while True:
            block = file.read(block_size)
            C.append(block)
            if not block:
                break
    C.pop()
    C_int = [int(s) for s in C]
    index = filepath.find('.')
    new_filepath = filepath[:index]
    with open(new_filepath + '_decrypted.txt', 'w') as file:
        file.write(Decode(n,d,C_int))

def factorize(n: int) -> list[int]:
    """Brute force algorithm for factoring n
    returns list of factors, empty list if prime
    """
    factors = []
    for i in range(2,n):
        if n % i == 0:
            factors.append(i)
    return factors

def break_key(n: int, e: int, C: list[int]) -> tuple[int, int]:
    """Given public key and ciphertext, returns private key"""
    factors = factorize(n)
    for i in range(len(factors)):
        p = factors[i]
        for j in range(i + 1,len(factors)):
            q = factors[j]
            d = Find_Private_Key_d(e,p,q)
            print('*'*10)
            print('Decoded message:', Decode(n,d,C))
            print('Private key:', d)
            return n,d

def miller_rabin_test(n: int, k: int) -> str:
    """Returns 'composite' if n is composite, 'probably prime' otherwise
    
    n>2, an odd integer to be tested for primality
    k, the number of rounds of testing to perform
    
    from Wikipedia: https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
    """
    # find s,d such that (2**s)d = n - 1
    m = n-1
    d = m
    s = 0
    while d % 2 == 0:
        d /= 2
        s += 1

    # run test k times; if composite-ness property not found, n is probably prime
    for i in range(k):
        a = random.choice(list(range(2,n-2)))
        x = FME(a,d,n)
        for j in range(s):
            y = x**2 % n
            if y == 1 and x != 1 and x != m:
                return "composite"
            x = y
        if y != 1:
            return "composite"
            
    return "probably prime"

def generate_n_dig_keys(t: int) -> tuple[int,int,int]:
    """Generates primes p,q of approx. len(t) and uses them to produce (n,e,d)"""
    primes = []
    count = 0

    lower = 10**(t-1)+1
    upper = 10**t+1

    for i in range(lower,upper,2):
        n = random.choice(list(range(lower,upper,2)))
        p = miller_rabin_test(n,40)
        if p == "probably prime":
            if p not in primes:
                primes.append(n)
                count += 1
            if count == 2:
                break
                
    p,q = primes
    n = (p-1)*(q-1)
    
    n,e = Find_Public_Key_e(p,q)
    d = Find_Private_Key_d(e,p,q)

    return (n,e,d)

def break_file(n: int, e: int, filepath: str) -> int:
    """Given a public key (n,e) and a filepath, will attempt to break public key"""
    C=[]
    block_size = find_block_size(n)
    with open(filepath, 'r') as file:
        for i in range(10):
            block = file.read(block_size)
            C.append(block)
            
    C_int = [int(x) for x in C]

    d = break_key(n,e,C_int)
    return d

def display_address_book() -> None:
    """Prints fake address book"""
    print("Here is our address book:")
    print('John Doe (264607518881, 127427) \nJane Eyre (290208112387, 459953) \nMoby Duck (136906631761, 257953)\n')

def prompt_pubkey() -> tuple[int,int]:
    """Prompts for public key"""
    prompt = input("Enter public key as xxx, yyy: ")
    n,e = prompt.split(',')
    n,e = int(n),int(e)
    return n,e

def prompt_privkey() -> tuple[int,int]:
    """Prompts for private key"""
    prompt = input("Enter private key as xxx, yyy, or -1 if you do not know: ")
    if prompt == '-1':
        return -1,-1
    n,d = prompt.split(',')
    n,d = int(n),int(d)
    return n,d

def prompt_kind_of_ciphertext(n: int) -> list[int]:
    """Prompts for format of ciphertext
    Returns ciphertext as list of ints
    """
    print('Choose a format to enter your ciphertext:')
    format = input("1=[xxx, yyy, zzz, ...]\n2='xxxyyyzzz...'\n")
    if format == '1':
        return prompt_ciphertext()
    elif format == '2':
        return prompt_ciphertext2(n)
    else:
        return prompt_kind_of_ciphertext()

def prompt_ciphertext() -> list[int]:
    """Prompts for a ciphertext in list form; converts strings to ints
    Returns list of ints
    """
    prompt = input('Enter a ciphertext as [xxx, yyy, zzz, ...]: ')
    prompt = prompt.replace(',','')
    prompt = prompt[1:-1]
    if "'" in prompt:
        prompt = prompt.replace("'", "")
    prompt = prompt.split(' ')
    prompt = [int(c) for c in prompt]
    return prompt

def prompt_ciphertext2(n: int) -> list[int]:
    """Prompts for ciphertext as a single string
    Returns ciphertext as list of ints
    """
    prompt = input('Enter a ciphertext as a single string: ')
    block_size = find_block_size(n)
    num_blocks = len(prompt)//block_size
    C = []
    for i in range(num_blocks):
        C.append(int(prompt[block_size*i:(block_size*i+block_size)]))
    C = [int(c) for c in C]
    return C

def prompt_break_key() -> tuple[int,int] | bool:
    """Prompts whether to break key; 
    if yes, returns private key; if no, false
    """
    print("Do you wish to try to break the key?")
    prompt = prompt_yes_no()
    if prompt == '1':
        n,e = prompt_pubkey()
        C = prompt_kind_of_ciphertext(n)
        n,d = break_key(n,e,C)
        return n,d
    elif prompt == '2':
        return False
    else:
        return prompt_yes_no()

def prompt_yes_no() -> str:
    """Prompts yes or no"""
    prompt = input('1=Yes\n2=No\n')
    if prompt not in ['1','2']:
        return prompt_yes_no()
    else:
        return prompt

def prompt_message() -> str:
    """Prompts for a message to encrypt"""
    prompt = input('Enter a message to encrypt: ')
    return prompt

def prompt_continue() -> bool:
    """Prompts to continue or not
    Returns true if yes, false otherwise
    """
    print(('Continue?'))
    prompt2 = prompt_yes_no()
    if prompt2 == '1':
        return True
    else:
        return False

def prompt_concatenate(C) -> str:
    """Prompts to concatenate or not
    If yes, returns ciphertext as string; False if no
    """
    print('Do you want to concatenate?')
    prompt = prompt_yes_no()
    if prompt == '1':
        S = ''
        for block in C:
            S += str(block)
        return S
    elif prompt == '2':
        return ''
    else:
        return prompt_concatenate(C)

def prompt_digs() -> int:
    """Prompt for length of key"""
    prompt = int(input('Enter approximately how many digits you want your keys to be (must be at least 3 digits): '))
    if prompt < 3:
        return prompt_digs()
    if prompt == 3:
        return 2
    else:
        prompt = prompt//2
        return prompt

def prompt_menu() -> str:
    """Prompt for menu options"""
    prompt = input('\nChoose:\n1=Encrypt Message\n2=Decrypt Message\n3=Encrypt file\n4=Decrypt file\n5=Generate Keys\n6=Quit\n\n')
    return prompt

def main():
    print("\nWelcome to the RSA Encryptor! We support encrypting and decrypting simple messages as well as .txt files.")
    print("You can also generate public and private keys here.")
    
    while True:
        prompt = prompt_menu()
        # Encrypt message option
        if prompt == '1':
            print("Do you have the recipient's public key?")
            prompt2 = prompt_yes_no()
            if prompt2 == '1':
                n,e = prompt_pubkey()
                M = prompt_message()
                C = Encode(n,e,M)
                print('Your encrypted message is below:')
                print(C)
                S = prompt_concatenate(C)
                if S:
                    print('Your encrypted message is below:')
                    print(S)
                if not prompt_continue():
                    break

            elif prompt2 == '2':
                print("Would you like to view our address book?")
                prompt3 = prompt_yes_no()
                if prompt3 == '1':
                    display_address_book()
                    n,e = prompt_pubkey()
                    M = prompt_message()
                    C = Encode(n,e,M)
                    print('Your encrypted message is below:')
                    print(C)
                    S = prompt_concatenate(C)
                    print('Your encrypted message is below:')
                    print(S)
                    if not prompt_continue():
                        break
                else:
                    break
                
        # Decrypt message option
        elif prompt == '2':
            n,d = prompt_privkey()
            if n == -1:
                prompt_break_key()
            else: 
                C = prompt_kind_of_ciphertext(n)
                M = Decode(n,d,C)
                print('Your decrypted message is below:')
                print(M)
            if not prompt_continue():
                break
            
        # Encrypt file option
        elif prompt == '3':
            while True:
                print("Do you have the recipient's public key? ")
                prompt2 = prompt_yes_no()
                if prompt2 == '1':
                    n,e = prompt_pubkey()
                    prompt3 = input("Enter the path to the file you want to encrypt: ")
                    encrypt_file(prompt3,n,e)
                    print(f"\n-->You should now have a file in the same folder as the input file, with '_encrypted' added to the filename.")
                    break
                
                # Does not have pubkey
                elif prompt2 == '2':
                    print("Would you like to view our address book?")
                    prompt3 = prompt_yes_no()
                    if prompt3 == '1':
                        display_address_book()
                        n,e = prompt_pubkey()
                        prompt = input("Enter the path to the file you want to encrypt: ")
                        encrypt_file(prompt,n,e)
                        print(f"\n-->You should now have a file in the same folder as the input file, with '_encrypted' added to the filename.")
                        break
                    else:
                        break
                else:
                    continue
            
        # Decrypt option
        elif prompt == '4':
            prompt2 = input("Enter the path to the file you want to decrypt: ")
            n,d = prompt_privkey()
            if n == -1:
                n,d = prompt_break_key()
            decrypt_file(prompt2, n, d)
            print(f"\n-->You should now have a file in the same folder as the input file, with '_decrypted' added to the filename.")
            if not prompt_continue():
                break
            
        # Generate Keys option
        elif prompt == '5':
            len_digs = prompt_digs()
            n,e,d = generate_n_dig_keys(len_digs)
            print(f"Your public key is {n}, {e}.")
            print(f"Your private key is {n}, {d}.")
            if not prompt_continue():
                break
        elif prompt == '6':
            break
        else:
            continue

    print("Thank you for using the RSA Encryptor!")

if __name__ == "__main__":
    main()