# RSAencryptor
A command-line program implementing the RSA encryption scheme. It supports generating keys using the Miller-Rabin test of primality, as well as encrypting and decrypting messages and .txt files. This project was completed as part of the requirements for Discrete Structures at CU Boulder.

## Features
- Message encryption/decryption
- File encryption/decryption (.txt files)
- Key generation with configurable key size
- Command-line interface with interactive prompts
- Implementation of fundamental cryptographic algorithms:
  - Fast Modular Exponentiation
  - Euclidean Algorithm
  - Extended Euclidean Algorithm
  - Sieve of Eratosthenes
  - Miller-Rabin Primality Test

## Dependencies
- Python 3.x
- Standard Python libraries only:
  - math
  - random
  - typing

## Installation
```bash
# Clone the repository
git clone [your-repository-url]

# Navigate to directory
cd RSAencryptor
```

## Usage
Run the program:
```bash
python rsa.py
```

The program will present an interactive menu with the following options:
1. Encrypt Message
2. Decrypt Message
3. Encrypt file
4. Decrypt file
5. Generate Keys
6. Quit

### Key Generation
- Supports customizable key size (minimum 3 digits)
- Uses Miller-Rabin primality testing with 40 rounds for secure prime generation
- Outputs both public and private keys

### File Operations
- Encrypts/decrypts .txt files
- Creates output files in the same directory as input
- Appends '_encrypted' or '_decrypted' to output filenames

### Message Operations
- Supports direct message input
- Provides options for different ciphertext formats
- Includes a mock address book for demonstration

## Implementation Details

### Security Features
- Miller-Rabin primality testing with 40 rounds
- Random prime number generation
- Secure key generation process

### Mathematical Functions
1. `FME(b, n, m)`: Fast Modular Exponentiation - computes b^n mod m efficiently
2. `Euclidean_Alg(a, b)`: Computes GCD of two numbers
3. `EEA(a, b)`: Extended Euclidean Algorithm - finds Bézout coefficients
4. `miller_rabin_test(n, k)`: Probabilistic primality testing
5. `generate_primes(n)`: Sieve of Eratosthenes implementation

## Code Structure
- Well-documented functions with type hints
- Modular design separating cryptographic operations from user interface
- Clear variable naming conventions (documented in code)
- Interactive command-line interface with error handling

## Contributing
This project was completed as coursework, but suggestions for improvements are welcome.

## Author
Daniel Williams

## License
MIT License

## Acknowledgments
- Course: Discrete Structures, CU Boulder
- Course instructors: Sriram Sankaranarayanan, Elizabeth Stade
