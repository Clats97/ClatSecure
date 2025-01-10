# README: AES Key Generator and Encryption Framework

## Overview
This project implements AES key generation and encryption utilities in Python, including:
- **128-bit, 192-bit & 256-bit AES encryption key generation** using Argon2i for key derivation.
- AES key expansion and encryption round functionality with S-Box, Rcon, and XOR operations.

### Key Features
- Generates secure AES keys with **high entropy**.
- Supports encryption rounds compliant with AES.
- Provides functionality for **key expansion**, **round transformations**, and **state operations**.

---

## Installation

### Required Python Libraries
The following libraries are needed to run the script:
1. **os**: For generating secure random salts.
2. **numpy**: For efficient matrix manipulations and transformations.
3. **argon2-cffi**: For cryptographic key derivation using Argon2.

Install the dependencies using pip:

pip install numpy argon2-cffi

## How It Works

### 1. Key Derivation
Keys are derived from a password using Argon2i with a randomly generated 16-byte salt.
This ensures secure and reproducible keys, ideal for cryptographic purposes.

### 2. AES Key Expansion
The generated key undergoes an **expansion process** to create round keys used during encryption:
- **Rcon** and **S-Box** operations are applied for non-linear transformations.
- Intermediate keys are XORed to create the expanded keys for each round.

### 3. Encryption Rounds
The state matrix is transformed in the following sequence:
1. **SubBytes**: Substitutes bytes using the AES S-Box.
2. **ShiftRows**: Rotates rows of the state matrix.
3. **MixColumns**: Combines columns (simplified in this implementation).
4. **AddRoundKey**: XORs the state with the current round key.

### 4. Final Round
The final round omits the **MixColumns** step:
1. **SubBytes**
2. **ShiftRows**
3. **AddRoundKey**

---

## Usage

### Running the Script
1. Enter a password when prompted. The script will generate 100 AES keys, apply the encryption rounds, and display the final state in hexadecimal format.
2. Run the script:

### Example Output
Enter password: mypassword
Final state (hexadecimal):
C0A1B2C3D4E5F60789AB12CD34EF5678


## Limitations
- **MixColumns**: This implementation uses a simplified version, not the GF(2^8) operations defined in the AES standard.

## Applications
- Encrypting sensitive data using AES encryption.
- Secure password-derived key generation for cryptographic use.
- Testing and learning cryptographic algorithms.

---

## License
This project is open-source under the Apache 2.0 License.

--- 

## Contributing
Contributions are welcome! Feel free to open issues or submit pull requests to improve functionality or compliance with AES standards.

Histograms of outputs:

![histogram1](https://github.com/user-attachments/assets/6dab58b4-ec22-49ea-b6a5-8729ae4c398e)


![histogram2](https://github.com/user-attachments/assets/842ed410-c6d5-48bc-a733-cbf568d981b4)
