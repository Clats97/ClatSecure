import os
import numpy as np
from argon2.low_level import hash_secret_raw, Type
from pystyle import Write, Colors

ROUND_COUNT = 40
KEY_SIZE = 32

S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01,
    0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D,
    0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4,
    0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7,
    0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E,
    0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB,
    0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB,
    0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C,
    0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C,
    0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D,
    0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A,
    0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3,
    0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A,
    0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E,
    0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9,
    0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9,
    0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99,
    0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]

RCON = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
    0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6,
    0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91,
    0x39, 0x72, 0xE4, 0x9D, 0x23, 0x46, 0x8C, 0x01, 0x02, 0x04
]

def generate_aes_key(password: bytes, salt: bytes = None):
    if salt is None:
        salt = os.urandom(128)
    try:
        key = hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=20,
            memory_cost=1024000,
            parallelism=8,
            hash_len=KEY_SIZE,
            type=Type.ID
        )
        return key, salt
    except Exception as e:
        raise ValueError(f"Key derivation failed: {str(e)}")

def sub_word(word):
    return [S_BOX[b] for b in word]

def rot_word(word):
    return word[1:] + word[:1]

def xor_words(word1, word2):
    return [a ^ b for a, b in zip(word1, word2)]

def key_expansion(key):
    expanded_keys = []
    rcon_iter = 1

    for i in range(KEY_SIZE // 4):
        expanded_keys.append([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]])

    for i in range(KEY_SIZE // 4, 4 * (ROUND_COUNT + 1)):
        temp = expanded_keys[-1][:]
        # Every (KEY_SIZE // 4) words, apply Rcon
        if i % (KEY_SIZE // 4) == 0:
            temp = xor_words(sub_word(rot_word(temp)), [RCON[rcon_iter - 1], 0, 0, 0])
            rcon_iter += 1
        expanded_keys.append(xor_words(expanded_keys[i - (KEY_SIZE // 4)], temp))

    return np.array(expanded_keys).reshape((ROUND_COUNT + 1, 4, 4))

def add_round_key(state, round_key):
    return np.bitwise_xor(state, round_key)

def sub_bytes(state):
    return np.vectorize(lambda x: S_BOX[x])(state)

def shift_rows(state):
    state[1] = np.roll(state[1], -1)
    state[2] = np.roll(state[2], -2)
    state[3] = np.roll(state[3], -3)
    return state

def mix_columns(state):
    # Simplified mixcolumns
    for i in range(4):
        col = state[:, i]
        state[:, i] = np.roll(col, 1)
    return state

def aes_round(state, round_key):
    state = sub_bytes(state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, round_key)
    return state

def final_round(state, round_key):
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_key)
    return state

def generate_and_print_keys(password: bytes, num_keys: int = 100):
    for _ in range(num_keys):
        try:
            generated_key, used_salt = generate_aes_key(password)
            round_keys = key_expansion(generated_key)

            # Demo encryption on a random 4x4 state
            state = np.random.randint(0, 256, (4, 4), dtype=np.uint8)
            state = add_round_key(state, round_keys[0])
            for round_num in range(1, ROUND_COUNT):
                state = aes_round(state, round_keys[round_num])
            state = final_round(state, round_keys[ROUND_COUNT])

            hex_key = generated_key.hex().upper()
            print(f"Generated 256-bit AES key:\n{hex_key}")
        except ValueError as ve:
            print(ve)

if __name__ == "__main__":
    print("\033[1;31m   ██████╗    ██╗          █████╗     ████████╗    ███████╗    ███████╗     ██████╗    ██╗   ██╗    ██████╗     ███████╗")
    print("   ██╔════╝    ██║         ██╔══██╗    ╚══██╔══╝    ██╔════╝    ██╔════╝    ██╔════╝    ██║   ██║    ██╔══██╗    ██╔════╝")
    print("   ██║         ██║         ███████║       ██║       ███████╗    █████╗      ██║         ██║   ██║    ██████╔╝    █████╗  ")
    print("   ██║         ██║         ██╔══██║       ██║       ╚════██║    ██╔══╝      ██║         ██║   ██║    ██╔══██╗    ██╔══╝  ")
    print("   ╚██████╗    ███████╗    ██║  ██║       ██║       ███████║    ███████╗    ╚██████╗    ╚██████╔╝    ██║  ██║    ███████╗")
    print("    ╚═════╝    ╚══════╝    ╚═╝  ╚═╝       ╚═╝       ╚══════╝    ╚══════╝     ╚═════╝     ╚═════╝     ╚═╝  ╚═╝    ╚══════╝\033[0m")
    print("\033[1;34mC       L      A       T       S       E       C       U       R       E\033[0m   \033[1;31m(Version 1.03)\033[0m")

    author = "🛡️ By Josh Clatney - Ethical Pentesting Enthusiast 🛡️"
    Write.Print(author + "\n[CES Key Generator (256-bit)]\nWhen Standard Keys Won't Cut It\n", Colors.white, interval=0)

    while True:
        try:
            num_keys = int(input("How many keys do you want to generate? (1-1000): "))
            if 1 <= num_keys <= 1000:
                break
            else:
                print("Please enter a number between 1 and 1000.")
        except ValueError:
            print("Please enter a valid number.")

    user_password = input("Enter seed value for key derivation: ").encode()
    generate_and_print_keys(user_password, num_keys)
    input("Press Enter to exit...")