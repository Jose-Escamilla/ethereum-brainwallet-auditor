"""
auditor_brainwallet.py
Genera frases débiles, deriva claves ETH (brainwallet via SHA256), consulta Etherscan (opcional)
y guarda todo en un archivo cifrado AES-GCM.

USO SEGURO:
- Define AES_KEY como variable de entorno (32 bytes hex) o pásalo al iniciar.
- Si no tienes API_KEY de Etherscan deja ETHERSCAN_API_KEY = None -> el script no consultará la red.
"""

import os
import json
import time
import hashlib
import secrets
from typing import List, Dict, Optional
import requests
from dotenv import load_dotenv


# Crypto: eth key derivation
from eth_account import Account

# AES-GCM
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# -----------------------
# Configuración
# -----------------------
load_dotenv()  # Esto lee el archivo .env y carga las variables al entorno
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")  # opcional
AES_KEY_HEX = os.getenv("AUDITOR_AES_KEY")  # Debe ser 64 hex chars = 32 bytes. ej: export AUDITOR_AES_KEY=0123... (64 hex)
OUT_FILE = "hallazgos.enc"

# -----------------------
# Utilidades
# -----------------------
def derive_eth_private_from_phrase(phrase: str) -> str:
    """
    Deriva una clave privada a partir de una frase mediante SHA-256 (brainwallet estilo).
    Retorna hex sin prefijo '0x'.
    """
    h = hashlib.sha256(phrase.encode("utf-8")).hexdigest()
    return h  # 64 hex chars

def eth_address_from_private_hex(priv_hex: str) -> str:
    acct = Account.from_key(bytes.fromhex(priv_hex))
    return acct.address  # '0x...'

def query_etherscan_balance_and_lasttx(address: str, api_key: Optional[str]):
    """
    Consulta balance y lista de transacciones (para extraer fecha último tx).
    Devuelve (balance_wei:int, last_tx_unix:int_or_None)
    """
    if not api_key:
        return None, None

    base = "https://api.etherscan.io/api"
    # balance
    params_balance = {"module": "account", "action": "balance", "address": address, "tag": "latest", "apikey": api_key}
    rbal = requests.get(base, params=params_balance, timeout=10)
    rbal.raise_for_status()
    data_bal = rbal.json()
    if data_bal.get("status") != "1" and data_bal.get("result") == "0":
        balance = 0
    else:
        balance = int(data_bal.get("result", "0"))

    time.sleep(0.6)  # ← Pausa para no exceder 2 consultas por segundo

    # tx list (normal)
    params_tx = {"module": "account", "action": "txlist", "address": address, "startblock": 0, "endblock": 99999999, "sort": "desc", "apikey": api_key}
    rtx = requests.get(base, params=params_tx, timeout=10)
    rtx.raise_for_status()
    data_tx = rtx.json()
    last_ts = None
    if data_tx.get("status") == "1" and isinstance(data_tx.get("result"), list) and len(data_tx["result"]) > 0:
        # timestamp is in seconds
        last_ts = int(data_tx["result"][0].get("timeStamp"))
    return balance, last_ts

# -----------------------
# Cifrado / almacenamiento
# -----------------------
def get_aes_key() -> bytes:
    if not AES_KEY_HEX:
        raise RuntimeError("No AES key found. Define AUDITOR_AES_KEY env var (64 hex chars => 32 bytes).")
    key = bytes.fromhex(AES_KEY_HEX)
    if len(key) != 32:
        raise RuntimeError("AES key must be 32 bytes (64 hex chars).")
    return key

def encrypt_and_write_records(records: List[Dict], out_file: str, key: bytes):
    """
    Serializa JSON y cifra con AES-GCM. Formato en disco: nonce(12) + ciphertext + tag(16)
    """
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    data = json.dumps(records, ensure_ascii=False, indent=2).encode("utf-8")
    ct = aesgcm.encrypt(nonce, data, associated_data=None)  # ct contains tag appended
    with open(out_file, "wb") as f:
        f.write(nonce + ct)
    print(f"[+] Guardado {len(records)} registros cifrados en {out_file}")

def decrypt_file_to_records(in_file: str, key: bytes) -> List[Dict]:
    with open(in_file, "rb") as f:
        raw = f.read()
    nonce = raw[:12]
    ct = raw[12:]
    aesgcm = AESGCM(key)
    data = aesgcm.decrypt(nonce, ct, associated_data=None)
    return json.loads(data.decode("utf-8"))

# -----------------------
# Generador de candidatos (ejemplo)
# -----------------------
def generate_candidates_from_wordlist(wordlist: List[str]) -> List[str]:
    """
    Genera variantes simples (leet, sufijos numéricos) para simular frases débiles.
    Mantén control sobre el tamaño de la lista para no disparar consultas masivas.
    """
    candidates = []
    for w in wordlist:
        candidates.append(w)
        candidates.append(w + "123")
        candidates.append(w + "123456")
        candidates.append(w + "2020")
        candidates.append(w.capitalize())
        # leet simple
        leet = w.replace("a","4").replace("e","3").replace("o","0").replace("i","1").replace("s","5")
        if leet != w:
            candidates.append(leet)
    # dedupe
    seen = set()
    res = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            res.append(c)
    return res

# -----------------------
# Flujo principal
# -----------------------
def run_audit(wordlist: List[str], etherscan_api_key: Optional[str], out_file: str):
    candidates = generate_candidates_from_wordlist(wordlist)
    print(f"[+] Generados {len(candidates)} candidatos (variantes incluidas).")

    registros = []
    for idx, phrase in enumerate(candidates, start=1):
        priv_hex = derive_eth_private_from_phrase(phrase)
        address = eth_address_from_private_hex(priv_hex)
        balance, last_ts = (None, None)
        try:
            balance, last_ts = query_etherscan_balance_and_lasttx(address, etherscan_api_key)
        except Exception as e:
            # no queremos que el fallo en la API rompa todo; registrar el error y seguir
            print(f"[!] Error querying Etherscan for {address}: {e}")

        registro = {
            "pattern": phrase,
            "private_key_hex": priv_hex,
            "address": address,
            "balance_wei": balance,
            "last_tx_unix": last_ts,
            "checked_at_unix": int(time.time())
        }
        registros.append(registro)

        # impresión mínima para seguimiento
        if idx % 10 == 0 or (balance and balance != 0):
            print(f"[{idx}/{len(candidates)}] {phrase} -> {address}  balance={balance} last_tx={last_ts}")

    # cifrar y guardar
    key = get_aes_key()
    encrypt_and_write_records(registros, out_file, key)
    # print("[+] Auditoría completada.")

    # filtrar registros con balance positivo
    registros_con_fondos = [r for r in registros if r.get("balance_wei") and r["balance_wei"] > 0]
    if registros_con_fondos:
        encrypt_and_write_records(registros_con_fondos, "hallazgos_con_fondos.enc", key)
        print(f"[+] Guardado {len(registros_con_fondos)} registros con fondos en hallazgos_con_fondos.enc")
    else:
        print("[*] No se encontraron registros con fondos.")

    print("[+] Auditoría completada.")


# ----------------------- 
# Generador de chunks
# -----------------------
def chunks(iterable, size=1000):
    """Generador que devuelve listas de tamaño 'size' de un iterable."""
    chunk = []
    for item in iterable:
        chunk.append(item)
        if len(chunk) == size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


# -----------------------
# Ejecución ejemplo
# -----------------------
if __name__ == "__main__":
    progress_file = "progress.txt"

    # Leer progreso previo
    if os.path.exists(progress_file):
        with open(progress_file, "r") as f:
            start_block = int(f.read().strip())
    else:
        start_block = 0
    
    try:
        with open("rockyou.txt", "r", encoding="latin-1") as f:
            for i, batch in enumerate(chunks(f, 1000), start=1):
                sample_wordlist = [line.strip() for line in batch if line.strip()]
                print(f"Procesando bloque {i} de 1000 palabras...")
                run_audit(sample_wordlist, ETHERSCAN_API_KEY, OUT_FILE)
                # Pausa para revisar resultados antes del siguiente bloque
                # input("Presiona Enter para procesar el siguiente bloque...")

                # Guardar progreso
                with open(progress_file, "w") as pf:
                    pf.write(str(i + 1))
                
                print("Esperando 5 segundos antes del siguiente bloque...")
                time.sleep(5)
                
    except FileNotFoundError:
        print("No se encontró rockyou.txt, usando lista pequeña por defecto.")
        sample_wordlist = ["password", "123456", "admin", "qwerty", "letmein"]
        # ADVERTENCIA: no ejecutar sobre listas enormes sin control
        run_audit(sample_wordlist, ETHERSCAN_API_KEY, OUT_FILE)
