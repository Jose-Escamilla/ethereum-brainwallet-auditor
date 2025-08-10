from auditor_brainwallet import decrypt_file_to_records, get_aes_key

def mostrar_registros_cifrados(nombre_archivo):
    try:
        key = get_aes_key()  # obtiene la clave AES de la variable de entorno o .env
        registros = decrypt_file_to_records(nombre_archivo, key)
        for i, reg in enumerate(registros, start=1):
            print(f"Registro {i}:")
            print(f"  Patrón: {reg['pattern']}")
            print(f"  Dirección: {reg['address']}")
            print(f"  Balance (wei): {reg['balance_wei']}")
            print(f"  Última transacción (unix): {reg['last_tx_unix']}")
            print("-" * 30)
    except Exception as e:
        print(f"Error al descifrar o leer el archivo: {e}")

if __name__ == "__main__":
    mostrar_registros_cifrados("hallazgos.enc")
