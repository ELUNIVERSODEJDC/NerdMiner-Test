import socket
import json
import hashlib
import time

# Configuración del servidor
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 4028
BUFFER_SIZE = 4096

# Variables globales para el monitoreo
nonce_count = 0  # Contador de nonces recibidos
start_time = time.time()  # Marca de tiempo al iniciar el servidor

def load_block_header(filename="encabezadobloque.txt"):
    """Carga los datos del encabezado del bloque desde un archivo JSON."""
    try:
        with open(filename, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Error: No se encontró el archivo {filename}.")
        return None
    except json.JSONDecodeError as e:
        print(f"Error al leer el archivo JSON: {e}")
        return None

def nbits_to_target(nbits):
    """Convierte nbits (dificultad compacta) a un objetivo (target) completo."""
    exponent = (nbits >> 24) & 0xFF
    mantissa = nbits & 0xFFFFFF
    target = mantissa * (2 ** (8 * (exponent - 3)))
    return target

def validate_work(prev_hash, extranonce2, coinb1, coinb2, ntime, nonce, target):
    """Valida el trabajo enviado por el ASIC."""
    try:
        extranonce2 = extranonce2 if extranonce2 else "00000000"
        ntime = ntime if ntime else "00000000"
        nonce = nonce if nonce else "00000000"

        header = f"{prev_hash}{extranonce2}{coinb1}{coinb2}{ntime}{nonce}"
        header_bin = bytes.fromhex(header)
        hash_result = hashlib.sha256(hashlib.sha256(header_bin).digest()).digest()
        hash_hex = hash_result.hex()
        print(f"Hash calculado: {hash_hex}")

        return int(hash_hex, 16) < target
    except ValueError as e:
        print(f"Error al procesar el encabezado: {e}")
        return False

def notify_work(client_socket, block_data):
    """Envía un trabajo al ASIC, garantizando que los datos sean los originales."""
    # Verificar los datos del bloque antes de enviarlos
    print("Datos originales del bloque:")
    print(f"prev_block_hash: {block_data['prev_block_hash']}")
    print(f"coinb1: {block_data['coinb1']}")
    print(f"coinb2: {block_data['coinb2']}")
    print(f"merkle_root: {block_data['merkle_root']}")
    print(f"version: {block_data['version']}")
    print(f"nbits: {block_data['nbits']}")
    print(f"ntime: {block_data['ntime']}")

    # Construir el mensaje para el ASIC
    job_message = {
        "id": None,
        "method": "mining.notify",
        "params": [
            "1",  # job_id
            block_data["prev_block_hash"],
            block_data["coinb1"],
            block_data["coinb2"],
            [block_data["merkle_root"]],  # Rama de Merkle calculada
            f"{block_data['version']:08x}",
            f"{block_data['nbits']:08x}",
            f"{block_data['ntime']:08x}",
            True  # clean_jobs
        ]
    }
    client_socket.sendall((json.dumps(job_message) + '\n').encode('utf-8'))
    print(f"Trabajo enviado al ASIC: {job_message}")

def handle_connection(client_socket, block_data):
    """Maneja la conexión con el ASIC."""
    global nonce_count
    try:
        target = nbits_to_target(int(block_data["nbits"]))
        print(f"Target calculado: {target}")

        while True:
            data = client_socket.recv(BUFFER_SIZE).decode('utf-8').strip()
            if not data:
                print("El ASIC cerró la conexión.")
                break

            print(f"Datos recibidos del ASIC: {data}")
            try:
                request = json.loads(data)
                if request.get("method") == "mining.subscribe":
                    response = {
                        "id": request["id"],
                        "result": [[["mining.notify", "abc123", 4]], "session_id"],
                        "error": None
                    }
                    client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))

                elif request.get("method") == "mining.authorize":
                    response = {
                        "id": request["id"],
                        "result": True,
                        "error": None
                    }
                    client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))
                    notify_work(client_socket, block_data)

                elif request.get("method") == "mining.suggest_difficulty":
                    response = {
                        "id": request["id"],
                        "result": True,
                        "error": None
                    }
                    client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))

                elif request.get("method") == "mining.submit":
                    params = request.get("params", [])
                    username, job_id, extranonce2, ntime, nonce = params

                    # Validar el trabajo enviado
                    valid = validate_work(
                        block_data["prev_block_hash"],
                        extranonce2,
                        block_data["coinb1"],
                        block_data["coinb2"],
                        ntime,
                        nonce,
                        target
                    )
                    response = {
                        "id": request["id"],
                        "result": valid,
                        "error": None if valid else "Invalid work"
                    }
                    client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))

                    # Registro del nonce enviado
                    nonce_count += 1
                    elapsed_time = time.time() - start_time
                    print(f"Nonce recibido: {nonce} (Decimal: {int(nonce, 16)}) | Total: {nonce_count} | Tiempo: {elapsed_time:.2f}s")

                    # Guardar en un archivo de log
                    with open("nonce_log.txt", "a") as log_file:
                        log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Nonce: {nonce}, "
                                       f"Decimal: {int(nonce, 16)}, Válido: {valid}, Total: {nonce_count}\n")

                else:
                    print(f"Método desconocido recibido: {request.get('method')}")
            except json.JSONDecodeError:
                print("Error al interpretar el mensaje recibido: No es un JSON válido.")
    except Exception as e:
        print(f"Error durante la conexión: {e}")
    finally:
        client_socket.close()

def start_server(host, port, block_data):
    """Inicia el servidor para escuchar conexiones del ASIC."""
    print(f"Iniciando servidor en {host}:{port}...")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print("Esperando conexión del ASIC...")
    try:
        while True:
            client_socket, client_address = server_socket.accept()
            handle_connection(client_socket, block_data)
    except KeyboardInterrupt:
        print("Servidor detenido manualmente.")
    finally:
        server_socket.close()

def simulate_hashing(header, target, start_nonce=0, max_nonce=100000):
    """Simula el cálculo de hashes en el servidor."""
    print(f"Iniciando simulación con target: {target}")
    for nonce in range(start_nonce, max_nonce):
        combined = f"{header}{nonce:08x}"
        hash_result = hashlib.sha256(hashlib.sha256(bytes.fromhex(combined)).digest()).digest()
        hash_hex = hash_result.hex()
        if int(hash_hex, 16) < target:
            print(f"Nonce encontrado: {nonce} -> Hash: {hash_hex}")
            return nonce, hash_hex
    print("No se encontró nonce válido en el rango.")
    return None, None

if __name__ == "__main__":
    block_data = load_block_header()
    if not block_data:
        print("No se pudo cargar el encabezado del bloque. Cerrando el servidor.")
    else:
        start_server(SERVER_HOST, SERVER_PORT, block_data)

        # Simulación de prueba (puedes ajustar el rango de nonces)
        simulate_hashing(
            block_data["prev_block_hash"],
            nbits_to_target(block_data["nbits"]),
            start_nonce=0,
            max_nonce=1000
        )
