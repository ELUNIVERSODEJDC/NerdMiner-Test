import socket
import json
import hashlib

# Configuración del servidor
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 4028
BUFFER_SIZE = 4096


def load_block_header(filename="encabezadobloque.txt"):
    """Carga los datos del encabezado del bloque desde un archivo JSON."""
    try:
        with open(filename, "r") as file:
            block_data = json.load(file)
            required_fields = [
                "prev_block_hash", "coinb1", "coinb2", "merkle_root",
                "version", "nbits", "ntime"
            ]
            for field in required_fields:
                if field not in block_data:
                    raise ValueError(f"El campo '{field}' está ausente en el archivo.")
            return block_data
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
        print(f"Error al cargar el encabezado del bloque: {e}")
        return None


def determine_zeros_from_difficulty(nbits):
    """Determina la cantidad de ceros iniciales basándose en nbits directamente."""
    nbits_hex = f"{nbits:08x}"
    exponent = int(nbits_hex[:2], 16)
    mantissa = int(nbits_hex[2:], 16)
    target = mantissa * (2 ** (8 * (exponent - 3)))
    target_hex = f"{target:064x}"
    zeros_required = len(target_hex) - len(target_hex.lstrip('0'))
    return zeros_required, target_hex


def calculate_hash(header, nonce):
    """Calcula el hash doble SHA256 para un bloque con un nonce dado."""
    header_bin = bytes.fromhex(header) + nonce.to_bytes(4, byteorder='big')
    return hashlib.sha256(hashlib.sha256(header_bin).digest()).digest()


def notify_work(client_socket, block_data):
    """Envía trabajo al ASIC."""
    try:
        nbits = block_data["nbits"]
        if isinstance(nbits, str):
            nbits = int(nbits, 16)

        zeros_required, target_hex = determine_zeros_from_difficulty(nbits)

        job_message = {
            "id": None,
            "method": "mining.notify",
            "params": [
                "1",
                block_data["prev_block_hash"],
                block_data["coinb1"],
                block_data["coinb2"],
                [block_data["merkle_root"]],
                f"{block_data['version']:08x}",
                f"{nbits:08x}",
                f"{block_data['ntime']:08x}",
                True
            ]
        }
        client_socket.sendall((json.dumps(job_message) + '\n').encode('utf-8'))
        print(f"Trabajo enviado al ASIC: {job_message}")
        print(f"Target calculado (hex): {target_hex} | Mínimo de ceros requeridos: {zeros_required}")
    except Exception as e:
        print(f"Error al notificar trabajo al ASIC: {e}")


def handle_connection(client_socket, block_data):
    """Maneja la conexión con el ASIC."""
    try:
        nbits = block_data["nbits"]
        if isinstance(nbits, str):
            nbits = int(nbits, 16)

        zeros_required, target_hex = determine_zeros_from_difficulty(nbits)

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
                    suggested_difficulty = request["params"][0]
                    print(f"Dificultad sugerida recibida: {suggested_difficulty}")
                    if suggested_difficulty < 1.0:
                        nbits = 0x207fffff  # Dificultad baja
                    else:
                        nbits = 0x1d00ffff  # Dificultad estándar
                    block_data["nbits"] = nbits
                    response = {"id": request["id"], "result": True, "error": None}
                    client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))
                    print(f"Dificultad ajustada. Nuevo nbits: {nbits:08x}")

                elif request.get("method") == "mining.submit":
                    params = request.get("params", [])
                    if len(params) != 5:
                        print(f"Formato incorrecto en mining.submit: {params}")
                        continue

                    username, job_id, extranonce2, ntime, nonce = params

                    try:
                        nonce_int = int(nonce, 16)
                        header = (
                            f"{block_data['prev_block_hash']}{block_data['coinb1']}"
                            f"{block_data['coinb2']}{block_data['merkle_root']}"
                        )
                        hash_result = calculate_hash(header, nonce_int)
                        hash_hex = hash_result.hex()
                        leading_zeros = len(hash_hex) - len(hash_hex.lstrip('0'))

                        state = "VÁLIDO" if leading_zeros >= zeros_required else "INVÁLIDO"
                        print(f"Nonce recibido: {nonce} | Hash: {hash_hex} | "
                              f"Ceros iniciales: {leading_zeros} | Estado: {state}")

                        if state == "VÁLIDO":
                            response = {
                                "id": request["id"],
                                "result": True,
                                "error": None
                            }
                            client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))
                            print(f"Bloque resuelto correctamente por el ASIC. Nonce: {nonce}, Hash: {hash_hex}")
                            with open("bloques_resueltos.log", "a") as log_file:
                                log_file.write(f"Bloque resuelto: Nonce: {nonce}, Hash: {hash_hex}\n")
                        else:
                            response = {
                                "id": request["id"],
                                "result": False,
                                "error": None
                            }
                            client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))

                    except ValueError as e:
                        print(f"Error al procesar el nonce: {nonce} | Error: {e}")

                else:
                    print(f"Método desconocido recibido: {request.get('method')}")
            except json.JSONDecodeError:
                print("Error al interpretar el mensaje recibido.")
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


if __name__ == "__main__":
    block_data = load_block_header()
    if not block_data:
        print("No se pudo cargar el encabezado del bloque. Cerrando el servidor.")
    else:
        start_server(SERVER_HOST, SERVER_PORT, block_data)

