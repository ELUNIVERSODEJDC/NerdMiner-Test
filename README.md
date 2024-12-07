# Código de Prueba para NerdMiner

Este proyecto contiene un código diseñado para probar el rendimiento de **NerdMiner** utilizando un bloque con un `nonce` extremadamente fácil de resolver. El objetivo es demostrar que, incluso con una dificultad baja, el NerdMiner es incapaz de encontrar un nonce válido en un tiempo razonable.

## Archivos incluidos
- **`Mining.py`**: El servidor principal que emula el protocolo Stratum y envía trabajos al NerdMiner.
- **`Setup.py`**: Configuración inicial que prepara el entorno para el servidor.
- **`encabezadobloque.txt`**: Archivo JSON que contiene los datos del bloque a resolver, con un `nonce` de baja dificultad.

## Instrucciones de uso

### 1. Preparar el entorno
1. Asegúrate de que todos los archivos del proyecto (**`Mining.py`**, **`Setup.py`** y **`encabezadobloque.txt`**) estén en la **misma carpeta**.
2. Instala Python 3.11 o superior y asegúrate de que el comando `python` esté disponible en tu terminal.

### 2. Configurar la dirección IP y el puerto
El NerdMiner debe conectarse al ordenador donde se ejecuta el servidor. Sigue estos pasos para configurar correctamente la IP:

1. Abre el archivo **`Mining.py`** y asegúrate de que el puerto configurado es `4028` (o el puerto deseado).
2. Encuentra la dirección IP de tu ordenador:
   - Abre **CMD** (símbolo del sistema).
   - Escribe el comando: `ipconfig`.
   - Busca la línea que dice `Dirección IPv4` en tu adaptador de red.
3. En el NerdMiner, configura la **IP del ordenador** como la dirección encontrada en el paso anterior. **NO uses la IP del archivo de configuración, ya que es un valor genérico.**
4. Configura también el puerto que aparece en el archivo **`Mining.py`** (por defecto: `4028`).

### 3. Ejecutar el servidor
Ejecuta el servidor en tu ordenador desde visualstudio abriendo mining.py para que esté listo para recibir conexiones del NerdMiner:
recuerda que todo este en una misma carpeta. 

El servidor enviará un bloque con un nonce extremadamente fácil de resolver. Sin embargo, el NerdMiner mostrará que es incapaz de encontrar un hash válido en un tiempo razonable. 
