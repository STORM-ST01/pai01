
# PAI-01

Implementación de un sistema cliente servidor para transacciones bancarias simples, garantizando la integridad en el almacenamiento y transmisión de la información.

## Requisitos

* Python 3.x
* pip (gestor de paquetes de Python)

## Configuración

1.  **Clonar el repositorio:**

    ```bash
    git clone https://github.com/STORM-ST01/pai01.git
    cd [nombre del repositorio]
    ```

2.  **Crear un entorno virtual (recomendado):**

    ```bash
    python3 -m venv venv
    ```

3.  **Activar el entorno virtual:**

    * **En Windows:**

        ```bash
        venv\Scripts\activate
        ```

    * **En macOS y Linux:**

        ```bash
        source venv/bin/activate
        ```

4.  **Instalar las dependencias:**

    ```bash
    pip install -r requirements.txt
    ```

## Ejecución

1.  **Iniciar el servidor:**

    ```bash
    python servidor.py
    ```

2.  **Iniciar el cliente (en otra terminal):**

    ```bash
    python cliente.py
    ```

3.  **Se desplegará la aplicación y podrá probar las funcionalidades:**

Listado de usuarios de prueba:
  <user1,Usuar1o_1>
  <user2,Usuar1o_2>


## Pruebas

Se incluyen pruebas unitarias en la carpeta `tests` para verificar el correcto funcionamiento de la aplicación. Para ejecutar las pruebas:

1.  Asegúrate de tener el entorno virtual activado.
2.  Ejecute los Script de test de peticiones para probar las medidas de seguridad.
