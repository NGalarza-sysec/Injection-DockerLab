Injection

# Reporte de Explotación | Writeup: Inyección SQL a Escalada de Privilegios SUID.

El presente documento detalla el proceso de análisis de vulnerabilidades y pruebas de penetración (*Pentesting*) realizado sobre la máquina **Injection**, un entorno controlado desplegado localmente mediante la plataforma **DockerLabs**. 

El objetivo es identificar servicios expuestos, explotar fallos de configuración o vulnerabilidades de software, y escalar privilegios hasta obtener acceso total como el usuario administrador (`root`).

- **Atacante (Host):** `kali` (`172.17.0.1` / Red Local Docker)
- **Víctima (Target):** `172.17.0.2` (Contenedor Ubuntu 22.04 LTS)
- **Servicios Expuestos:** SSH (`22/tcp`), Web HTTP (`80/tcp`)
- **Vulnerabilidades Explotadas:** 

  **1.** Inyección SQL (Authentication Bypass en formulario Web).
  
  **2.** Escalada de Privilegios mediante Binario SUID Inseguro (`/usr/bin/env`).


## 1. Escaneo con Nmap
>[!NOTE]
>Se realizó un escaneo inicial de puertos en la dirección IP objetivo `172.17.0.2` para identificar los servicios activos:
>
>```bash
>nmap 172.17.0.2
>```
>
>![](Injection/Imagenes/IMG-1.png)
>
>### Resultado
>Puerto Abiertos:
>
>`22/tcp open  ssh`
>
>`80/tcp open  http`

## 2. Exploracion o Reconocimiento de Sitio Web
>[!NOTE]
>Accediendo vía navegador web a http://172.17.0.2, se encontró un formulario de inicio de sesión (Login).
>
>Inspección del Código Fuente (Ctrl + U)
>Analizando el código HTML mediante la búsqueda de etiquetas del formulario, se identificó el parámetro exacto esperado por el backend PHP:
>
>![](Injection/Imagenes/IMG-2.png)
>
>(Usamos el comando Ctrl+U para ver el Codigo. Iniciamos una busqueda con Ctrl+F con las palabras claves admin, user, users, script y obtuvimos el siguiente detalle en el codigo)
>
>![](Injection/Imagenes/IMG-3.png)
>
>### Por qué es importante este hallazgo
>Conocer el nombre exacto de la variable (name, en lugar de username o user) permite construir peticiones HTTP POST precisas y evaluar de manera efectiva la lógica del formulario.
> 
>**El parametro del usuario se llama `name` (no `username` ni `user`)**
> * `<input type="text" id="name" name="name">` 

## 3. Pruebas de Credenciales por Defecto (Default Credentials)
>[!NOTE]
>Antes de realizar pruebas de inyección, se evaluó la presencia de credenciales genéricas o por defecto en el formulario de inicio de sesión:
>
>| Usuario | Contraseña | Resultado |
>| :--- | :--- | :--- |
>| `admin` | `admin` | Rechazado |
>| `admin` | `admin123` | Rechazado |
>| `admin` | `password` | Rechazado |
>| `admin` | *(vacío)* | Rechazado |
>| `user` | `user` | Rechazado |
>| `user` | `user123` | Rechazado |
>| `test` | `test` | Rechazado |
>| `root` | `root` | Rechazado |
>
>**En cada intento de sesion nos devolvio `Wrong Credentials`.**
>
>![](Injection/Imagenes/IMG-4.png)

## 4. Explotación de Inyección SQL (Authentication Bypass)
>[!NOTE]
>Al verificar que las credenciales por defecto no funcionaban, se evaluó la vulnerabilidad a **SQL Injection (SQLi)** en el parámetro de inicio de sesión `name`.
>### Construcción del Payload
>Se ingresó el siguiente payload en el campo **User**:
>```SQL
>' OR 1=1 -- -
>```
>
>**Explicación técnica:**
>
>1. `'` — Cierra la comilla de la cadena SQL original en el parámetro `name`.
>
>2. `OR 1=1` — Inyecta una condición booleana que siempre se evalúa como **verdadera** ($1=1$).
>
>3. `-- -` — Comenta y anula el resto de la consulta SQL original (desactivando la verificación del parámetro `password`).
>
>### Resultado
>La inyección alteró la lógica de la consulta en la base de datos, logrando evadir la autenticación con éxito. El sistema redirigió a la vista `/acceso_valido_dylan.php`, exponiendo las credenciales de un >usuario válido:
>
>* **Usuario obtenido:** `Dylan`
>
>* **Contraseña / Clave expuesta:** `KJSDFG789FGSDF78`
>
>![](Injection/Imagenes/IMG-5.png)

## 5. Acceso Inicial al Sistema mediante SSH
>[!NOTE]
>Con las credenciales obtenidas en la fase web (`dylan` : `KJSDFG789FGSDF78`), se procedió a la conexión remota por el puerto 22.
>
>**Nota / Tip de Resolución de Problemas (Troubleshooting):**
>Al intentar conectar por primera vez, el servicio SSH rechazó la conexión mostrando el error `WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!` debido a una clave de host previa (de un contenedor anterior) >guardada en `/home/kali/.ssh/known_hosts`.
>
>**Para solucionar esto y limpiar el registro conflictivo, se ejecutó el siguiente comando:**
>
>```bash
>ssh-keygen -f '/home/kali/.ssh/known_hosts' -R '172.17.0.2'
>```
>
>![](Injection/Imagenes/IMG-7.png)
>
>**Posteriormente, se volvió a iniciar la sesión y se aceptó la nueva huella digital (fingerprint) confirmando con `yes`:**
>
>* **Comando:** `ssh dylan@172.17.0.2`
>
>* **Resultado:** Acceso exitoso como usuario `dylan` en el sistema (Ubuntu 22.04 LTS).
>
>![](Injection/Imagenes/IMG-6.png)

## 6. Reconocimiento y Escalada de Privilegios
>[!NOTE]
>Una vez obtenida la sesión remota como usuario `dylan`, se procedió a auditar los posibles vectores de elevación de privilegios en el sistema.
>
>### Identificación de Permisos Inseguros
>Se intentó listar las reglas de `sudo` del usuario con `sudo -l`, pero el binario no se encontraba instalado en el sistema.
>
>![](Injection/Imagenes/IMG-8.png)
>
>Posteriormente, se realizó una búsqueda de archivos ejecutable con el bit **SUID** (`Set User ID`) activado mediante el siguiente comando:
>
>```bash
>find / -perm -4000 -ls 2>/dev/null
>```
>
>![](Injection/Imagenes/IMG-9.png)
>
>### Análisis de Permisos SUID
>
>Durante la revisión de archivos con el bit SUID activado, se identificaron binarios que requieren evaluación de seguridad para garantizar que no infrinjan el principio de mínimo privilegio.
>
>* **Concepto:**
>	El permiso SUID (Set Owner User ID up on execution) permite que un archivo ejecutable se ejecute con los privilegios del propietario del archivo en lugar del usuario que lo ejecuta.
>	
>* **¿Por qué es un vector de escalada?**
>	**`env`** se utiliza para ejecutar un programa en un entorno modificado. Al tener el bit SUID activado y ser de **`root`**, si le pedimos a **`env`** que ejecute una shell (como **`/bin/sh`** o
> **`bash`**), esta se ejecutará con los privilegios del propietario del archivo (es decir, **`root`**).

## 7. Escalada de Privilegios (Explotación SUID)
>[!NOTE]
>Aprovechando la mala configuración SUID en el binario /usr/bin/env, se ejecutó la siguiente instrucción para obtener acceso como root:
>
>```bash
>/usr/bin/env /bin/sh -p
>```
>
>**¿Por qué funciona esto?**
>
>* **`/usr/bin/env:`** Al contar con el bit SUID activo y ser propiedad de **`root`**, ejecuta cualquier instrucción posterior bajo la identidad efectiva de **`root`**.
>
>* **`/bin/sh:`** Comando para solicitar la creación de una shell.
>
>* **`-p`** (preserve privileges): Parámetro crítico. Evita que la shell reduzca (drop) automáticamente los privilegios efectivos al detectar que el usuario real (**`dylan`**) difiere del usuario efectivo >(**`root`**).
>
>```bash
># whoami
>root
>```
> 
>![](Injection/Imagenes/IMG-10.png)

## 8. Recomendaciones de Mitigación
>[!WARNING]
>* **Sanitización de Entradas (SQLi):** Implementar Sentencias Preparadas (Prepared Statements) y Consultas Parametrizadas en el backend PHP para evitar la inyección de código SQL.
>
>* **Principio de Mínimo Privilegio (SUID):** Revisar y auditar periódicamente los binarios del sistema. Quitar el bit SUID a utilidades administrativas innecesarias mediante el comando **`chmod u-s /usr/bin/env`**.
