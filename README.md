<p align="center"><a href="./README-en.md">English</a> | Español</p>

# Ethereum Brainwallet Auditor

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/Security-Audit-red.svg)](https://github.com/features/security)
[![Blockchain](https://img.shields.io/badge/Blockchain-Ethereum-purple.svg)](https://ethereum.org/)
[![Crypto](https://img.shields.io/badge/Crypto-AES--GCM-orange.svg)](https://en.wikipedia.org/wiki/AES-GCM)

## 📋 Descripción

Este proyecto implementa una herramienta para auditar frases débiles estilo *brainwallet* y derivar claves privadas Ethereum a partir de ellas. Consulta la blockchain (vía API de Etherscan) para detectar si alguna de estas claves generadas ha tenido actividad o tiene saldo, y guarda los resultados de forma segura cifrados con AES-GCM.

El objetivo principal es facilitar investigaciones de seguridad sobre patrones débiles de generación de claves, ayudando a identificar vulnerabilidades en frases usadas comúnmente.

---

## 📁 Estructura del Proyecto

```
ethereum-brainwallet-auditor/
├── auditor_brainwallet.py    # Script principal para auditar brainwallets
├── decrypt.py                # Script auxiliar para descifrar archivos de resultados
├── AES_key.txt              # Archivo con la clave AES para cifrado/descifrado
├── rockyou.txt              # Diccionario de contraseñas comunes (133MB)
├── hallazgos.enc            # Resultados cifrados de la auditoría
├── requirements.txt          # Dependencias del proyecto
├── assets/                   # Carpeta de recursos multimedia
│   └── runcode.gif          # GIF mostrando la ejecución del código
├── README.md                # Documentación en español (este archivo)
├── README-en.md             # Documentación en inglés
└── __pycache__/             # Cache de Python (generado automáticamente)

```

---

## 🚀 Instalación

1. Clona este repositorio:
   ```bash
   git clone https://github.com/tu_usuario/ethereum-brainwallet-auditor.git
   cd ethereum-brainwallet-auditor
   ```

2. (Opcional pero recomendado) Crea un entorno virtual con Python 3.8+:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   venv\Scripts\activate     # Windows
   ```

3. Instala las dependencias:
   ```bash
   pip install -r requirements.txt
   ```

4. Crea un archivo `.env` en la raíz con tus variables de entorno:
   ```ini
   AUDITOR_AES_KEY=tu_clave_AES_256_en_hexadecimal_64_caracteres
   ETHERSCAN_API_KEY=tu_api_key_de_etherscan_opcional
   ```

---

## 💻 Uso

1. Descarga un diccionario de frases (por ejemplo `rockyou.txt`) y colócalo en la carpeta del proyecto.

2. Ejecuta el script principal:
   ```bash
   python auditor_brainwallet.py
   ```

El programa procesará el diccionario en bloques de 1000 frases, generará variantes, derivará claves privadas, consultará la blockchain y guardará:

- `hallazgos.enc` → todos los resultados cifrados.
- `hallazgos_con_fondos.enc` → solo los resultados con saldo positivo cifrados.

La ejecución esperará 5 segundos entre bloques para evitar saturar la API.

### 🔄 Marcador de Progreso

El código incluye un sistema de marcador de progreso que permite reanudar la auditoría desde donde se quedó:

**Cómo funciona este cambio:**
- `progress.txt` almacena el número del bloque de 1000 palabras en el que te quedaste.
- Al iniciar, lee ese número y omite todos los bloques anteriores.
- Cada vez que termina un bloque, guarda el índice siguiente en `progress.txt`.
- Si matas el proceso o se apaga el PC, cuando lo reinicies seguirá desde ahí.

---

## 🧠 Fundamentos Teóricos: ¿Es posible encontrar direcciones con fondos?

En teoría, sí es posible, pero en la práctica la probabilidad es extremadamente, casi absurdamente baja si hablamos de direcciones generadas al azar.

Te explico por qué:

### 1️⃣ Espacio de claves privadas de Ethereum
Una clave privada es un número de 256 bits.
Eso significa que hay 2^256 combinaciones posibles, es decir:
≈ 1,1579 × 10^77 posibles claves
(Un número tan grande que es mayor que el número estimado de átomos en el universo observable).

### 2️⃣ Brainwallets y patrones débiles
La única razón por la que scripts como el que usas sí han encontrado direcciones con fondos en el pasado es porque:
- Algunas personas usaban contraseñas simples (ej. "password", "123456", "letmein") como seed phrase para derivar su clave privada.
- Esas claves son predecibles y pueden estar en diccionarios como rockyou.txt.
- Esto reduce drásticamente el espacio a probar (en lugar de 2^256, quizás a unos pocos millones).

**Ejemplo real:**
Una seed phrase "password123" → clave privada determinística → dirección que alguien usó → fondos detectables.

### 3️⃣ Probabilidades reales
- **Claves totalmente aleatorias** → probabilidad de éxito ≈ 0.
- **Claves provenientes de un diccionario de contraseñas débiles** → probabilidad > 0, pero sigue siendo muy baja.

Por eso los scripts suelen enfocarse en brainwallets o weak keys y no en todo el espacio posible.

---

## ⚠️ ¿Qué es un Brainwallet y por qué son vulnerables?

Un *brainwallet* es una técnica para generar una clave privada criptográfica a partir de una frase o contraseña memorizada (una "seed phrase" o frase semilla), generalmente mediante un hash (como SHA-256). La idea es que el usuario no necesite almacenar una clave privada larga y compleja, sino solo recordar una frase simple.

**Sin embargo, esta simplicidad puede ser un riesgo:**

- Muchas personas usan frases comunes, palabras sencillas o patrones predecibles (fechas, nombres, combinaciones comunes).
- Los atacantes pueden usar diccionarios y algoritmos para generar miles o millones de frases probables y calcular sus claves privadas derivadas.
- Luego consultan la blockchain para detectar si alguna de estas claves tiene fondos o ha tenido actividad, y así robarlos.

Por eso, las brainwallets basadas en frases débiles son altamente inseguras y han sido fuente de pérdidas importantes en el pasado.

Este proyecto simula justamente esa auditoría para detectar dichas vulnerabilidades y educar sobre la importancia de usar frases verdaderamente aleatorias y seguras.

![Auditoría en acción](https://media1.giphy.com/media/v1.Y2lkPTc5MGI3NjExbTBuaGh0OWNvaWNjYThqbm01bGU4M3hoNGxsOGo5dW9ibGdkdXgybCZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/llKJGxQ1ESmac/giphy.gif)

*GIF mostrando el proceso de auditoría - una persona tecleando en una computadora mientras realiza análisis de seguridad*

---

## 🎯 Problema que resuelve

Muchas personas usan frases débiles o patrones sencillos para generar sus claves privadas (brainwallets), lo que puede ser explotado por atacantes para robar fondos. Esta herramienta ayuda a:

- Identificar patrones inseguros en claves derivadas de frases débiles.
- Detectar claves activas con saldo en la blockchain.
- Mantener los datos sensibles seguros mediante cifrado.

---

## 🔧 Enfoque y solución

- **Generación de candidatos** basada en listas de palabras comunes y variantes simples (leet speak, sufijos numéricos).
- **Derivación de claves privadas** usando SHA-256 de la frase (brainwallet).
- **Consulta a Etherscan** para obtener balance y fecha de última transacción.
- **Almacenamiento cifrado** de todos los registros y filtrado adicional para claves con saldo.
- **Procesamiento por bloques** para manejo eficiente y control de tasa de consultas.

---

## 🚀 Mejoras futuras / ⚠️ Limitaciones

### 🚀 **Mejoras futuras:**
- 🔗 **Soporte multi-blockchain**: Extender a otros tipos de wallets o blockchains.
- 🗄️ **Base de datos**: Implementar bases de datos para manejo eficiente de grandes volúmenes.
- ⚡ **Consultas paralelas**: Optimización para consultas paralelas sin exceder límites API.
- 🖥️ **Interfaz gráfica**: Desarrollo de interfaz gráfica o web para visualización de resultados.
- 🧠 **Heurísticas avanzadas**: Implementación de algoritmos más sofisticados para generación de frases.

### ⚠️ **Limitaciones actuales:**
- 🌐 **Dependencia API**: Depende de la disponibilidad y límites de la API de Etherscan.
- 📊 **Gestión de recursos**: El diccionario y generación de variantes deben usarse con cuidado para no saturar recursos.
- 🎯 **Cobertura limitada**: No garantiza encontrar todas las frases débiles posibles, solo las basadas en patrones simples.

---

## 🔍 Proceso y resolución de problemas

El desarrollo empezó por comprender la generación y derivación de claves brainwallet (SHA-256 de frase). Luego, se integró la consulta a Etherscan para validar actividad en la blockchain. Para mantener la seguridad y privacidad, se optó por cifrar la salida con AES-GCM usando una clave proporcionada por el usuario.

Se enfrentaron retos como manejo de archivos grandes (`rockyou.txt`), para lo cual se implementó procesamiento por bloques, y la correcta gestión de variables de entorno para claves. También se diseñó un generador de variantes para ampliar la búsqueda sin explosionar el número de consultas.

---

## 📸 Capturas de pantalla

![Ejecución del código](assets/runcode.gif)

*GIF mostrando la ejecución del código del auditor de brainwallets*

---

## 📋 Requisitos

- 🐍 **Python 3.8+**
- 📦 **Dependencias** listadas en `requirements.txt`
- 🔑 **Clave AES** de 256 bits (64 caracteres hexadecimales)
- 🌐 **API Key de Etherscan** (opcional)
- 📚 **Diccionario de contraseñas** (ej: `rockyou.txt` - 133MB)

## 🔒 Seguridad

⚠️ **ADVERTENCIA**: Esta herramienta está diseñada únicamente para fines educativos y de investigación de seguridad. Úsala solo en entornos controlados y con la autorización adecuada.

- Las claves privadas generadas se almacenan cifradas localmente
- No se transmiten datos sensibles a servidores externos
- Se recomienda usar en máquinas aisladas para mayor seguridad
