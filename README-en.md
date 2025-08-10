<p align="center"><a href="./README.md">Español</a> | English</p>

# Ethereum Brainwallet Auditor

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/Security-Audit-red.svg)](https://github.com/features/security)
[![Blockchain](https://img.shields.io/badge/Blockchain-Ethereum-purple.svg)](https://ethereum.org/)
[![Crypto](https://img.shields.io/badge/Crypto-AES--GCM-orange.svg)](https://en.wikipedia.org/wiki/AES-GCM)

## 📋 Description

This project implements a tool to audit weak *brainwallet*-style phrases and derive Ethereum private keys from them. It queries the blockchain (via Etherscan API) to detect if any of these generated keys have had activity or have a balance, and securely stores the results encrypted with AES-GCM.

The main objective is to facilitate security research on weak key generation patterns, helping to identify vulnerabilities in commonly used phrases.

---

## 📁 Project Structure

```
ethereum-brainwallet-auditor/
├── auditor_brainwallet.py    # Main script to audit brainwallets
├── decrypt.py                # Auxiliary script to decrypt result files
├── AES_key.txt              # File with AES key for encryption/decryption
├── rockyou.txt              # Common passwords dictionary (133MB)
├── hallazgos.enc            # Encrypted audit results
├── requirements.txt          # Project dependencies
├── assets/                   # Multimedia resources folder
│   └── runcode.gif          # GIF showing code execution
├── README.md                # Spanish documentation (this file)
├── README-en.md             # English documentation
└── __pycache__/             # Python cache (auto-generated)
```

---

## 🚀 Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/tu_usuario/ethereum-brainwallet-auditor.git
   cd ethereum-brainwallet-auditor
   ```

2. (Optional but recommended) Create a virtual environment with Python 3.8+:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   venv\Scripts\activate     # Windows
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Create a `.env` file in the root with your environment variables:
   ```ini
   AUDITOR_AES_KEY=your_256_bit_AES_key_in_64_hexadecimal_characters
   ETHERSCAN_API_KEY=your_etherscan_api_key_optional
   ```

---

## 💻 Usage

1. Download a phrase dictionary (for example `rockyou.txt`) and place it in the project folder.

2. Run the main script:
   ```bash
   python auditor_brainwallet.py
   ```

The program will process the dictionary in blocks of 1000 phrases, generate variants, derive private keys, query the blockchain, and save:

- `hallazgos.enc` → all encrypted results.
- `hallazgos_con_fondos.enc` → only results with positive balance encrypted.

Execution will wait 5 seconds between blocks to avoid saturating the API.

---

## ⚠️ What is a Brainwallet and why are they vulnerable?

A *brainwallet* is a technique to generate a cryptographic private key from a memorized phrase or password (a "seed phrase"), generally using a hash (like SHA-256). The idea is that the user doesn't need to store a long and complex private key, but only remember a simple phrase.

**However, this simplicity can be a risk:**

- Many people use common phrases, simple words, or predictable patterns (dates, names, common combinations).
- Attackers can use dictionaries and algorithms to generate thousands or millions of probable phrases and calculate their derived private keys.
- Then they query the blockchain to detect if any of these keys have funds or have had activity, and thus steal them.

That's why brainwallets based on weak phrases are highly insecure and have been the source of significant losses in the past.

This project simulates exactly that audit to detect such vulnerabilities and educate about the importance of using truly random and secure phrases.

![Audit in action](https://media1.giphy.com/media/v1.Y2lkPTc5MGI3NjExbTBuaGh0OWNvaWNjYThqbm01bGU4M3hoNGxsOGo5dW9ibGdkdXgybCZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/llKJGxQ1ESmac/giphy.gif)

*GIF showing the audit process - a person typing on a computer while performing security analysis*

---

## 🎯 Problem it solves

Many people use weak phrases or simple patterns to generate their private keys (brainwallets), which can be exploited by attackers to steal funds. This tool helps to:

- Identify insecure patterns in keys derived from weak phrases.
- Detect active keys with balance on the blockchain.
- Keep sensitive data secure through encryption.

---

## 🔧 Approach and solution

- **Candidate generation** based on common word lists and simple variants (leet speak, numeric suffixes).
- **Private key derivation** using SHA-256 of the phrase (brainwallet).
- **Etherscan query** to obtain balance and last transaction date.
- **Encrypted storage** of all records and additional filtering for keys with balance.
- **Block processing** for efficient handling and query rate control.

---

## 🚀 Future improvements / ⚠️ Limitations

### 🚀 **Future improvements:**
- 🔗 **Multi-blockchain support**: Extend to other types of wallets or blockchains.
- 🗄️ **Database**: Implement databases for efficient handling of large volumes.
- ⚡ **Parallel queries**: Optimization for parallel queries without exceeding API limits.
- 🖥️ **Graphical interface**: Development of graphical or web interface for result visualization.
- 🧠 **Advanced heuristics**: Implementation of more sophisticated algorithms for phrase generation.

### ⚠️ **Current limitations:**
- 🌐 **API dependency**: Depends on the availability and limits of the Etherscan API.
- 📊 **Resource management**: The dictionary and variant generation must be used carefully to avoid saturating resources.
- 🎯 **Limited coverage**: Does not guarantee finding all possible weak phrases, only those based on simple patterns.

---

## 🔍 Process and problem resolution

Development started by understanding brainwallet key generation and derivation (SHA-256 of phrase). Then, Etherscan querying was integrated to validate blockchain activity. To maintain security and privacy, output encryption with AES-GCM using a user-provided key was chosen.

Challenges were faced such as handling large files (`rockyou.txt`), for which block processing was implemented, and proper environment variable management for keys. A variant generator was also designed to expand the search without exploding the number of queries.

---

## 📸 Screenshots

![Code execution](assets/runcode.gif)

*GIF showing the execution of the brainwallet auditor code*

---

## 📋 Requirements

- 🐍 **Python 3.8+**
- 📦 **Dependencies** listed in `requirements.txt`
- 🔑 **AES Key** of 256 bits (64 hexadecimal characters)
- 🌐 **Etherscan API Key** (optional)
- 📚 **Password dictionary** (e.g., `rockyou.txt` - 133MB)

## 🔒 Security

⚠️ **WARNING**: This tool is designed solely for educational and security research purposes. Use it only in controlled environments and with appropriate authorization.

- Generated private keys are stored encrypted locally
- No sensitive data is transmitted to external servers
- It is recommended to use on isolated machines for greater security
