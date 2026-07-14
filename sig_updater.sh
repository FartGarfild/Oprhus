!/bin/bash
echo "[*] Updating signatures..."

# Maldet
if [ -d "/usr/local/maldetect/sigs" ]; then
    cp -r /usr/local/maldetect/sigs/* signatures/
fi

# MalwareBazaar (після отримання Auth-Key)
curl -s -H "Auth-Key: ТВІЙ_КЛЮЧ" ... > signatures/malwarebazaar.sha256

# YARA
git -C signatures/yara pull || git clone https://github.com/Neo23x0/signature-base signatures/yara

echo "[OK] Signatures updated"
