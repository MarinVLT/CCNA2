# ============================================================
# DECIFRADOR DE SENHA CISCO TYPE 7
# ============================================================
# Objetivo: reverter a "ofuscação" (não é criptografia de verdade)
# usada pelo comando "service password-encryption" do Cisco IOS.
# ============================================================

def cisco_type7_decrypt(encrypted):

    # ------------------------------------------------------------
    # A TABELA XLAT (a "chave")
    # ------------------------------------------------------------
    # Isso é uma lista de 53 bytes FIXOS, sempre iguais em
    # QUALQUER dispositivo Cisco do mundo. Não vem da senha,
    # não muda, é gravada no próprio IOS.
    #
    # Cada 0xNN é um byte escrito em hexadecimal (0x00 a 0xFF,
    # ou seja, 0 a 255 em decimal).
    #
    # Essa tabela funciona como um "molho de chaves" fixo que
    # vamos usar pra desfazer o XOR aplicado na senha.
    # ------------------------------------------------------------
    xlat = [
        0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c, 0x2e,
        0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44,
        0x48, 0x53, 0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36, 0x39,
        0x38, 0x33, 0x34, 0x6e, 0x63, 0x78, 0x76, 0x39, 0x38, 0x37, 0x33,
        0x32, 0x35, 0x34, 0x6b, 0x3b, 0x66, 0x67, 0x38, 0x37
    ]

    # ------------------------------------------------------------
    # PASSO 1 — Extrair o "seed" (ponto de partida na tabela)
    # ------------------------------------------------------------
    # Uma senha Type 7 do Cisco tem esse formato:
    #
    #     0802455D0A16091E1C0E1C057F7E
    #     └┬┘└──────────┬─────────────┘
    #    seed      bytes cifrados
    #
    # Os 2 primeiros caracteres NÃO fazem parte da senha cifrada
    # em si — são um número de 00 a 15 que diz "por qual posição
    # da tabela xlat começar". Esse número foi sorteado UMA ÚNICA
    # VEZ pelo Cisco na hora de criar a senha (é por isso que a
    # mesma senha "cisco" gera strings diferentes cada vez que
    # você reconfigura — só o seed muda, a tabela não).
    # ------------------------------------------------------------
    seed = int(encrypted[0:2])

    # O restante da string (a partir do 3º caractere) são os
    # bytes cifrados de verdade, ainda em formato hexadecimal
    # (texto), ex: "02455D0A16..."
    resto_hex = encrypted[2:]

    # ------------------------------------------------------------
    # PASSO 2 — Converter o texto hexadecimal em bytes reais
    # ------------------------------------------------------------
    # bytes.fromhex() pega a string e agrupa de 2 em 2 caracteres,
    # transformando cada par (ex: "02", "45", "5D"...) em um
    # número de 0 a 255 (1 byte).
    #
    # "02455D..." vira [2, 69, 93, ...]
    # ------------------------------------------------------------
    cipher_bytes = bytes.fromhex(resto_hex)

    # String vazia onde vamos ir "empilhando" cada caractere
    # decifrado, um por um, até formar a senha completa.
    result = ""

    # ------------------------------------------------------------
    # PASSO 3 — Percorrer cada byte cifrado e desfazer o XOR
    # ------------------------------------------------------------
    # enumerate() nos dá dois valores a cada volta do loop:
    #   i     = contador simples (0, 1, 2, 3...) -> NÃO é sorteado,
    #           é só a posição do byte na sequência
    #   byte  = o valor cifrado daquela posição (ex: 2, 69, 93...)
    # ------------------------------------------------------------
    for i, byte in enumerate(cipher_bytes):

        # Aqui é onde "andamos" pela tabela xlat a partir do seed.
        # Exemplo com seed=8:
        #   i=0 -> posição 8   (8 + 0)
        #   i=1 -> posição 9   (8 + 1)
        #   i=2 -> posição 10  (8 + 2)
        # O "% len(xlat)" existe só para o caso da senha ser tão
        # longa que passe do fim da tabela (53 posições) -> aí ele
        # "dá a volta" e recomeça do início.
        posicao_na_tabela = (seed + i) % len(xlat)

        # Pega o valor da chave fixa naquela posição específica
        chave = xlat[posicao_na_tabela]

        # ---------------------------------------------------
        # A OPERAÇÃO CENTRAL: XOR bit a bit
        # ---------------------------------------------------
        # byte ^ chave faz XOR entre os dois números, bit por
        # bit (é o operador "^" do Python para XOR).
        #
        # Isso é a mesma conta que fizemos na mão:
        #   0110 0011  (byte cifrado, em binário)
        # ^ 0100 0001  (chave da tabela, em binário)
        # -----------
        #   0010 0010  (resultado: o código ASCII original)
        #
        # Como o byte cifrado foi originalmente criado fazendo
        # "ASCII_original XOR chave", refazer XOR com a MESMA
        # chave desfaz a operação e devolve o ASCII original.
        # Essa é a propriedade "reversível" do XOR que discutimos.
        # ---------------------------------------------------
        codigo_ascii_original = byte ^ chave

        # chr() converte o número ASCII de volta para o
        # caractere de texto correspondente (ex: 99 -> 'c')
        caractere = chr(codigo_ascii_original)

        # Vai concatenando cada caractere decifrado na senha final
        result += caractere

    # Depois de passar por todos os bytes, 'result' já é a
    # senha original completa, em texto puro.
    return result


# ============================================================
# TESTE com uma senha real (tirada do running-config do SW1)
# ============================================================
senha_cifrada = "0802455D0A16091E1C0E1C057F7E"
senha_original = cisco_type7_decrypt(senha_cifrada)

print(f"Senha cifrada:  {senha_cifrada}")
print(f"Senha original: {senha_original}")