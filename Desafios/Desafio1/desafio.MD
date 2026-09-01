# Criar um código que quebra a criptografia do Service password encrypition cisco

Os dois processos, espelhados

CRIPTOGRAFAR (o que o Cisco faz quando você digita a senha pela primeira vez):

Você tem:     "Ciscolinepa55"  (senha em texto puro)
Você não tem: os bytes cifrados ainda

1. Cisco sorteia um seed (ex: 8)
2. Para cada letra da senha, pega o ASCII e faz XOR com xlat[posição]
3. Resultado: bytes cifrados → salvos como "08" + hex

DECRIPTOGRAFAR (o que o nosso script faz):

Você tem:     "0802455D0A16091E1C0E1C057F7E"  (bytes cifrados + seed)
Você não tem: a senha original ainda

1. Lê o seed que já está salvo (8)
2. Para cada byte cifrado, faz XOR com xlat[posição] (mesma posição!)
3. Resultado: ASCII original → senha em texto puro