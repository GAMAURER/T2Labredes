# T2 Laboratório de Redes de Computadores

## Monitorador Passivo

O monitorador passivo é uma ferramenta utilizada para monitorar o trafego de pacotes na rede local, para executá-lo pode-se simplesmente usar o comando python3 sniffer.py e o monitoramento começará para interromper a execução o comando ctrl+c deve ser utilizado. Ao interromper o programa uma série de informações sobre a execução serão exibidas.

`sudo python3 sniffer.py`

## Monitorador Ativo 

O monitorador ativo recebe uma rede com um CIDR(I.e. 192.168.100.0/24) e uma range de portas i.e 100-110 e retorna quais máquinas estão ativas e quais as portas delas que estão ativas. Para rodar este programa basta rodar o código abaixo.

`sudo python3 map.py <rede/CIDR> <porta inicial-porta final>`