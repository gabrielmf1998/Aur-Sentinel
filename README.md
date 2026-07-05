````markdown
![Aur Sentinel](https://i.ibb.co/Ng3PHPp2/image.png)

## Requisitos 🚨

O **Aur Sentinel** parte do princípio de que você já utiliza Arch Linux ou uma distribuição compatível com pacotes AUR.

Ele foi pensado principalmente para usuários de Arch Linux com ambiente gráfico KDE/Plasma, mas pode funcionar em outros ambientes desde que as dependências necessárias estejam instaladas.

Dependências esperadas:

- Arch Linux ou sistema compatível com `pacman`
- `git`
- `base-devel`
- `makepkg`
- `pacman`
- `bsdtar`
- `file`
- Qt/KDE conforme o pacote instalado exigir

O Aur Sentinel **não substitui o pacman**, **não substitui o makepkg** e **não é um helper AUR tradicional**.

Ele é uma ferramenta visual para auditar pacotes AUR antes da instalação.

## Como utilizar❓

Baixe o pacote `.pacman` mais recente na página de releases e instale com:

- Terminal: 🚀

```bash
sudo pacman -U aursentinel-*.pacman
````

Também é possível instalar o pacote no formato padrão do Arch:

```bash
sudo pacman -U aursentinel-*.pkg.tar.zst
```

Depois de instalado, abra pelo menu do KDE ou pelo terminal:

```bash
aursentinel
```

## Porque foi criado❓

Com cada vez mais usuários usando Arch Linux, também cresce o uso do AUR. O AUR é uma das maiores forças do Arch, mas exige atenção: os pacotes são mantidos pela comunidade e o usuário deve revisar o que será executado antes de instalar.

Foi assim que nasceu o **Aur Sentinel**.

O projeto foi criado para ajudar usuários de Arch Linux a usar o AUR com mais clareza, menos medo e mais controle. A ideia não é assustar o usuário, nem dizer que todo pacote AUR é perigoso. A ideia é mostrar, de forma visual e simples, se um pacote apresenta padrões parecidos com incidentes AUR já documentados.

O Aur Sentinel não tenta substituir o conhecimento técnico. Ele tenta organizar a análise inicial para que o usuário veja, de forma clara, o que está acontecendo antes de rodar `makepkg`.

## O que ele consegue fazer❓

Logo na tela inicial, o Aur Sentinel permite buscar pacotes AUR, selecionar um pacote e iniciar uma auditoria visual.

Durante a auditoria, ele executa uma sequência de verificações antes de permitir qualquer instalação:

* clona o repositório AUR do pacote na pasta Downloads
* lista os arquivos versionados do pacote
* mostra os últimos commits
* mostra o diff do último commit
* analisa o PKGBUILD
* procura padrões compatíveis com incidentes AUR documentados
* detecta uso suspeito de `.install`
* detecta comandos como `curl`, `wget`, `npm`, `bun`, `node`, `systemctl`, `setcap`, `dkms` e outros padrões sensíveis
* bloqueia antes do `makepkg` se encontrar algo compatível com incidentes conhecidos
* valida fontes e checksums
* compila o pacote sem instalar
* inspeciona o pacote final
* verifica se existe `Install Script`
* verifica caminhos sensíveis como systemd, udev, polkit, sudoers, cron e módulos do kernel
* verifica setuid, setgid e Linux capabilities
* gera um relatório completo para copiar e enviar para análise com IA

O resultado é apresentado de forma simples:

* 🟢 **OK — pode instalar**
* 🔴 **INSEGURO — revisão manual necessária**
* 🟡 **Erro na auditoria**

## Do que ele protege❓

O Aur Sentinel foi criado com foco em padrões usados em incidentes AUR já documentados.

Ele verifica sinais compatíveis com casos como:

* **2018**: pacotes AUR com execução remota via `curl | bash` e download de scripts externos
* **2025**: pacotes como `librewolf-fix-bin`, `firefox-patch-bin` e `zen-browser-patched-bin`, associados a scripts remotos/RAT
* **2026**: campanhas com adoção maliciosa de pacotes órfãos e uso de `npm`, `atomic-lockfile`, `lockfile-js` e `js-digest`
* **2026**: nova onda usando `bun`, `execa`, `commander` e padrões similares

Ele também verifica elementos sensíveis como:

* `.install`
* hooks de instalação
* `systemd`
* `udev`
* `polkit`
* `sudoers`
* `dkms`
* `setcap`
* `Install Script`
* setuid/setgid
* Linux capabilities
* caminhos sensíveis no pacote final

## Como ele verifica❓

O Aur Sentinel segue um fluxo **fail-closed**.

Isso significa que, se algo sensível for encontrado, ele para antes de executar `makepkg`.

O fluxo básico é:

1. o usuário busca um pacote AUR
2. o pacote é clonado na pasta Downloads
3. os arquivos do repositório são analisados
4. os commits recentes são exibidos
5. o último diff é inspecionado
6. o PKGBUILD é analisado
7. padrões sensíveis são procurados
8. se algo for encontrado, a auditoria é bloqueada
9. se nada for encontrado, as fontes são validadas
10. o pacote é compilado sem instalar
11. o pacote final é inspecionado
12. o resultado é exibido de forma clara

Se tudo estiver limpo, o Aur Sentinel mostra:

```text
OK — pode instalar
```

Se encontrar algo sensível, ele mostra:

```text
INSEGURO — revisão manual necessária
```

Se houver falha de rede, pacote inexistente, dependência ausente ou erro de build, ele mostra:

```text
Erro na auditoria
```

## O que significa OK — pode instalar❓

Quando o Aur Sentinel mostra **OK — pode instalar**, significa que o pacote passou pelo filtro contra padrões usados em incidentes AUR conhecidos.

Isso quer dizer que:

* nenhum padrão sensível foi encontrado nos arquivos versionados
* nenhum arquivo sensível foi encontrado no repositório AUR
* as fontes/checksums foram validadas
* o pacote compilou sem instalar
* o pacote final foi localizado
* o pacote final não possui `Install Script`
* o pacote não instala em caminhos sensíveis
* o pacote não possui setuid/setgid
* o pacote não possui Linux capabilities

Isso não é uma auditoria completa do código upstream, mas é uma validação prática contra os vetores AUR conhecidos.

## O que significa INSEGURO — revisão manual necessária❓

Quando o Aur Sentinel mostra **INSEGURO — revisão manual necessária**, significa que foi encontrado algum padrão compatível com incidentes AUR documentados.

Exemplos:

* uso de `curl` ou `wget`
* uso de `npm`, `bun`, `node`, `npx`, `pnpm` ou `yarn`
* uso de `.install`
* uso de `systemctl`
* uso de `setcap`
* instalação em caminhos sensíveis
* presença de `sudoers`, `polkit`, `udev`, `dkms`
* `SKIP` em checksums
* comandos como `bash -c`, `sh -c`, `eval`, `base64`
* arquivos com setuid/setgid
* capabilities no pacote final

Isso não significa automaticamente que o pacote é malware. Significa que o pacote precisa de revisão manual antes de qualquer instalação.

## Copiar para IA 🤖

O Aur Sentinel possui a função **Copiar para IA**.

Ela gera um relatório técnico em Markdown contendo:

* nome do pacote
* data e hora da auditoria
* diretório de trabalho
* status final
* motivo da decisão
* padrões encontrados
* arquivos sensíveis encontrados
* histórico recente
* diff do último commit
* resumo do PKGBUILD
* saída do `makepkg --verifysource`
* saída do `makepkg -sr`
* metadados do pacote final
* arquivos que seriam instalados
* checks finais
* conclusão

A ideia é permitir que o usuário cole o relatório em uma IA ou envie para alguém mais experiente analisar.

## Por que Arch❓

O foco principal é Arch Linux porque o Arch representa liberdade, controle e aprendizado.

O AUR é parte importante desse ecossistema, mas também exige responsabilidade. O Aur Sentinel existe para reduzir a barreira de entrada e ajudar o usuário a usar o AUR de forma mais consciente.

Ele não tenta tirar o controle do usuário. Pelo contrário: ele mostra o que será analisado, onde o pacote foi baixado, quais comandos seriam executados e por que um pacote foi aprovado ou bloqueado.

O objetivo é simples:

```text
usar AUR com mais clareza, menos medo e mais controle
```

## O que o Aur Sentinel não faz❓

O Aur Sentinel não promete segurança absoluta.

Ele não garante que:

* o código upstream é 100% seguro
* não existe backdoor sofisticado no código-fonte
* o maintainer upstream nunca será comprometido
* todo pacote AUR aprovado é perfeito
* toda falha futura será detectada automaticamente

O que ele faz é bloquear padrões compatíveis com incidentes AUR conhecidos e entregar uma análise inicial clara antes da instalação.

## Filosofia do projeto 🛡️

O Aur Sentinel foi criado com uma ideia simples:

```text
AUR não precisa ser usado no escuro.
```

O usuário não deve instalar pacotes com medo, mas também não deve instalar sem entender nada.

O Aur Sentinel tenta ficar no meio termo:

* simples para iniciantes
* claro para usuários intermediários
* útil para quem quer revisar pacotes rapidamente
* conservador quando encontra padrões perigosos
* transparente sobre o que foi analisado

Se estiver tudo certo, ele mostra verde.

Se precisar revisar, ele mostra vermelho.

Se algo falhar, ele mostra erro operacional.

Sem pânico. Sem enrolação. Sem esconder comandos.

```
```
