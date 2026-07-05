# Aur Sentinel

Aur Sentinel é uma ferramenta Qt/KDE simples para auditar pacotes AUR antes do `makepkg`.

O fluxo principal é intencionalmente curto:

```text
Buscar pacote -> Selecionar resultado -> Auditar -> Instalar somente se estiver OK
```

O objetivo é responder uma pergunta prática:

```text
Este pacote AUR tem sinais compatíveis com os incidentes AUR conhecidos?
```

## O que o app faz

- busca pacotes pela AUR RPC API;
- mostra versão, descrição, votos, popularidade, mantenedor e metadados do pacote selecionado;
- clona `https://aur.archlinux.org/<pacote>.git` em `~/Downloads`;
- lista os arquivos versionados;
- coleta os últimos commits;
- coleta o diff do último commit;
- resume os campos principais do `PKGBUILD`;
- bloqueia padrões compatíveis com incidentes AUR documentados antes de qualquer `makepkg`;
- bloqueia arquivos versionados sensíveis como `*.install`, units systemd, hooks, regras udev, polkit e sudoers;
- se não houver bloqueio inicial, executa `makepkg --verifysource` e `makepkg -sr`;
- localiza pacotes finais `*.pkg.tar.zst`;
- inspeciona metadados com `pacman -Qip`;
- lista arquivos instalados com `pacman -Qlp`;
- bloqueia Install Script, caminhos sensíveis, setuid, setgid e Linux capabilities.
- permite instalar somente os `*.pkg.tar.zst` gerados pela auditoria atual quando o status é `OK — pode instalar`.

## O que o app não faz

- não chama helper AUR;
- não chama `yay`, `paru`, `octopi` ou ferramentas similares;
- não roda `makepkg` novamente na hora de instalar;
- não instala se a auditoria terminou vermelha ou amarela;
- não pergunta para continuar depois de um bloqueio.

## Estados

**OK — pode instalar**

Nenhum padrão compatível com incidentes AUR documentados foi encontrado. O pacote foi validado, compilado sem instalar e o conteúdo final foi inspecionado.

**INSEGURO — revisão manual necessária**

Foram encontrados padrões compatíveis com incidentes AUR documentados. Não execute `makepkg` antes de revisar manualmente ou enviar o relatório para análise com IA.

**Erro na auditoria**

A auditoria não foi concluída por erro operacional, dependência ausente ou falha de build. Isso não classifica o pacote como seguro nem inseguro.

## Copiar para IA

O botão `Copiar para IA` copia um relatório Markdown completo com:

- pacote, data/hora e diretório de trabalho;
- resultado final e motivo;
- padrões e arquivos sensíveis encontrados;
- metadados do pacote AUR;
- últimos commits;
- diff do último commit;
- campos principais do `PKGBUILD`;
- saída de `makepkg --verifysource`, se executado;
- saída de `makepkg -sr`, se executado;
- saída de `pacman -Qip` e `pacman -Qlp`, se executadas;
- checks de Install Script, paths sensíveis, setuid/setgid e capabilities.

## Instalação

O botão `Instalar` fica desabilitado até a auditoria atual terminar em `OK — pode instalar`.

Quando habilitado, ele instala apenas os arquivos `*.pkg.tar.zst` criados no diretório daquela auditoria usando `pacman -U` via `pkexec`, `kdesu` ou `kdesudo`. O app não usa helper AUR e não recompila o pacote nessa etapa.

## Executar

```bash
python main.py
```

## Testes

```bash
pytest
```
