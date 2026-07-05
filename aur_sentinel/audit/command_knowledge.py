from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class CommandKnowledge:
    command: str | None
    category: str
    suggested_severity: str
    regex: str
    description: str
    aur_risk: str
    review: str
    recommendation: str
    safe_example: str = ""
    acceptable_when: str = ""
    suspicious_when: str = ""
    preferred_alternative: str = ""


DEFAULT_KNOWLEDGE = CommandKnowledge(
    command="padrao suspeito",
    category="other",
    suggested_severity="INFO",
    regex=r"$^",
    description="Padrao textual relevante para auditoria estatica.",
    aur_risk="No contexto do AUR, revise se esse trecho altera o build, baixa codigo externo ou executa comandos inesperados.",
    review="Revise a linha, o arquivo e o contexto da funcao do PKGBUILD ou scriptlet.",
    recommendation="Continue apenas apos revisao manual do trecho.",
)


def _entry(
    command: str,
    category: str,
    severity: str,
    regex: str,
    description: str,
    aur_risk: str,
    review: str,
    recommendation: str,
    safe_example: str = "",
    acceptable_when: str = "",
    suspicious_when: str = "",
    preferred_alternative: str = "",
) -> CommandKnowledge:
    return CommandKnowledge(
        command=command,
        category=category,
        suggested_severity=severity,
        regex=regex,
        description=description,
        aur_risk=aur_risk,
        review=review,
        recommendation=recommendation,
        safe_example=safe_example,
        acceptable_when=acceptable_when,
        suspicious_when=suspicious_when,
        preferred_alternative=preferred_alternative,
    )


REMOTE_DOWNLOAD_RISK = (
    "No AUR, downloads feitos em funcoes de build podem buscar codigo que nao esta declarado "
    "em source=() nem validado pelos checksums do PKGBUILD."
)
DEPENDENCY_RISK = (
    "Durante o build, esse gerenciador pode baixar codigo externo e executar hooks/scripts de dependencias, "
    "frequentemente fora de source=() do PKGBUILD, reduzindo reprodutibilidade e aumentando risco de supply chain."
)
REMOTE_EXEC_REVIEW = (
    "Revise URL, dominio, HTTPS, assinatura, checksum, conteudo baixado e por que isso nao esta em source=()."
)


COMMAND_KNOWLEDGE: list[CommandKnowledge] = [
    _entry(
        "curl ... | bash",
        "remote_execution",
        "CRITICAL",
        r"\bcurl\b[^|;\n]*\|\s*bash\b",
        "Baixa conteudo de uma URL com curl e envia diretamente para o interpretador Bash.",
        "Pode executar codigo remoto durante o build sem revisao local previa e sem validacao explicita por checksum no PKGBUILD.",
        REMOTE_EXEC_REVIEW,
        "Reprove salvo justificativa muito forte; prefira declarar o arquivo em source=() com checksum.",
        suspicious_when="Suspeito em qualquer etapa de build/install porque executa conteudo remoto antes da revisao local.",
        preferred_alternative="Declarar arquivo em source=() e validar com checksum ou assinatura.",
    ),
    _entry(
        "curl ... | sh",
        "remote_execution",
        "CRITICAL",
        r"\bcurl\b[^|;\n]*\|\s*sh\b",
        "Baixa conteudo de uma URL com curl e envia diretamente para sh.",
        "Pode executar codigo remoto durante o build sem revisao local previa.",
        REMOTE_EXEC_REVIEW,
        "Prefira source=() com checksum e revisao do conteudo antes da execucao.",
    ),
    _entry(
        "wget ... | sh",
        "remote_execution",
        "CRITICAL",
        r"\bwget\b[^|;\n]*(?:-O\s*-|-qO\s*-|-qO-)[^|;\n]*\|\s*(?:bash|sh)\b",
        "Baixa conteudo com wget na saida padrao e envia diretamente para um shell.",
        "Executa codigo remoto durante o build sem materializar o arquivo para revisao local previa.",
        REMOTE_EXEC_REVIEW,
        "Declare a fonte em source=(), valide checksum e execute apenas conteudo revisado.",
    ),
    _entry(
        "bash <(curl ...)",
        "remote_execution",
        "CRITICAL",
        r"\bbash\s+<\(\s*curl\b",
        "Usa substituicao de processo para executar com Bash conteudo baixado por curl.",
        "Tem efeito semelhante a pipe remoto para shell e dificulta revisao antes da execucao.",
        REMOTE_EXEC_REVIEW,
        "Evite execucao direta; baixe, valide e revise o arquivo explicitamente.",
    ),
    _entry(
        "sh <(wget ...)",
        "remote_execution",
        "CRITICAL",
        r"\bsh\s+<\(\s*wget\b",
        "Usa substituicao de processo para executar com sh conteudo baixado por wget.",
        "Pode executar codigo remoto sem etapa clara de revisao ou checksum.",
        REMOTE_EXEC_REVIEW,
        "Evite execucao direta; use source=() e checksums fortes.",
    ),
    _entry(
        "curl -F",
        "network_exfiltration",
        "CRITICAL",
        r"\bcurl\s+-F\b",
        "Envia dados via multipart/form-data com curl.",
        "Se combinado com arquivos locais ou segredos, pode indicar upload de dados durante build/install.",
        "Revise destino, parametros -F e qualquer referencia a HOME, chaves, tokens ou configuracoes privadas.",
        "Uploads durante build raramente sao esperados; remova ou justifique claramente.",
    ),
    _entry(
        "curl --data",
        "network_exfiltration",
        "CRITICAL",
        r"\bcurl\s+--data\b",
        "Envia corpo HTTP com curl.",
        "Pode transmitir dados locais para um endpoint externo durante build/install.",
        "Revise URL, payload e variaveis usadas no corpo da requisicao.",
        "Evite transmissao de dados no build; documente e limite qualquer chamada necessaria.",
    ),
    _entry(
        "curl -d",
        "network_exfiltration",
        "CRITICAL",
        r"\bcurl\s+-d\b",
        "Envia dados em uma requisicao HTTP com curl.",
        "Pode transmitir dados locais ou ambiente para fora do sistema durante build/install.",
        "Revise payload, URL e referencias a credenciais.",
        "Evite uploads no build e prefira fontes declaradas/verificadas.",
    ),
    _entry(
        "wget --post-data",
        "network_exfiltration",
        "CRITICAL",
        r"\bwget\s+--post-data\b",
        "Envia dados por HTTP POST usando wget.",
        "Pode transmitir dados locais para uma URL externa.",
        "Revise o payload, o dominio e qualquer dado lido do ambiente do usuario.",
        "Uploads durante build devem ser tratados como red flag forte.",
    ),
    _entry(
        "curl",
        "remote_download",
        "MEDIUM",
        r"\bcurl\b",
        "Este comando normalmente baixa ou envia conteudo via URL.",
        REMOTE_DOWNLOAD_RISK,
        "Revise se a URL pertence ao upstream oficial e se o download esta declarado em source=() com checksum.",
        "Prefira source=() com sha256sums/b2sums e sem execucao direta.",
    ),
    _entry(
        "wget",
        "remote_download",
        "MEDIUM",
        r"\bwget\b",
        "Este comando normalmente baixa conteudo de uma URL.",
        REMOTE_DOWNLOAD_RISK,
        "Revise URL, flags usadas e validacao por checksum.",
        "Prefira source=() com checksum forte.",
    ),
    _entry(
        "aria2c",
        "remote_download",
        "MEDIUM",
        r"\baria2c\b",
        "Baixa arquivos usando HTTP(S), FTP, BitTorrent ou metalinks.",
        REMOTE_DOWNLOAD_RISK,
        "Revise URLs, mirrors e hashes esperados.",
        "Prefira declarar fontes no PKGBUILD e validar hashes.",
    ),
    _entry(
        "git clone",
        "remote_download",
        "MEDIUM",
        r"\bgit\s+clone\b",
        "Clona um repositorio Git remoto.",
        "Pode buscar codigo fora de source=(), sem pinning claro de commit/tag e sem checksum.",
        "Revise URL, branch, commit fixado e se o repositorio e o upstream oficial.",
        "Use source=() com git+URL e pinning quando possivel.",
    ),
    _entry(
        "eval",
        "dynamic_execution",
        "CRITICAL",
        r"\beval\b",
        "Avalia uma string como codigo shell.",
        "Pode executar conteudo construido dinamicamente durante o build, dificultando auditoria estatica.",
        "Revise de onde vem a string avaliada e se ha entrada remota ou ofuscada.",
        "Evite eval; use chamadas diretas com argumentos explicitos.",
    ),
    _entry("exec", "dynamic_execution", "MEDIUM", r"\bexec\b", "Substitui o processo atual por outro comando.", "Pode ocultar o fluxo real executado se combinado com variaveis dinamicas.", "Revise comando e argumentos efetivos.", "Use comandos explicitos e simples."),
    _entry("bash -c", "dynamic_execution", "CRITICAL", r"\bbash\s+-c\b", "Executa uma string como comando Bash.", "Pode executar codigo montado dinamicamente durante build/install.", "Revise origem da string e expansoes de variaveis.", "Prefira argumentos explicitos sem shell intermediario."),
    _entry("sh -c", "dynamic_execution", "CRITICAL", r"\bsh\s+-c\b", "Executa uma string como comando sh.", "Pode executar codigo dinamico e dificultar auditoria.", "Revise origem da string e expansoes.", "Prefira chamadas diretas."),
    _entry("python -c", "dynamic_execution", "CRITICAL", r"\bpython(?:3)?\s+-c\b", "Executa codigo Python passado na linha de comando.", "Pode executar logica dinamica ou baixada durante o build.", "Revise o codigo inline e entradas usadas.", "Prefira scripts versionados e revisaveis."),
    _entry("perl -e", "dynamic_execution", "CRITICAL", r"\bperl\s+-e\b", "Executa codigo Perl inline.", "Pode esconder logica em uma linha de comando pouco revisavel.", "Revise o codigo inline integralmente.", "Prefira arquivo versionado e legivel."),
    _entry("ruby -e", "dynamic_execution", "CRITICAL", r"\bruby\s+-e\b", "Executa codigo Ruby inline.", "Pode esconder logica em uma linha de comando pouco revisavel.", "Revise o codigo inline integralmente.", "Prefira arquivo versionado e legivel."),
    _entry("base64 -d", "obfuscation", "CRITICAL", r"\bbase64\s+-d\b", "Decodifica dados base64.", "Pode reconstruir payloads ou comandos ofuscados durante build/install.", "Revise a entrada decodificada e o destino da saida.", "Evite payloads codificados; mantenha scripts em texto claro."),
    _entry("base32 -d", "obfuscation", "CRITICAL", r"\bbase32\s+-d\b", "Decodifica dados base32.", "Pode reconstruir payloads ofuscados.", "Revise a entrada e o destino da saida.", "Mantenha conteudo revisavel em texto claro."),
    _entry("xxd -r", "obfuscation", "CRITICAL", r"\bxxd\s+-r\b", "Reverte dump hexadecimal para bytes.", "Pode reconstruir binarios ou scripts ofuscados durante build/install.", "Revise a origem do hex dump e o arquivo gerado.", "Evite reconstruir payloads opacos."),
    _entry("openssl enc", "obfuscation", "CRITICAL", r"\bopenssl\s+enc\b", "Criptografa ou descriptografa dados usando openssl enc.", "Pode ocultar payloads ou configurar dados nao revisaveis estaticamente.", "Revise chaves, entradas e arquivos de saida.", "Evite conteudo cifrado no build."),
    _entry("gpg --decrypt", "obfuscation", "CRITICAL", r"\bgpg\s+--decrypt\b", "Descriptografa conteudo com GPG.", "Pode materializar conteudo nao visivel no repositorio antes do build.", "Revise origem, assinatura e destino do conteudo descriptografado.", "Prefira fontes publicas verificadas por assinatura/checksum."),
    _entry(
        "npm install",
        "dependency_manager",
        "MEDIUM",
        r"\bnpm\s+install\b",
        "Resolve e instala dependencias Node.js conforme package.json. Pode executar scripts de ciclo de vida como preinstall, install, postinstall e prepare.",
        "Pode baixar codigo externo durante build/install fora de source=() do PKGBUILD e executar scripts de dependencias. Foi um padrao relevante em ataques recentes ao AUR, nos quais pacotes aparentemente legitimos passaram a instalar dependencias npm maliciosas.",
        "Verifique package-lock.json, npm-shrinkwrap.json, package.json, scripts npm, origem das dependencias e se ha lockfile versionado.",
        "Preferir npm ci com lockfile. Avaliar --ignore-scripts quando compativel.",
        acceptable_when="Pode ser aceitavel quando ha lockfile versionado, dependencias coerentes com o upstream, sem scripts suspeitos, e quando o build exige ecossistema Node.js.",
        suspicious_when="Suspeito em *.install, suspeito se adicionado recentemente, suspeito sem lockfile, critico se instalar pacote npm nao relacionado ao projeto.",
        preferred_alternative="npm ci com lockfile versionado e scripts revisados.",
    ),
    _entry("npm ci", "dependency_manager", "MEDIUM", r"\bnpm\s+ci\b", "Instala dependencias Node.js estritamente a partir de lockfile.", DEPENDENCY_RISK, "Revise lockfile e scripts de ciclo de vida.", "Prefira npm ci com lockfile versionado e scripts revisados."),
    _entry("npm run", "dependency_manager", "MEDIUM", r"\bnpm\s+run\b", "Executa script definido em package.json.", "Pode acionar comandos arbitrarios definidos pelo projeto.", "Revise o script chamado e scripts transitivos.", "Execute apenas scripts necessarios e revisados."),
    _entry("npx", "dependency_manager", "HIGH", r"\bnpx\b", "Executa binarios de pacotes Node.js, podendo baixa-los sob demanda.", "Pode executar codigo externo nao pinado durante o build.", "Revise pacote, versao e origem.", "Evite npx; use dependencias fixadas e auditadas."),
    _entry("yarn", "dependency_manager", "MEDIUM", r"\byarn\b", "Instala ou executa scripts do ecossistema Node.js.", DEPENDENCY_RISK, "Revise yarn.lock e scripts.", "Use lockfile versionado e scripts revisados."),
    _entry("pnpm dlx", "dependency_manager", "HIGH", r"\bpnpm\s+dlx\b", "Baixa e executa pacote pnpm temporariamente.", "Pode executar codigo externo dinamico durante o build.", "Revise pacote, versao e origem.", "Evite dlx; use dependencias fixadas."),
    _entry("pnpm", "dependency_manager", "MEDIUM", r"\bpnpm\b", "Instala dependencias ou executa scripts Node.js com pnpm.", DEPENDENCY_RISK, "Revise pnpm-lock.yaml e scripts.", "Use lockfile versionado e scripts revisados."),
    _entry("bunx", "dependency_manager", "HIGH", r"\bbunx\b", "Executa pacotes JavaScript sob demanda usando Bun.", "Pode baixar e executar codigo externo dinamicamente.", "Revise pacote, versao e origem.", "Evite bunx no build; fixe dependencias."),
    _entry(
        "bun install",
        "dependency_manager",
        "MEDIUM",
        r"\bbun\s+install\b",
        "Instala dependencias do ecossistema JavaScript usando Bun e pode executar scripts definidos no projeto/dependencias.",
        "Pode baixar codigo externo durante build/install. Ataques recentes contra o AUR tambem observaram caminhos baseados em Bun para instalar dependencias maliciosas.",
        "Revise bun.lockb/bun.lock, scripts, nomes de dependencias e coerencia com o upstream.",
        "Use lockfile versionado e scripts revisados.",
        acceptable_when="Pode ser aceitavel quando ha lockfile versionado e o upstream usa Bun como ferramenta de build.",
        suspicious_when="Suspeito em *.install, suspeito sem lockfile, suspeito quando instala dependencia nao relacionada ao upstream.",
        preferred_alternative="bun install com lockfile versionado e scripts revisados; avaliar desabilitar scripts quando compativel.",
    ),
    _entry("bun", "dependency_manager", "MEDIUM", r"\bbun\b", "Executa Bun como runtime ou gerenciador JavaScript.", DEPENDENCY_RISK, "Revise bun.lockb/bun.lock e scripts.", "Use lockfile e scripts revisados."),
    _entry("python -m pip install", "dependency_manager", "MEDIUM", r"\bpython(?:3)?\s+-m\s+pip\s+install\b", "Instala pacotes Python via pip executado como modulo.", DEPENDENCY_RISK, "Revise requirements, hashes, URLs e setup hooks.", "Use dependencias de repositorio ou hashes pinados quando possivel."),
    _entry("pip install", "dependency_manager", "MEDIUM", r"\bpip\s+install\b", "Instala pacotes Python e pode executar hooks de build.", DEPENDENCY_RISK, "Revise requirements, URLs, hashes e pyproject/setup.py.", "Use hashes pinados e evite URLs dinamicas."),
    _entry("poetry install", "dependency_manager", "MEDIUM", r"\bpoetry\s+install\b", "Instala dependencias Python conforme pyproject/poetry.lock.", DEPENDENCY_RISK, "Revise poetry.lock e scripts/plugins.", "Use lockfile versionado."),
    _entry("pipenv install", "dependency_manager", "MEDIUM", r"\bpipenv\s+install\b", "Instala dependencias Python conforme Pipfile/Pipfile.lock.", DEPENDENCY_RISK, "Revise Pipfile.lock e fontes.", "Use lockfile versionado e hashes."),
    _entry("cargo build", "dependency_manager", "MEDIUM", r"\bcargo\s+build\b", "Compila projeto Rust e pode baixar crates conforme Cargo.toml/Cargo.lock.", DEPENDENCY_RISK, "Revise Cargo.lock, build.rs e crates com scripts de build.", "Use lockfile e fontes vendorizadas quando adequado."),
    _entry("cargo install", "dependency_manager", "HIGH", r"\bcargo\s+install\b", "Instala binarios Rust a partir de crates ou repositorios.", "Pode baixar e compilar codigo externo durante o build.", "Revise origem, versao e flags como --git.", "Evite cargo install dinamico em PKGBUILD."),
    _entry("cargo update", "dependency_manager", "MEDIUM", r"\bcargo\s+update\b", "Atualiza resolucao de dependencias Rust.", "Pode alterar dependencias durante o build e reduzir reprodutibilidade.", "Revise Cargo.lock resultante.", "Nao atualize lockfile durante build."),
    _entry("go generate", "dependency_manager", "HIGH", r"\bgo\s+generate\b", "Executa comandos declarados em diretivas //go:generate.", "Pode executar comandos arbitrarios definidos no codigo fonte.", "Revise todas as diretivas //go:generate.", "Evite go generate sem revisao explicita."),
    _entry("go install", "dependency_manager", "HIGH", r"\bgo\s+install\b", "Baixa/compila modulo Go, frequentemente com versao @latest.", "Pode buscar codigo externo dinamico durante o build.", "Revise modulo, versao e checksums.", "Evite @latest; fixe versoes."),
    _entry("go get", "dependency_manager", "MEDIUM", r"\bgo\s+get\b", "Resolve e baixa modulos Go.", DEPENDENCY_RISK, "Revise go.mod e go.sum.", "Use versoes fixadas e go.sum versionado."),
    _entry("go mod download", "dependency_manager", "MEDIUM", r"\bgo\s+mod\s+download\b", "Baixa modulos declarados em go.mod.", DEPENDENCY_RISK, "Revise go.mod, go.sum e proxy usado.", "Use go.sum versionado."),
    _entry("go mod tidy", "dependency_manager", "MEDIUM", r"\bgo\s+mod\s+tidy\b", "Atualiza go.mod/go.sum conforme imports.", "Pode alterar dependencias durante o build.", "Revise diff de go.mod/go.sum.", "Evite modificar lock/metadados durante build."),
    _entry("gem install", "dependency_manager", "MEDIUM", r"\bgem\s+install\b", "Instala gems Ruby.", DEPENDENCY_RISK, "Revise gem, versao e origem.", "Use dependencias empacotadas ou lockfile."),
    _entry("bundle install", "dependency_manager", "MEDIUM", r"\bbundle\s+install\b", "Instala gems conforme Gemfile/Gemfile.lock.", DEPENDENCY_RISK, "Revise Gemfile.lock e fontes.", "Use lockfile versionado."),
    _entry("composer update", "dependency_manager", "HIGH", r"\bcomposer\s+update\b", "Atualiza dependencias PHP e lockfile.", "Pode mudar dependencias durante build.", "Revise composer.lock resultante.", "Evite update no build; use composer install com lockfile."),
    _entry("composer install", "dependency_manager", "MEDIUM", r"\bcomposer\s+install\b", "Instala dependencias PHP conforme composer.lock.", DEPENDENCY_RISK, "Revise composer.lock e scripts.", "Use lockfile versionado e scripts revisados."),
    _entry("mvn dependency:get", "dependency_manager", "HIGH", r"\bmvn\s+dependency:get\b", "Busca artefato Maven especifico sob demanda.", DEPENDENCY_RISK, "Revise coordenadas, repositorios e checksums.", "Evite downloads dinamicos fora do build padrao."),
    _entry("mvn package", "dependency_manager", "MEDIUM", r"\bmvn\s+package\b", "Compila/empacota projeto Maven e resolve dependencias.", DEPENDENCY_RISK, "Revise pom.xml, plugins e repositorios.", "Use versoes fixas e repositorios esperados."),
    _entry("mvn install", "dependency_manager", "MEDIUM", r"\bmvn\s+install\b", "Compila e instala artefatos no repositorio Maven local.", DEPENDENCY_RISK, "Revise pom.xml, plugins e repositorios.", "Evite efeitos persistentes desnecessarios no HOME."),
    _entry("gradle build", "dependency_manager", "MEDIUM", r"\bgradle\s+build\b", "Executa build Gradle e resolve dependencias/plugins.", DEPENDENCY_RISK, "Revise build.gradle, settings e plugins.", "Use lockfiles e repositorios fixos."),
    _entry("./gradlew", "dependency_manager", "HIGH", r"(^|\s)\./gradlew\b", "Executa wrapper Gradle incluido no projeto.", "O wrapper e scripts Gradle podem baixar distribuicao Gradle e executar plugins/codigo externo.", "Revise gradlew, gradle-wrapper.properties, checksums e scripts Gradle.", "Execute apenas apos revisar wrapper e origem da distribuicao."),
    _entry("dotnet restore", "dependency_manager", "MEDIUM", r"\bdotnet\s+restore\b", "Restaura pacotes NuGet de projeto .NET.", DEPENDENCY_RISK, "Revise *.csproj, packages.lock.json e fontes NuGet.", "Use lockfile e feeds esperados."),
    _entry("nuget restore", "dependency_manager", "MEDIUM", r"\bnuget\s+restore\b", "Restaura pacotes NuGet.", DEPENDENCY_RISK, "Revise packages.config/lockfile e feeds.", "Use lockfile e fontes esperadas."),
    _entry("systemctl enable --now", "persistence", "CRITICAL", r"\bsystemctl\s+enable\s+--now\b", "Habilita e inicia um servico systemd imediatamente.", "Pode criar persistencia ou iniciar codigo durante instalacao sem acao manual do usuario.", "Revise unidade systemd, alvo e necessidade.", "Documente servico e deixe ativacao para o usuario quando possivel."),
    _entry("systemctl enable", "persistence", "HIGH", r"\bsystemctl\s+enable\b", "Habilita inicio automatico de servico systemd.", "Pode criar persistencia no sistema apos instalacao.", "Revise unidade e scriptlet.", "Prefira instrucoes manuais ao usuario."),
    _entry("systemctl start", "persistence", "HIGH", r"\bsystemctl\s+start\b", "Inicia um servico systemd.", "Pode executar codigo imediatamente durante install/upgrade.", "Revise unidade e timing de execucao.", "Evite iniciar servicos automaticamente."),
    _entry("crontab", "persistence", "HIGH", r"\bcrontab\b", "Lista ou altera tarefas cron do usuario.", "Pode criar execucao recorrente apos instalacao.", "Revise entradas criadas e usuario afetado.", "Nao altere cron sem consentimento explicito."),
    _entry("escrita em .bashrc", "persistence", "CRITICAL", r">\>?\s*(?:~/\.bashrc|\$HOME/\.bashrc)", "Escreve em arquivo de inicializacao Bash.", "Pode persistir comandos a cada shell interativo.", "Revise conteudo escrito e motivo.", "Evite modificar arquivos pessoais do usuario."),
    _entry("escrita em .zshrc", "persistence", "CRITICAL", r">\>?\s*(?:~/\.zshrc|\$HOME/\.zshrc)", "Escreve em arquivo de inicializacao Zsh.", "Pode persistir comandos a cada shell interativo.", "Revise conteudo escrito e motivo.", "Evite modificar arquivos pessoais do usuario."),
    _entry("escrita em .profile", "persistence", "CRITICAL", r">\>?\s*(?:~/\.profile|\$HOME/\.profile)", "Escreve em arquivo de perfil do usuario.", "Pode persistir comandos em sessoes futuras.", "Revise conteudo escrito e motivo.", "Evite modificar arquivos pessoais do usuario."),
    _entry("~/.config/autostart", "persistence", "CRITICAL", r"(?:~/\.config/autostart|\.config/autostart)", "Cria ou modifica entrada de autostart de desktop.", "Pode iniciar aplicacao automaticamente em sessoes graficas.", "Revise arquivo .desktop criado e comando executado.", "Nao crie autostart sem consentimento explicito."),
    _entry("sudo", "privilege_escalation", "CRITICAL", r"\bsudo\b", "Executa comando com elevacao via sudo.", "PKGBUILDs e scriptlets nao devem chamar sudo diretamente durante build/auditoria.", "Revise comando alvo e motivo da elevacao.", "Delegue privilegios ao makepkg/pacman apenas na etapa final padrao."),
    _entry("su", "privilege_escalation", "CRITICAL", r"\bsu\b", "Troca usuario ou executa comando como outro usuario.", "Pode contornar o fluxo esperado de permissoes do build.", "Revise comando e usuario alvo.", "Evite elevacao manual em PKGBUILD."),
    _entry("doas", "privilege_escalation", "CRITICAL", r"\bdoas\b", "Executa comando com elevacao via doas.", "Pode pedir privilegio fora do fluxo esperado.", "Revise comando alvo e motivo.", "Nao use elevacao direta no pacote."),
    _entry("pkexec", "privilege_escalation", "CRITICAL", r"\bpkexec\b", "Executa comando via polkit com privilegios elevados.", "Pode disparar prompt de privilegio fora do fluxo esperado.", "Revise comando e contexto.", "Evite elevacao direta no pacote."),
    _entry("useradd", "account_change", "HIGH", r"\buseradd\b", "Cria usuario local.", "Altera estado do sistema durante install/upgrade.", "Revise nome, shell, home e grupo.", "Use mecanismos de pacote documentados e minima permissao."),
    _entry("usermod", "account_change", "HIGH", r"\busermod\b", "Modifica usuario local.", "Pode alterar grupos, shell ou permissoes de contas existentes.", "Revise usuario alvo e flags.", "Evite alterar usuarios existentes sem necessidade clara."),
    _entry("groupadd", "account_change", "HIGH", r"\bgroupadd\b", "Cria grupo local.", "Altera estado do sistema.", "Revise nome e necessidade do grupo.", "Documente grupo e use scriptlets cautelosamente."),
    _entry("passwd", "account_change", "HIGH", r"\bpasswd\b", "Altera senha ou metadados de senha.", "Pode afetar autenticacao local.", "Revise usuario alvo e entrada usada.", "Nao altere senhas em pacote."),
    _entry("chpasswd", "account_change", "HIGH", r"\bchpasswd\b", "Atualiza senhas em lote.", "Pode alterar credenciais locais.", "Revise origem da entrada.", "Nao configure senhas em pacote."),
    _entry("chmod 4755", "dangerous_permissions", "CRITICAL", r"\bchmod\s+4755\b", "Define permissao SUID com modo 4755.", "Pode permitir execucao com privilegios do dono do arquivo.", "Revise binario alvo e justificativa.", "Evite SUID; use capabilities minimas se justificadas."),
    _entry("chmod u+s", "dangerous_permissions", "CRITICAL", r"\bchmod\s+u\+s\b", "Ativa bit SUID.", "Pode ampliar privilegios de execucao.", "Revise arquivo alvo.", "Evite SUID sem justificativa forte."),
    _entry("setcap", "dangerous_permissions", "CRITICAL", r"\bsetcap\b", "Concede Linux capabilities a arquivo.", "Pode dar privilegios especificos a binarios.", "Revise capability e binario alvo.", "Use a menor capability possivel e documente."),
    _entry("chown root", "dangerous_permissions", "CRITICAL", r"\bchown\s+root\b", "Altera dono de arquivo para root.", "Pode combinar com permissoes perigosas e alterar superficie de ataque.", "Revise arquivo alvo e modo.", "Use ownership root apenas quando esperado pelo pacote."),
    _entry("nc", "network_exfiltration", "HIGH", r"\bnc\b", "Ferramenta de rede capaz de abrir conexoes TCP/UDP.", "Pode enviar ou receber dados arbitrarios durante build/install.", "Revise host, porta e dados transmitidos.", "Evite conexoes arbitrarias no build."),
    _entry("ncat", "network_exfiltration", "HIGH", r"\bncat\b", "Ferramenta de rede semelhante ao netcat.", "Pode transferir dados ou abrir shells/conexoes.", "Revise host, porta e flags.", "Evite uso em PKGBUILD/scriptlets."),
    _entry("socat", "network_exfiltration", "HIGH", r"\bsocat\b", "Encaminha fluxos entre sockets, arquivos e processos.", "Pode criar canais de rede complexos durante build/install.", "Revise endpoints e fluxos.", "Evite canais de rede arbitrarios."),
    _entry("/dev/tcp", "network_exfiltration", "HIGH", r"/dev/tcp", "Usa recurso do shell para abrir conexao TCP.", "Pode enviar dados para rede sem binario externo.", "Revise destino e dados redirecionados.", "Evite conexoes shell diretas."),
    _entry("scp", "network_exfiltration", "HIGH", r"\bscp\b", "Transfere arquivos via SSH.", "Pode copiar arquivos locais para host remoto ou baixar conteudo nao declarado.", "Revise host e caminho.", "Evite transferencia durante build."),
    _entry("rsync", "network_exfiltration", "HIGH", r"\brsync\b", "Sincroniza arquivos local/remoto.", "Pode transferir dados para ou de hosts remotos.", "Revise origem, destino e flags.", "Use apenas fontes declaradas e verificadas."),
    _entry("ftp", "network_exfiltration", "HIGH", r"\bftp\b", "Cliente FTP para transferencia de arquivos.", "Pode baixar ou enviar dados sem garantias modernas.", "Revise servidor e arquivos.", "Prefira HTTPS em source=() com checksum."),
    _entry("sftp", "network_exfiltration", "HIGH", r"\bsftp\b", "Cliente SFTP para transferencia de arquivos.", "Pode enviar/baixar dados via SSH.", "Revise host e arquivos.", "Evite transferencia interativa no build."),
    _entry("pacman-key", "critical_system_change", "CRITICAL", r"\bpacman-key\b", "Gerencia chaves confiaveis do pacman.", "Pode alterar cadeia de confianca de pacotes do sistema.", "Revise chave, servidor e motivo.", "Nao altere chaveiro pacman em PKGBUILD/scriptlet sem justificativa extrema."),
    _entry("/etc/pacman.conf", "critical_system_change", "CRITICAL", r"/etc/pacman\.conf", "Referencia configuracao principal do pacman.", "Editar esse arquivo pode alterar repositorios e politica de instalacao.", "Revise qualquer escrita ou substituicao.", "Nao modifique pacman.conf automaticamente."),
    _entry("/etc/pacman.d/mirrorlist", "critical_system_change", "CRITICAL", r"/etc/pacman\.d/mirrorlist", "Referencia lista de mirrors do pacman.", "Editar mirrors pode redirecionar origem de pacotes.", "Revise qualquer escrita.", "Nao modifique mirrorlist automaticamente."),
    _entry("mkinitcpio", "critical_system_change", "CRITICAL", r"\bmkinitcpio\b", "Gera initramfs no Arch.", "Pode afetar boot do sistema.", "Revise hooks e arquivos alterados.", "Execute apenas em fluxo de pacote esperado e documentado."),
    _entry("dracut", "critical_system_change", "CRITICAL", r"\bdracut\b", "Gera initramfs.", "Pode afetar boot do sistema.", "Revise configuracao e destino.", "Evite chamadas inesperadas."),
    _entry("grub-install", "critical_system_change", "CRITICAL", r"\bgrub-install\b", "Instala bootloader GRUB.", "Pode alterar boot do sistema.", "Revise dispositivo alvo.", "Nao execute automaticamente em pacote AUR."),
    _entry("grub-mkconfig", "critical_system_change", "CRITICAL", r"\bgrub-mkconfig\b", "Gera configuracao do GRUB.", "Pode alterar menu e parametros de boot.", "Revise destino e entradas geradas.", "Evite alteracao automatica."),
    _entry("bootctl", "critical_system_change", "CRITICAL", r"\bbootctl\b", "Gerencia systemd-boot.", "Pode alterar bootloader/entradas de boot.", "Revise comando e destino.", "Nao execute automaticamente."),
    _entry("efibootmgr", "critical_system_change", "CRITICAL", r"\befibootmgr\b", "Edita entradas de boot EFI.", "Pode alterar ordem ou entradas de boot.", "Revise flags e entradas.", "Nao execute em build/scriptlet sem consentimento claro."),
    _entry("modprobe", "critical_system_change", "HIGH", r"\bmodprobe\b", "Carrega ou remove modulo do kernel.", "Pode alterar estado do kernel em tempo real.", "Revise modulo e parametros.", "Evite carregar modulos automaticamente."),
    _entry("insmod", "critical_system_change", "HIGH", r"\binsmod\b", "Insere modulo do kernel diretamente.", "Pode carregar codigo no kernel.", "Revise modulo e origem.", "Evite em pacote AUR sem justificativa extrema."),
    _entry("dkms", "critical_system_change", "HIGH", r"\bdkms\b", "Gerencia modulos de kernel via DKMS.", "Pode compilar/instalar modulos para kernels locais.", "Revise codigo do modulo e hooks.", "Use fluxo DKMS esperado e documentado."),
    _entry("rm -rf /", "data_destruction", "CRITICAL", r"\brm\s+-[A-Za-z]*r[A-Za-z]*f[A-Za-z]*\s+/", "Remove recursivamente arquivos a partir da raiz.", "Pode destruir o sistema se executado.", "Revise expansoes e protecoes.", "Nao aceite comandos destrutivos no pacote."),
    _entry("rm -rf \"$HOME\"", "data_destruction", "CRITICAL", r"\brm\s+-[A-Za-z]*r[A-Za-z]*f[A-Za-z]*\s+['\"]?\$HOME['\"]?", "Remove recursivamente o HOME do usuario.", "Pode destruir dados pessoais.", "Revise variaveis e alvo.", "Nao execute remocao recursiva de HOME."),
    _entry("find / -delete", "data_destruction", "CRITICAL", r"\bfind\s+/\s+[^;\n]*-delete", "Apaga arquivos encontrados a partir da raiz.", "Pode remover grandes partes do sistema.", "Revise caminho base e filtros.", "Nunca use find / -delete em build/install."),
    _entry("dd if=/dev/zero", "data_destruction", "CRITICAL", r"\bdd\s+if=/dev/zero\b", "Grava zeros em destino especificado pelo dd.", "Pode destruir disco/arquivo se o destino for sensivel.", "Revise of= e tamanho.", "Evite dd destrutivo em pacote."),
    _entry("mkfs", "data_destruction", "CRITICAL", r"\bmkfs(?:\.[A-Za-z0-9_-]+)?\b", "Cria sistema de arquivos, normalmente apagando conteudo do alvo.", "Pode destruir dados em dispositivo.", "Revise dispositivo alvo.", "Nao formate dispositivos em PKGBUILD/scriptlet."),
    _entry("wipefs", "data_destruction", "CRITICAL", r"\bwipefs\b", "Apaga assinaturas de filesystem/RAID/particao.", "Pode tornar dados indisponiveis.", "Revise dispositivo alvo.", "Nao use em pacote AUR."),
    _entry("shred", "data_destruction", "CRITICAL", r"\bshred\b", "Sobrescreve arquivos para dificultar recuperacao.", "Pode destruir dados de forma irreversivel.", "Revise arquivos alvo.", "Nao use shred em build/install."),
]


RULE_CATEGORY_HINTS = {
    "critical.remote-shell-pipe": "remote_execution",
    "critical.dynamic-execution": "dynamic_execution",
    "critical.destructive-command": "data_destruction",
    "critical.exfiltration": "network_exfiltration",
    "critical.persistence": "persistence",
    "critical.privilege-escalation": "privilege_escalation",
    "critical.sensitive-system-change": "critical_system_change",
    "critical.dangerous-permissions": "dangerous_permissions",
    "high.systemd-start-enable": "persistence",
    "high.account-or-cron-change": "account_change",
    "high.network-tooling": "network_exfiltration",
    "high.generated-code-or-remote-tool": "dependency_manager",
    "medium.download-outside-source": "remote_download",
    "medium.dependency-manager": "dependency_manager",
    "medium.skipped-or-weak-checksum": "checksum",
    "medium.install-directive": "install_scriptlet",
    "medium.install-file-present": "install_scriptlet",
    "high.package-writes-outside-pkgdir": "pkgdir_violation",
    "medium.pkgbuild-srcinfo-mismatch": "metadata",
    "low.no-maintainer": "metadata",
    "low.out-of-date": "metadata",
    "info.low-popularity": "metadata",
    "info.recently-modified": "metadata",
    "low.sensitive-dependency": "sensitive_dependency",
    "medium.git-sensitive-file-changed": "git",
    "high.git-new-install-scriptlet": "git",
    "AUR_RECENT_SENSITIVE_CHANGE": "recent_sensitive_change",
    "AUR_MALICIOUS_DEPENDENCY_PATTERN": "known_campaign_indicator",
    "AUR_MALICIOUS_DEPENDENCY_PATTERN_COMMENT": "known_campaign_indicator",
    "NODE_INSTALL_IN_INSTALL_SCRIPT": "dependency_manager",
    "NODE_INSTALL_IN_PKGBUILD": "dependency_manager",
    "INSTALL_SCRIPT_PERSISTENCE": "persistence",
    "DEPENDENCY_MANAGER_WITHOUT_LOCKFILE": "dependency_manager",
}


def category_for_rule(rule_id: str | None, default: str = "other") -> str:
    if not rule_id:
        return default
    if rule_id.startswith("info.comment."):
        rule_id = rule_id.removeprefix("info.comment.")
    return RULE_CATEGORY_HINTS.get(rule_id, default)


def explain_text(
    text: str,
    rule_id: str | None = None,
    fallback_severity: str = "INFO",
) -> CommandKnowledge:
    for item in COMMAND_KNOWLEDGE:
        if re.search(item.regex, text, flags=re.IGNORECASE):
            return item
    category = category_for_rule(rule_id, "other")
    return CommandKnowledge(
        command=None if category in {"metadata", "git", "file"} else DEFAULT_KNOWLEDGE.command,
        category=category,
        suggested_severity=fallback_severity,
        regex=DEFAULT_KNOWLEDGE.regex,
        description=DEFAULT_KNOWLEDGE.description,
        aur_risk=DEFAULT_KNOWLEDGE.aur_risk,
        review=DEFAULT_KNOWLEDGE.review,
        recommendation=DEFAULT_KNOWLEDGE.recommendation,
        safe_example=DEFAULT_KNOWLEDGE.safe_example,
    )
