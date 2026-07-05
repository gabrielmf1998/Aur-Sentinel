from __future__ import annotations

from .models import Rule


STATIC_RULES: list[Rule] = [
    Rule(
        id="critical.remote-shell-pipe",
        name="Execucao remota direta",
        severity="CRITICAL",
        regex=(
            r"\bcurl\s+.*\|\s*(?:bash|sh)\b|"
            r"\bwget\s+.*\|\s*(?:bash|sh)\b|"
            r"\bbash\s+<\(\s*curl\b|"
            r"\bsh\s+<\(\s*wget\b|"
            r"\beval\s+.*(?:curl|wget)\b"
        ),
        description="Baixa conteudo remoto e executa diretamente em um shell.",
        recommendation="Baixe o arquivo, revise seu conteudo e valide assinatura/hash antes de executar.",
    ),
    Rule(
        id="critical.dynamic-execution",
        name="Obfuscacao ou execucao dinamica",
        severity="CRITICAL",
        regex=(
            r"\bbase64\s+-d.*\|\s*(?:bash|sh)\b|"
            r"\bxxd\s+-r.*\|\s*(?:bash|sh)\b|"
            r"\bopenssl\s+enc.*\|\s*(?:bash|sh)\b|"
            r"\beval\b|\bbash\s+-c\b|\bsh\s+-c\b|\bpython\s+-c\b|"
            r"\bperl\s+-e\b|\bruby\s+-e\b|\bnode\s+-e\b"
        ),
        description="Uso de execucao dinamica, decodificacao ou descriptografia durante scripts de build/install.",
        recommendation="Revise manualmente o comando e confirme que nao executa payload oculto.",
    ),
    Rule(
        id="critical.destructive-command",
        name="Comando destrutivo",
        severity="CRITICAL",
        regex=(
            r"\b(?:rm\s+-[A-Za-z]*r[A-Za-z]*f[A-Za-z]*\s+(?:/|['\"]?\$HOME['\"]?|~/\.config|/etc\b|/usr\b)|"
            r"find\s+/\s+[^;\n]*-delete|dd\s+if=/dev/zero|mkfs(?:\.[A-Za-z0-9_-]+)?\b|wipefs\b|shred\b)"
        ),
        description="Padrao capaz de apagar dados ou destruir sistemas de arquivos.",
        recommendation="Nao prossiga sem entender exatamente o escopo do comando.",
    ),
    Rule(
        id="critical.exfiltration",
        name="Possivel exfiltracao de dados",
        severity="CRITICAL",
        regex=(
            r"(?:\b(?:curl\s+(?:-F|--data|-d)|wget\s+--post-data)\b[^;\n]*"
            r"(?:\$HOME|~/\.ssh|\.gnupg|\.aws|\.kube|\.config|token|secret|password|private key)|"
            r"(?:\$HOME|~/\.ssh|\.gnupg|\.aws|\.kube|\.config|token|secret|password|private key)"
            r"[^;\n]*\b(?:curl\s+(?:-F|--data|-d)|wget\s+--post-data)\b)"
        ),
        description="Upload HTTP combinado com locais ou termos associados a credenciais.",
        recommendation="Verifique se o pacote nao envia arquivos locais, chaves, tokens ou configuracoes privadas.",
    ),
    Rule(
        id="critical.persistence",
        name="Persistencia suspeita",
        severity="CRITICAL",
        regex=(
            r"\bsystemctl\s+enable\b|\bsystemctl\s+start\b|\bsystemctl\s+enable\s+--now\b|"
            r"\bcrontab\b|\.config/systemd/user|/etc/systemd/system|/etc/cron|xdg/autostart|"
            r">>\s*.*\.bashrc|>>\s*.*\.zshrc|>>\s*.*\.profile|>>\s*.*config\.fish|"
            r"tee\s+.*\.bashrc|tee\s+.*\.zshrc|sed\s+-i\s+.*\.bashrc|sed\s+-i\s+.*\.zshrc|"
            r"echo\s+.*>\s*.*\.bashrc|echo\s+.*>\s*.*\.zshrc"
        ),
        description="Tentativa de persistir execucao via shell rc, autostart, cron ou systemd.",
        recommendation="Revise se a persistencia e esperada e se ocorre apenas em scriptlet documentado.",
    ),
    Rule(
        id="critical.privilege-escalation",
        name="Escalacao de privilegio",
        severity="CRITICAL",
        regex=r"\b(?:sudo|su|doas|pkexec)\b",
        description="Uso explicito de mecanismo de elevacao de privilegio dentro do pacote.",
        recommendation="Pacotes AUR nao devem invocar elevacao diretamente durante build ou auditoria.",
    ),
    Rule(
        id="critical.sensitive-system-change",
        name="Alteracao sensivel do sistema",
        severity="CRITICAL",
        regex=(
            r"\bpacman-key\b|/etc/pacman\.conf|/etc/pacman\.d/mirrorlist|\bmkinitcpio\b|"
            r"\bdracut\b|\bgrub-install\b|\bgrub-mkconfig\b|\bbootctl\b|\befibootmgr\b|"
            r"\bmodprobe\b|\binsmod\b|\bdkms\b|/etc/ld\.so\.preload|\bLD_PRELOAD\b"
        ),
        description="Comando ou arquivo associado a boot, chaves do pacman ou configuracao critica.",
        recommendation="Confirme manualmente se essa alteracao e legitima e necessaria.",
    ),
    Rule(
        id="critical.dangerous-permissions",
        name="Permissoes perigosas",
        severity="CRITICAL",
        regex=r"\bchmod\s+(?:4755|u\+s)\b|\bsetcap\b|\bchown\s+root\b",
        description="Permissoes privilegiadas, capabilities ou propriedade root podem criar superficie de ataque.",
        recommendation="Revise o binario/arquivo alvo e justifique qualquer SUID/capability.",
    ),
    Rule(
        id="high.systemd-start-enable",
        name="Ativacao de servico systemd",
        severity="HIGH",
        regex=r"\bsystemctl\s+(?:enable|start)\b",
        description="Habilita ou inicia servicos durante scripts do pacote.",
        recommendation="Servicos devem ser documentados e normalmente ativados pelo usuario, nao pelo build.",
    ),
    Rule(
        id="high.account-or-cron-change",
        name="Alteracao de usuarios, grupos ou cron",
        severity="HIGH",
        regex=r"\b(?:crontab|useradd|usermod|groupadd|passwd|chpasswd)\b",
        description="Modifica contas locais, senhas, grupos ou cron.",
        recommendation="Revise o scriptlet e prefira instrucoes manuais quando possivel.",
    ),
    Rule(
        id="high.network-tooling",
        name="Ferramenta de rede sensivel",
        severity="INFO",
        regex=r"\b(?:nc|ncat|socat|scp|rsync|ftp|sftp)\b|/dev/tcp",
        description="Uso de ferramenta capaz de transferir dados ou abrir conexoes arbitrarias.",
        recommendation="Valide destino, argumentos e necessidade operacional.",
    ),
    Rule(
        id="high.generated-code-or-remote-tool",
        name="Execucao de ferramenta remota/dinamica",
        severity="INFO",
        regex=(
            r"\bgo\s+generate\b|\bnpx\b|\bpnpm\s+dlx\b|\byarn\s+dlx\b|\bbunx\b|"
            r"\bnpm\s+install\s+-g\b|\bpip\s+install\s+(?:git\+https://|https://)|"
            r"\bcargo\s+install(?:\s+--git)?\b|\bgo\s+install\b|"
            r"\bcomposer\s+update\b|\bmvn\s+dependency:get\b|(?:^|\s)\./gradlew\b"
        ),
        description="Executa geradores, wrappers ou instaladores que podem buscar codigo dinamico.",
        recommendation="Revise lockfiles, scripts e origens antes de permitir a execucao.",
    ),
    Rule(
        id="medium.download-outside-source",
        name="Download fora de source()",
        severity="INFO",
        regex=r"\b(?:curl|wget|aria2c|git\s+clone)\b",
        description="Download manual detectado fora da declaracao source=().",
        recommendation="Prefira source=() com checksums fortes quando possivel.",
    ),
    Rule(
        id="medium.dependency-manager",
        name="Gerenciador de dependencias em funcao de build",
        severity="INFO",
        regex=(
            r"\b(?:npm\s+install|npm\s+ci|yarn\s+install|pnpm\s+install|bun\s+install|"
            r"python(?:3)?\s+-m\s+pip\s+install|pip\s+install|poetry\s+install|pipenv\s+install|"
            r"cargo\s+install|go\s+install\s+.*@latest|gem\s+install|bundle\s+install|"
            r"composer\s+install|mvn\s+install|gradle\s+build|dotnet\s+restore|nuget\s+restore)\b"
        ),
        description="Gerenciador de dependencias pode buscar codigo durante prepare/build/check/package.",
        recommendation="Revise lockfiles, checksums e scripts de ciclo de vida.",
    ),
    Rule(
        id="medium.skipped-or-weak-checksum",
        name="Checksum fraco ou ignorado",
        severity="INFO",
        regex=r"\b(?:sha256sums|b2sums)\s*=\s*\([^)]*['\"]?SKIP['\"]?|\b(?:md5sums|sha1sums)\s*=",
        description="Checksum SKIP ou algoritmo fraco reduz verificabilidade das fontes.",
        recommendation="Prefira sha256/sha512/b2 com valores reais e verificados.",
        file_kinds=("PKGBUILD", "AUX"),
    ),
    Rule(
        id="medium.install-directive",
        name="Scriptlet de instalacao declarado",
        severity="MEDIUM",
        regex=r"^\s*install\s*=\s*[^#\s]+\.install\b",
        description="PKGBUILD declara scriptlet executado pelo gerenciador de pacotes.",
        recommendation="Revise o arquivo .install, pois ele roda em eventos de instalacao/upgrade/remocao.",
        file_kinds=("PKGBUILD",),
    ),
]


SENSITIVE_DEPENDENCIES = {
    "openssh",
    "netcat",
    "nmap",
    "socat",
    "xclip",
    "wl-clipboard",
    "keyutils",
    "gnupg",
    "pass",
}

NPM_LIFECYCLE_SCRIPTS = {
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "build",
    "test",
    "start",
}

DANGEROUS_NPM_SCRIPT_RE = (
    r"\b(?:curl|wget|bash|sh|python|base64|eval)\b|node\s+install\.js"
)
