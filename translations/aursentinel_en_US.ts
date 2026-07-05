<?xml version='1.0' encoding='utf-8'?>
<TS version="2.1" language="en_US">
    <context>
        <name>AurAuditRunner</name>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="387" />
            <source>Auditoria em andamento</source>
            <translation>Audit in progress</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="388" />
            <source>Coletando dados do pacote AUR.</source>
            <translation>Collecting AUR package data.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="393" />
            <source>Auditoria AUR</source>
            <translation>AUR audit</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="395" />
            <source>Pacote: {package}
</source>
            <translation>Package: {package}
</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="395" />
            <source>(vazio)</source>
            <translation>(empty)</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="397" />
            <source>Data/hora: {date_time}

</source>
            <translation>Date/time: {date_time}

</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="400" />
            <source>git ausente. Instale git para clonar o repositório AUR.</source>
            <translation>git is missing. Install git to clone the AUR repository.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="414" />
            <source>makepkg ausente. Instale base-devel/pacman para validar e compilar.</source>
            <translation>makepkg is missing. Install base-devel/pacman to validate and build.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="419" />
            <source>pacman ausente. Não foi possível inspecionar o pacote final.</source>
            <translation>pacman is missing. Could not inspect the final package.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="433" />
            <source>Auditoria cancelada pelo usuário.</source>
            <translation>Audit canceled by the user.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="437" />
            <source>Erro inesperado durante a auditoria: {error}</source>
            <translation>Unexpected error during audit: {error}</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="444" />
            <source>Auditoria cancelada pelo usuário. Encerrando processo em execução.</source>
            <translation>Audit canceled by the user. Stopping the running process.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="451" />
            <source>Clonando repositório AUR</source>
            <translation>Cloning AUR repository</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="457" />
            <source>Falha ao clonar o pacote AUR. Verifique o nome do pacote ou a rede.</source>
            <translation>Failed to clone the AUR package. Check the package name or network connection.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="461" />
            <source>Arquivos versionados</source>
            <translation>Versioned files</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="467" />
            <source>Falha ao listar arquivos versionados com git ls-files.</source>
            <translation>Failed to list versioned files with git ls-files.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="469" />
            <source>Arquivos analisados (git ls-files | sort):</source>
            <translation>Analyzed files (git ls-files | sort):</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="470" />
            <source>(nenhum)</source>
            <translation>(none)</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="474" />
            <source>Últimos commits</source>
            <translation>Latest commits</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="485" />
            <source>Falha ao coletar últimos commits.</source>
            <translation>Failed to collect latest commits.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="490" />
            <source>Diff do último commit</source>
            <translation>Latest commit diff</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="496" />
            <source>Falha ao coletar diff do último commit.</source>
            <translation>Failed to collect latest commit diff.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="503" />
            <source>PKGBUILD não encontrado no repositório clonado.</source>
            <translation>PKGBUILD was not found in the cloned repository.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="507" />
            <source>Falha ao ler PKGBUILD: {error}</source>
            <translation>Failed to read PKGBUILD: {error}</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="510" />
            <source>Campos principais do PKGBUILD</source>
            <translation>Main PKGBUILD fields</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="517" />
            <source>Padrões compatíveis com incidentes documentados</source>
            <translation>Patterns compatible with documented incidents</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="525" />
            <source>Falha ao executar git grep para padrões sensíveis.</source>
            <translation>Failed to run git grep for sensitive patterns.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="535" />
            <source>padrão sensível</source>
            <translation>sensitive pattern</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="539" />
            <source>Padrões encontrados</source>
            <translation>Matched patterns</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="544" />
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="992" />
            <source>Nenhum padrão compatível com incidentes AUR documentados foi encontrado.</source>
            <translation>No pattern compatible with documented AUR incidents was found.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="555" />
            <source>{file} (arquivo sensível: {glob})</source>
            <translation>{file} (sensitive file: {glob})</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="559" />
            <source>{file} (caminho contém {part})</source>
            <translation>{file} (path contains {part})</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="562" />
            <source>Arquivos sensíveis no repositório</source>
            <translation>Sensitive files in the repository</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="567" />
            <source>Nenhum arquivo sensível bloqueante foi encontrado nos arquivos versionados.</source>
            <translation>No blocking sensitive file was found in the versioned files.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="572" />
            <source>Validação de checksum e sources</source>
            <translation>Checksum and source validation</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="579" />
            <source>makepkg --verifysource falhou. A auditoria não foi concluída.</source>
            <translation>makepkg --verifysource failed. The audit was not completed.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="583" />
            <source>Build sem instalação do pacote final</source>
            <translation>Build without installing the final package</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="590" />
            <source>makepkg -sr falhou. Isso é erro operacional ou falha de build.</source>
            <translation>makepkg -sr failed. This is an operational error or build failure.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="601" />
            <source>Pacotes finais encontrados</source>
            <translation>Final packages found</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="603" />
            <source>Nenhum arquivo *.pkg.tar.zst final foi encontrado.</source>
            <translation>No final *.pkg.tar.zst file was found.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="604" />
            <source>Pacote final não encontrado após o build.</source>
            <translation>Final package not found after the build.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="611" />
            <source>Metadados do pacote final: {package}</source>
            <translation>Final package metadata: {package}</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="617" />
            <source>pacman -Qip falhou para {package}.</source>
            <translation>pacman -Qip failed for {package}.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="626" />
            <source>Arquivos que o pacote instalaria: {package}</source>
            <translation>Files the package would install: {package}</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="632" />
            <source>pacman -Qlp falhou para {package}.</source>
            <translation>pacman -Qlp failed for {package}.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="645" />
            <source>{package}: Install Script não é 'No' ({field})</source>
            <translation>{package}: Install Script is not 'No' ({field})</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="647" />
            <source>campo ausente</source>
            <translation>missing field</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="649" />
            <source>BLOQUEIO: {reason}</source>
            <translation>BLOCK: {reason}</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="652" />
            <source>Check de Install Script</source>
            <translation>Install Script check</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="653" />
            <source>(sem dados)</source>
            <translation>(no data)</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="655" />
            <source>Install Script no pacote final: {items}</source>
            <translation>Install Script in final package: {items}</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="668" />
            <source>{package}: {line} (contém {path})</source>
            <translation>{package}: {line} (contains {path})</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="675" />
            <source>BLOQUEIO:</source>
            <translation>BLOCK:</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="676" />
            <source>Caminhos sensíveis no pacote final: {items}</source>
            <translation>Sensitive paths in the final package: {items}</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="682" />
            <source>OK: nenhum caminho sensível bloqueante foi listado pelo pacman -Qlp.</source>
            <translation>OK: no blocking sensitive path was listed by pacman -Qlp.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="685" />
            <source>Check de caminhos sensíveis no pacote final</source>
            <translation>Sensitive path check in final package</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="694" />
            <source>bsdtar/tar ausente. Não foi possível extrair o pacote para checar permissões.</source>
            <translation>bsdtar/tar is missing. Could not extract the package to check permissions.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="707" />
            <source>Extraindo pacote para checar permissões: {package}</source>
            <translation>Extracting package to check permissions: {package}</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="715" />
            <source>Falha ao extrair {package} para inspeção de permissões.</source>
            <translation>Failed to extract {package} for permission inspection.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="723" />
            <source>OK: nenhum setuid/setgid encontrado.</source>
            <translation>OK: no setuid/setgid found.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="728" />
            <source>getcap ausente. Não foi possível checar Linux capabilities no pacote final.</source>
            <translation>getcap is missing. Could not check Linux capabilities in the final package.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="731" />
            <source>Checando Linux capabilities: {package}</source>
            <translation>Checking Linux capabilities: {package}</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="739" />
            <source>getcap falhou ao inspecionar {package}.</source>
            <translation>getcap failed while inspecting {package}.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="746" />
            <source>OK: nenhuma Linux capability encontrada por getcap.</source>
            <translation>OK: no Linux capability found by getcap.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="748" />
            <source>Check de setuid/setgid/capabilities</source>
            <translation>setuid/setgid/capabilities check</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="751" />
            <source>Permissões especiais no pacote final: {items}</source>
            <translation>Special permissions in the final package: {items}</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="763" />
            <source>Informe o nome do pacote AUR.</source>
            <translation>Enter the AUR package name.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="766" />
            <source>Nome de pacote inválido. Use apenas letras, números, @, ., _, + e -.</source>
            <translation>Invalid package name. Use only letters, numbers, @, ., _, +, and -.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="771" />
            <source>ERRO: não execute Aur Sentinel como root.</source>
            <translation>ERROR: do not run Aur Sentinel as root.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="787" />
            <source>O diretório {base} já existe. Para não sobrescrever, esta auditoria usará {work_dir}.
</source>
            <translation>The directory {base} already exists. To avoid overwriting it, this audit will use {work_dir}.
</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="791" />
            <source>Diretório de trabalho: {work_dir}
</source>
            <translation>Working directory: {work_dir}
</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="863" />
            <source>
Timeout em {title}; encerrando processo.
</source>
            <translation>
Timeout in {title}; stopping process.
</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="892" />
            <source>Timeout ao executar {command}.</source>
            <translation>Timeout while running {command}.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="895" />
            <source>Falha ao iniciar {program}: {error}</source>
            <translation>Failed to start {program}: {error}</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="899" />
            <source>
Comando terminou com código {returncode}.
</source>
            <translation>
Command exited with code {returncode}.
</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="983" />
            <source>padrões encontrados: {patterns}</source>
            <translation>matched patterns: {patterns}</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="985" />
            <source>arquivos sensíveis: {files}</source>
            <translation>sensitive files: {files}</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="986" />
            <source>Padrão bloqueante encontrado.</source>
            <translation>Blocking pattern found.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="990" />
            <source>OK — pode instalar</source>
            <translation>OK — can install</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="996" />
            <source>Isso não é uma auditoria completa do código upstream, mas o pacote passou pelo filtro contra os vetores AUR conhecidos.</source>
            <translation>This is not a full upstream code audit, but the package passed the filter for known AUR vectors.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="1000" />
            <source>Resultado: OK — pode instalar</source>
            <translation>Result: OK — can install</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="1006" />
            <source>INSEGURO — revisão manual necessária</source>
            <translation>UNSAFE — manual review required</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="1008" />
            <source>Foram encontrados padrões compatíveis com incidentes AUR documentados.</source>
            <translation>Patterns compatible with documented AUR incidents were found.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="1013" />
            <source>Resultado: INSEGURO — revisão manual necessária</source>
            <translation>Result: UNSAFE — manual review required</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="1020" />
            <source>Erro na auditoria</source>
            <translation>Audit error</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="1022" />
            <source>A auditoria não foi concluída por erro operacional, dependência ausente ou falha de build.</source>
            <translation>The audit was not completed due to an operational error, missing dependency, or build failure.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/audit/aur_audit_runner.py" line="1027" />
            <source>Resultado: Erro na auditoria</source>
            <translation>Result: Audit error</translation>
        </message>
    </context>
    <context>
        <name>HelpDialog</name>
        <message>
            <location filename="../aur_sentinel/ui/dialogs.py" line="19" />
            <source>Ajuda</source>
            <translation>Help</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/dialogs.py" line="24" />
            <source>Do que o Aur Sentinel protege?</source>
            <translation>What does Aur Sentinel protect against?</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/dialogs.py" line="25" />
            <source>Como ele verifica?</source>
            <translation>How does it check?</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/dialogs.py" line="30" />
            <source>Fechar</source>
            <translation>Close</translation>
        </message>
        <message>
            <source>2018: pacotes AUR com execução remota via curl | bash e download de scripts externos.</source>
            <translation>2018: AUR packages using remote execution through curl | bash and external script downloads.</translation>
        </message>
        <message>
            <source>2025: pacotes como librewolf-fix-bin, firefox-patch-bin e zen-browser-patched-bin, associados a script remoto/RAT.</source>
            <translation>2025: packages such as librewolf-fix-bin, firefox-patch-bin, and zen-browser-patched-bin associated with remote scripts/RAT behavior.</translation>
        </message>
        <message>
            <source>2026: campanhas com adoção maliciosa de pacotes órfãos e uso de npm, atomic-lockfile, lockfile-js e js-digest.</source>
            <translation>2026: campaigns involving malicious adoption of orphaned packages and use of npm, atomic-lockfile, lockfile-js, and js-digest.</translation>
        </message>
        <message>
            <source>2026: nova onda usando bun, execa, commander e padrões similares.</source>
            <translation>2026: another wave using bun, execa, commander, and similar patterns.</translation>
        </message>
        <message>
            <source>Amarelo/cinza significa erro operacional.</source>
            <translation>Yellow/gray means operational error.</translation>
        </message>
        <message>
            <source>Como o Aur Sentinel verifica?</source>
            <translation>How does Aur Sentinel check?</translation>
        </message>
        <message>
            <source>Ele também verifica .install, hooks e arquivos sensíveis, systemd, udev, polkit, sudoers, Install Script, caminhos sensíveis no pacote final, setuid/setgid e Linux capabilities.</source>
            <translation>It also checks .install files, hooks and sensitive files, systemd, udev, polkit, sudoers, Install Script, sensitive paths in the final package, setuid/setgid, and Linux capabilities.</translation>
        </message>
        <message>
            <source>Ele verifica vetores usados em incidentes conhecidos, como:</source>
            <translation>It checks vectors used in known incidents, such as:</translation>
        </message>
        <message>
            <source>O Aur Sentinel não substitui uma auditoria completa do código upstream, mas reduz o risco ao bloquear padrões compatíveis com os incidentes AUR conhecidos.</source>
            <translation>Aur Sentinel does not replace a full upstream code audit, but it reduces risk by blocking patterns compatible with known AUR incidents.</translation>
        </message>
        <message>
            <source>O Aur Sentinel protege contra padrões compatíveis com incidentes AUR já documentados.</source>
            <translation>Aur Sentinel protects against patterns compatible with documented AUR incidents.</translation>
        </message>
        <message>
            <source>O Aur Sentinel segue um fluxo fail-closed:</source>
            <translation>Aur Sentinel follows a fail-closed flow:</translation>
        </message>
        <message>
            <source>Verde significa que passou nos checks.</source>
            <translation>Green means the package passed the checks.</translation>
        </message>
        <message>
            <source>Vermelho significa que foram encontrados padrões compatíveis com incidentes conhecidos.</source>
            <translation>Red means patterns compatible with known incidents were found.</translation>
        </message>
        <message>
            <source>analisa o diff do último commit;</source>
            <translation>inspects the latest commit diff;</translation>
        </message>
        <message>
            <source>classifica o resultado como OK, INSEGURO ou Erro operacional.</source>
            <translation>classifies the result as OK, UNSAFE, or Operational error.</translation>
        </message>
        <message>
            <source>clona o repositório AUR do pacote na pasta Downloads;</source>
            <translation>clones the AUR package repository into Downloads;</translation>
        </message>
        <message>
            <source>coleta commits recentes;</source>
            <translation>collects recent commits;</translation>
        </message>
        <message>
            <source>compila sem instalar;</source>
            <translation>builds without installing;</translation>
        </message>
        <message>
            <source>inspeciona o pacote final;</source>
            <translation>inspects the final package;</translation>
        </message>
        <message>
            <source>lista os arquivos versionados;</source>
            <translation>lists versioned files;</translation>
        </message>
        <message>
            <source>procura padrões compatíveis com incidentes documentados;</source>
            <translation>searches for patterns compatible with documented incidents;</translation>
        </message>
        <message>
            <source>se encontrar algo sensível, bloqueia antes do makepkg;</source>
            <translation>if it finds a sensitive pattern, it blocks before makepkg;</translation>
        </message>
        <message>
            <source>se não encontrar, valida fontes e checksums;</source>
            <translation>if not, it validates sources and checksums;</translation>
        </message>
        <message>
            <source>verifica Install Script, caminhos sensíveis, setuid/setgid e capabilities;</source>
            <translation>checks Install Script, sensitive paths, setuid/setgid, and capabilities;</translation>
        </message>
        <message>
            <source>verifica arquivos sensíveis;</source>
            <translation>checks sensitive files;</translation>
        </message>
    </context>
    <context>
        <name>MainWindow</name>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="227" />
            <location filename="../aur_sentinel/ui/main_window.py" line="236" />
            <location filename="../aur_sentinel/ui/main_window.py" line="271" />
            <location filename="../aur_sentinel/ui/main_window.py" line="321" />
            <location filename="../aur_sentinel/ui/main_window.py" line="370" />
            <location filename="../aur_sentinel/ui/main_window.py" line="383" />
            <location filename="../aur_sentinel/ui/main_window.py" line="456" />
            <source>Aur Sentinel</source>
            <translation>Aur Sentinel</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="228" />
            <source>Ações</source>
            <translation>Actions</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="229" />
            <source>Abrir Downloads</source>
            <translation>Open Downloads</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="230" />
            <source>Idioma</source>
            <translation>Language</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="231" />
            <source>Ajuda</source>
            <translation>Help</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="232" />
            <source>Do que o Aur Sentinel protege?</source>
            <translation>What does Aur Sentinel protect against?</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="233" />
            <source>Como ele verifica?</source>
            <translation>How does it check?</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="234" />
            <location filename="../aur_sentinel/ui/main_window.py" line="244" />
            <source>Copiar para IA</source>
            <translation>Copy for AI</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="235" />
            <source>Instalar</source>
            <translation>Install</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="238" />
            <source>Auditoria AUR antes do makepkg, focada em padrões de incidentes documentados.</source>
            <translation>AUR audit before makepkg, focused on documented incident patterns.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="240" />
            <source>Auditar</source>
            <translation>Audit</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="241" />
            <source>Cancelar</source>
            <translation>Cancel</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="242" />
            <source>Por quê?</source>
            <translation>Why?</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="243" />
            <source>Log técnico</source>
            <translation>Technical log</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="250" />
            <location filename="../aur_sentinel/ui/main_window.py" line="524" />
            <source>Pronto para auditar</source>
            <translation>Ready to audit</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="257" />
            <source>O idioma foi alterado.</source>
            <translation>Language changed.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="272" />
            <source>Não foi possível abrir o diretório:
{path}</source>
            <translation>Could not open the directory:
{path}</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="314" />
            <source>Auditoria em andamento.</source>
            <translation>Audit in progress.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="322" />
            <source>Busque um pacote AUR e selecione um resultado antes de auditar.</source>
            <translation>Search for an AUR package and select a result before auditing.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="324" />
            <source>Selecione um pacote para auditar.</source>
            <translation>Select a package to audit.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="332" />
            <location filename="../aur_sentinel/ui/main_window.py" line="525" />
            <source>Auditoria em andamento</source>
            <translation>Audit in progress</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="333" />
            <location filename="../aur_sentinel/ui/main_window.py" line="535" />
            <source>Coletando dados do pacote AUR.</source>
            <translation>Collecting AUR package data.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="337" />
            <source>Auditando {package}...</source>
            <translation>Auditing {package}...</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="361" />
            <source>Cancelando auditoria...</source>
            <translation>Canceling audit...</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="371" />
            <source>Nenhum relatório de auditoria disponível para copiar.</source>
            <translation>No audit report is available to copy.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="375" />
            <source>Relatório Markdown copiado para a área de transferência.</source>
            <translation>Markdown report copied to the clipboard.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="384" />
            <source>A instalação só é liberada quando a auditoria atual terminou em OK para o pacote selecionado.</source>
            <translation>Installation is only enabled when the current audit finished as OK for the selected package.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="391" />
            <source>Instalar pacote auditado?</source>
            <translation>Install audited package?</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="394" />
            <source>O pacote foi auditado e classificado como OK. Deseja instalar os arquivos gerados nesta auditoria?</source>
            <translation>The package was audited and classified as OK. Do you want to install the files generated by this audit?</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="408" />
            <location filename="../aur_sentinel/ui/main_window.py" line="432" />
            <location filename="../aur_sentinel/ui/main_window.py" line="461" />
            <location filename="../aur_sentinel/ui/main_window.py" line="475" />
            <source>Erro na instalação</source>
            <translation>Installation error</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="409" />
            <source>Não encontrei pkexec, kdesu ou kdesudo para executar pacman com privilégio.</source>
            <translation>Could not find pkexec, kdesu, or kdesudo to run pacman with privileges.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="413" />
            <source>Instalação do pacote auditado</source>
            <translation>Audited package installation</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="428" />
            <source>Falha ao iniciar o processo de instalação.</source>
            <translation>Failed to start the installation process.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="455" />
            <location filename="../aur_sentinel/ui/main_window.py" line="456" />
            <source>Instalação concluída.</source>
            <translation>Installation completed.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="458" />
            <source>Erro operacional durante instalação.</source>
            <translation>Operational error during installation.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="462" />
            <source>A instalação falhou. Veja o log técnico para os detalhes.</source>
            <translation>Installation failed. See the technical log for details.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="509" />
            <source>Padrões: {patterns}</source>
            <translation>Patterns: {patterns}</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="511" />
            <source>Arquivos: {files}</source>
            <translation>Files: {files}</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="518" />
            <source>Selecionado: {package}</source>
            <translation>Selected: {package}</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="520" />
            <source>Nenhum pacote selecionado.</source>
            <translation>No package selected.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="526" />
            <source>OK — pode instalar</source>
            <translation>OK — can install</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="527" />
            <source>INSEGURO — revisão manual necessária</source>
            <translation>UNSAFE — manual review required</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="528" />
            <source>Erro na auditoria</source>
            <translation>Audit error</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="534" />
            <source>Busque um pacote AUR, selecione-o na lista e clique em Auditar.</source>
            <translation>Search for an AUR package, select it from the list, and click Audit.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="537" />
            <source>Nenhum padrão compatível com incidentes AUR documentados foi encontrado.</source>
            <translation>No pattern compatible with documented AUR incidents was found.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="540" />
            <source>Foram encontrados padrões compatíveis com incidentes AUR documentados.</source>
            <translation>Patterns compatible with documented AUR incidents were found.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="543" />
            <source>A auditoria não foi concluída por erro operacional, dependência ausente ou falha de build.</source>
            <translation>The audit was not completed due to an operational error, missing dependency, or build failure.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/main_window.py" line="624" />
            <source>Instalando pacote auditado...</source>
            <translation>Installing audited package...</translation>
        </message>
    </context>
    <context>
        <name>PackageSearchWidget</name>
        <message>
            <location filename="../aur_sentinel/ui/package_search.py" line="160" />
            <source>Buscar pacote AUR</source>
            <translation>Search AUR package</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/package_search.py" line="161" />
            <source>Nome do pacote AUR</source>
            <translation>AUR package name</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/package_search.py" line="162" />
            <source>Buscar</source>
            <translation>Search</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/package_search.py" line="164" />
            <source>Informações do pacote</source>
            <translation>Package information</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/package_search.py" line="166" />
            <source>AUR é mantido pela comunidade. O Aur Sentinel audita antes de compilar e não usa helper AUR.</source>
            <translation>AUR is maintained by the community. Aur Sentinel audits before building and does not use an AUR helper.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/package_search.py" line="173" />
            <source>Nome</source>
            <translation>Name</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/package_search.py" line="174" />
            <location filename="../aur_sentinel/ui/package_search.py" line="370" />
            <source>Versão</source>
            <translation>Version</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/package_search.py" line="175" />
            <source>Descrição</source>
            <translation>Description</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/package_search.py" line="176" />
            <location filename="../aur_sentinel/ui/package_search.py" line="371" />
            <source>Mantenedor</source>
            <translation>Maintainer</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/package_search.py" line="177" />
            <location filename="../aur_sentinel/ui/package_search.py" line="375" />
            <source>Votos</source>
            <translation>Votes</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/package_search.py" line="178" />
            <location filename="../aur_sentinel/ui/package_search.py" line="376" />
            <source>Popularidade</source>
            <translation>Popularity</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/package_search.py" line="184" />
            <location filename="../aur_sentinel/ui/package_search.py" line="305" />
            <source>Pacote selecionado: {package}</source>
            <translation>Package selected: {package}</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/package_search.py" line="186" />
            <location filename="../aur_sentinel/ui/package_search.py" line="196" />
            <location filename="../aur_sentinel/ui/package_search.py" line="222" />
            <location filename="../aur_sentinel/ui/package_search.py" line="232" />
            <source>Digite pelo menos 2 caracteres para consultar a AUR.</source>
            <translation>Type at least 2 characters to query the AUR.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/package_search.py" line="202" />
            <source>Informe um termo de busca.</source>
            <translation>Enter a search term.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/package_search.py" line="235" />
            <source>Busca em andamento; aguarde.</source>
            <translation>Search in progress; please wait.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/package_search.py" line="238" />
            <source>Buscando '{query}' na AUR...</source>
            <translation>Searching '{query}' in the AUR...</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/package_search.py" line="265" />
            <location filename="../aur_sentinel/ui/package_search.py" line="371" />
            <source>(sem mantenedor)</source>
            <translation>(no maintainer)</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/package_search.py" line="277" />
            <source>{count} resultado(s) encontrados. Selecione um pacote para auditar.</source>
            <translation>{count} result(s) found. Select a package to audit.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/package_search.py" line="340" />
            <source>Pacote selecionado, mas os detalhes completos não foram carregados: {error}</source>
            <translation>Package selected, but full details were not loaded: {error}</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/package_search.py" line="359" />
            <source>Selecione um resultado para ver versão, mantenedor, URL, licença e link AUR.</source>
            <translation>Select a result to see version, maintainer, URL, license, and AUR link.</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/package_search.py" line="373" />
            <source>Licença</source>
            <translation>License</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/package_search.py" line="374" />
            <source>Última modificação</source>
            <translation>Last modified</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/package_search.py" line="377" />
            <source>Link AUR</source>
            <translation>AUR link</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/package_search.py" line="377" />
            <source>Abrir página AUR</source>
            <translation>Open AUR page</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/package_search.py" line="383" />
            <location filename="../aur_sentinel/ui/package_search.py" line="395" />
            <location filename="../aur_sentinel/ui/package_search.py" line="401" />
            <location filename="../aur_sentinel/ui/package_search.py" line="403" />
            <location filename="../aur_sentinel/ui/package_search.py" line="404" />
            <source>Não disponível</source>
            <translation>Not available</translation>
        </message>
    </context>
    <context>
        <name>WhyDialog</name>
        <message>
            <location filename="../aur_sentinel/ui/dialogs.py" line="46" />
            <source>Por quê?</source>
            <translation>Why?</translation>
        </message>
        <message>
            <location filename="../aur_sentinel/ui/dialogs.py" line="56" />
            <source>Fechar</source>
            <translation>Close</translation>
        </message>
        <message>
            <source>A auditoria não foi concluída por erro operacional, dependência ausente ou falha de build. Isso não classifica o pacote como seguro nem inseguro.</source>
            <translation>The audit was not completed due to an operational error, missing dependency, or build failure. This does not classify the package as safe or unsafe.</translation>
        </message>
        <message>
            <source>Arquivos ou diretivas .install rodam durante instalação/upgrade e precisam de revisão manual.</source>
            <translation>.install files or directives run during installation/upgrade and need manual review.</translation>
        </message>
        <message>
            <source>Arquivos sensíveis encontrados</source>
            <translation>Sensitive files found</translation>
        </message>
        <message>
            <source>Busque um pacote AUR, selecione-o na lista e clique em Auditar.</source>
            <translation>Search for an AUR package, select it from the list, and click Audit.</translation>
        </message>
        <message>
            <source>Corrija a dependência, rede ou falha indicada no log técnico e execute a auditoria novamente.</source>
            <translation>Fix the dependency, network issue, or failure shown in the technical log and run the audit again.</translation>
        </message>
        <message>
            <source>Detalhes:</source>
            <translation>Details:</translation>
        </message>
        <message>
            <source>Erro na auditoria</source>
            <translation>Audit error</translation>
        </message>
        <message>
            <source>Esse padrão pode alterar persistência, permissões ou integração privilegiada do sistema.</source>
            <translation>This pattern can change persistence, permissions, or privileged system integration.</translation>
        </message>
        <message>
            <source>Esse padrão é sensível no contexto de PKGBUILD porque pode alterar o fluxo de build/install.</source>
            <translation>This pattern is sensitive in the PKGBUILD context because it can change the build/install flow.</translation>
        </message>
        <message>
            <source>Esse padrão é sensível porque pode baixar ou executar dependências JavaScript durante build/install.</source>
            <translation>This pattern is sensitive because it can download or execute JavaScript dependencies during build/install.</translation>
        </message>
        <message>
            <source>Esse padrão é sensível porque pode baixar ou executar scripts remotos antes de uma revisão local.</source>
            <translation>This pattern is sensitive because it can download or execute remote scripts before local review.</translation>
        </message>
        <message>
            <source>Esse tipo de comando foi usado em incidentes AUR documentados em 2026, como as campanhas envolvendo atomic-lockfile, js-digest e lockfile-js.</source>
            <translation>This type of command was used in documented AUR incidents in 2026, such as the campaigns involving atomic-lockfile, js-digest, and lockfile-js.</translation>
        </message>
        <message>
            <source>Foi encontrado o padrão {pattern} no arquivo {file}, linha {line}. Trecho: {snippet}. {reason}</source>
            <translation>The pattern {pattern} was found in file {file}, line {line}. Snippet: {snippet}. {reason}</translation>
        </message>
        <message>
            <source>INSEGURO — revisão manual necessária</source>
            <translation>UNSAFE — manual review required</translation>
        </message>
        <message>
            <source>Isso não substitui uma revisão completa do código upstream, mas responde à pergunta principal: nenhum sinal compatível com os incidentes AUR conhecidos foi encontrado nesta auditoria.</source>
            <translation>This does not replace a full upstream code review, but it answers the main question: no sign compatible with known AUR incidents was found in this audit.</translation>
        </message>
        <message>
            <source>Motivo:</source>
            <translation>Reason:</translation>
        </message>
        <message>
            <source>Não disponível</source>
            <translation>Not available</translation>
        </message>
        <message>
            <source>O bloqueio veio de um check posterior, como Install Script, paths sensíveis ou permissões especiais no pacote final.</source>
            <translation>The block came from a later check, such as Install Script, sensitive paths, or special permissions in the final package.</translation>
        </message>
        <message>
            <source>OK — pode instalar</source>
            <translation>OK — can install</translation>
        </message>
        <message>
            <source>PKGBUILD analisado;</source>
            <translation>PKGBUILD analyzed;</translation>
        </message>
        <message>
            <source>Padrões encontrados</source>
            <translation>Matched patterns</translation>
        </message>
        <message>
            <source>Pronto para auditar</source>
            <translation>Ready to audit</translation>
        </message>
        <message>
            <source>Você não deve instalar este pacote sem revisão manual porque o Aur Sentinel encontrou padrões compatíveis com incidentes AUR documentados. Foi detectado uso de comandos ou arquivos sensíveis, como npm, bun, .install, scripts remotos ou outros vetores já vistos em campanhas maliciosas. Recomendo usar o botão Copiar para IA para uma análise mais avançada.</source>
            <translation>You should not install this package without manual review because Aur Sentinel found patterns compatible with documented AUR incidents. Use of sensitive commands or files was detected, such as npm, bun, .install, remote scripts, or other vectors already seen in malicious campaigns. Use the Copy for AI button for a deeper analysis.</translation>
        </message>
        <message>
            <source>Você pode instalar porque o Aur Sentinel verificou os arquivos versionados do AUR, analisou o histórico recente do pacote, inspecionou o diff mais recente, bloqueou padrões compatíveis com incidentes conhecidos, validou as fontes, compilou sem instalar, analisou os metadados do pacote final e verificou que não há Install Script, caminhos sensíveis, setuid/setgid ou capabilities.</source>
            <translation>You can install because Aur Sentinel checked the versioned AUR files, analyzed the recent package history, inspected the latest diff, blocked patterns compatible with known incidents, validated sources, built without installing, analyzed the final package metadata, and verified that there is no Install Script, sensitive paths, setuid/setgid, or capabilities.</translation>
        </message>
        <message>
            <source>arquivos sensíveis não encontrados;</source>
            <translation>sensitive files not found;</translation>
        </message>
        <message>
            <source>build executado sem instalar;</source>
            <translation>build run without installing;</translation>
        </message>
        <message>
            <source>diff do último commit analisado;</source>
            <translation>latest commit diff analyzed;</translation>
        </message>
        <message>
            <source>fontes verificadas;</source>
            <translation>sources verified;</translation>
        </message>
        <message>
            <source>nenhum arquivo listado</source>
            <translation>no file listed</translation>
        </message>
        <message>
            <source>nenhum path sensível;</source>
            <translation>no sensitive path;</translation>
        </message>
        <message>
            <source>nenhum setuid/setgid;</source>
            <translation>no setuid/setgid;</translation>
        </message>
        <message>
            <source>nenhuma Linux capability.</source>
            <translation>no Linux capability.</translation>
        </message>
        <message>
            <source>pacote final encontrado: {packages};</source>
            <translation>final package found: {packages};</translation>
        </message>
        <message>
            <source>padrões sensíveis não encontrados;</source>
            <translation>sensitive patterns not found;</translation>
        </message>
        <message>
            <source>últimos commits analisados;</source>
            <translation>latest commits analyzed;</translation>
        </message>
    </context>
    <context>
        <name>AiReport</name>
        <message>
            <source>(não criado)</source>
            <translation>(not created)</translation>
        </message>
        <message>
            <source>(não executado)</source>
            <translation>(not run)</translation>
        </message>
        <message>
            <source>Analise este relatório AUR. Verifique se o pacote apresenta sinais compatíveis com incidentes AUR conhecidos, scripts remotos, hooks perigosos, persistência, caminhos sensíveis, permissões especiais ou necessidade de revisão manual.</source>
            <translation>Analyze this AUR report. Check whether the package shows signs compatible with known AUR incidents, remote scripts, dangerous hooks, persistence, sensitive paths, special permissions, or need for manual review.</translation>
        </message>
        <message>
            <source>Arquivos instalados pelo pacote</source>
            <translation>Files installed by the package</translation>
        </message>
        <message>
            <source>Arquivos sensíveis encontrados</source>
            <translation>Sensitive files found</translation>
        </message>
        <message>
            <source>Build sem instalar</source>
            <translation>Build without installing</translation>
        </message>
        <message>
            <source>Caminhos sensíveis</source>
            <translation>Sensitive paths</translation>
        </message>
        <message>
            <source>Checks finais</source>
            <translation>Final checks</translation>
        </message>
        <message>
            <source>Conclusão</source>
            <translation>Conclusion</translation>
        </message>
        <message>
            <source>Data/hora</source>
            <translation>Date/time</translation>
        </message>
        <message>
            <source>Descrição</source>
            <translation>Description</translation>
        </message>
        <message>
            <source>Diff do último commit</source>
            <translation>Latest commit diff</translation>
        </message>
        <message>
            <source>Diretório de trabalho</source>
            <translation>Working directory</translation>
        </message>
        <message>
            <source>EM ANDAMENTO</source>
            <translation>RUNNING</translation>
        </message>
        <message>
            <source>ERRO OPERACIONAL</source>
            <translation>OPERATIONAL ERROR</translation>
        </message>
        <message>
            <source>Histórico recente</source>
            <translation>Recent history</translation>
        </message>
        <message>
            <source>INSEGURO</source>
            <translation>UNSAFE</translation>
        </message>
        <message>
            <source>Licença</source>
            <translation>License</translation>
        </message>
        <message>
            <source>Link AUR</source>
            <translation>AUR link</translation>
        </message>
        <message>
            <source>Mantenedor</source>
            <translation>Maintainer</translation>
        </message>
        <message>
            <source>Metadados do pacote final</source>
            <translation>Final package metadata</translation>
        </message>
        <message>
            <source>Motivo</source>
            <translation>Reason</translation>
        </message>
        <message>
            <source>Nenhum.</source>
            <translation>None.</translation>
        </message>
        <message>
            <source>Nome</source>
            <translation>Name</translation>
        </message>
        <message>
            <source>NÃO INICIADO</source>
            <translation>NOT STARTED</translation>
        </message>
        <message>
            <source>Não disponível</source>
            <translation>Not available</translation>
        </message>
        <message>
            <source>OK</source>
            <translation>OK</translation>
        </message>
        <message>
            <source>Pacote</source>
            <translation>Package</translation>
        </message>
        <message>
            <source>Padrões encontrados</source>
            <translation>Matched patterns</translation>
        </message>
        <message>
            <source>Popularidade</source>
            <translation>Popularity</translation>
        </message>
        <message>
            <source>Primeiro envio</source>
            <translation>First submitted</translation>
        </message>
        <message>
            <source>Relatório de auditoria AUR</source>
            <translation>AUR audit report</translation>
        </message>
        <message>
            <source>Resumo do PKGBUILD</source>
            <translation>PKGBUILD summary</translation>
        </message>
        <message>
            <source>Status final</source>
            <translation>Final status</translation>
        </message>
        <message>
            <source>Validação de fontes</source>
            <translation>Source validation</translation>
        </message>
        <message>
            <source>Versão</source>
            <translation>Version</translation>
        </message>
        <message>
            <source>Votos</source>
            <translation>Votes</translation>
        </message>
        <message>
            <source>clone OK; arquivos versionados, commits e diff coletados; nenhum padrão sensível encontrado; makepkg --verifysource OK; makepkg -sr OK; pacote final inspecionado sem Install Script, paths sensíveis, setuid/setgid ou capabilities.</source>
            <translation>clone OK; versioned files, commits, and diff collected; no sensitive pattern found; makepkg --verifysource OK; makepkg -sr OK; final package inspected with no Install Script, sensitive paths, setuid/setgid, or capabilities.</translation>
        </message>
        <message>
            <source>Última modificação</source>
            <translation>Last modified</translation>
        </message>
    </context>
</TS>