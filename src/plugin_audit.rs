use crate::config::PolicyConfig;
use crate::discovery::shorten_home;
use crate::mcp_audit::McpFinding;
use crate::rules::{fingerprint_match, RuleCategory, RuleEngine, Severity};
use base64::Engine;
use regex::Regex;
use serde_json::Value;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

const MAX_PLUGIN_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_JSON_CONFIG_BYTES: u64 = 16 * 1024 * 1024;
const MAX_STREAM_PLUGIN_BYTES: u64 = 64 * 1024 * 1024;
const STREAM_CHUNK_BYTES: usize = 256 * 1024;
const STREAM_OVERLAP_BYTES: usize = 2048;

const HOOK_EVENTS: &[&str] = &[
    "SessionStart",
    "SessionEnd",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "PermissionRequest",
    "Notification",
    "SubagentStart",
    "SubagentStop",
    "PreInvocation",
    "PostInvocation",
    "PreCompact",
    "Stop",
];

const SETTINGS_HELPER_KEYS: &[&str] = &[
    "apiKeyHelper",
    "awsAuthRefresh",
    "awsCredentialExport",
    "otelHeadersHelper",
    "statusLine",
    "fileSuggestion",
];

const PLUGIN_TELEMETRY_DOMAINS: &[&str] = &[
    "i.posthog.com",
    "events.posthog.com",
    "app.posthog.com/batch",
    "app.posthog.com/capture",
    "api.segment.io",
    "cdn.segment.com",
    "api.mixpanel.com",
    "api-js.mixpanel.com",
    "api.amplitude.com",
    "api2.amplitude.com",
    "ingest.sentry.io",
    ".ingest.us.sentry.io",
    ".ingest.de.sentry.io",
    "http-intake.logs.datadoghq.com",
    "browser-intake-datadoghq.com",
    "trace.agent.datadoghq.com",
    "www.google-analytics.com/collect",
    "www.google-analytics.com/mp/collect",
    "analytics.google.com/g/collect",
];

const CREDENTIAL_HARVEST_PATTERNS: &[(&str, &str)] = &[
    (".ssh/id_rsa", "~/.ssh/id_rsa"),
    (".ssh/id_ed25519", "~/.ssh/id_ed25519"),
    (".ssh/id_ecdsa", "~/.ssh/id_ecdsa"),
    (".ssh/id_dsa", "~/.ssh/id_dsa"),
    ("'id_rsa'", "~/.ssh/id_rsa"),
    ("\"id_rsa\"", "~/.ssh/id_rsa"),
    ("'id_ed25519'", "~/.ssh/id_ed25519"),
    ("\"id_ed25519\"", "~/.ssh/id_ed25519"),
    ("'id_ecdsa'", "~/.ssh/id_ecdsa"),
    ("\"id_ecdsa\"", "~/.ssh/id_ecdsa"),
    (".ssh/authorized_keys", "~/.ssh/authorized_keys"),
    ("~/.ssh", "~/.ssh"),
    ("$home/.ssh", "$HOME/.ssh"),
    ("${home}/.ssh", "${HOME}/.ssh"),
    ("'/.ssh'", "~/.ssh"),
    ("\"/.ssh\"", "~/.ssh"),
    ("'.ssh'", "~/.ssh"),
    ("\".ssh\"", "~/.ssh"),
    (".aws/credentials", "~/.aws/credentials"),
    (".aws/config", "~/.aws/config"),
    (".aws/sso", "~/.aws/sso"),
    ("'.aws'", "~/.aws"),
    ("\".aws\"", "~/.aws"),
    ("'/.aws'", "~/.aws"),
    ("\"/.aws\"", "~/.aws"),
    (".azure/accesstokens.json", "~/.azure/accessTokens.json"),
    (".azure/msal_token_cache", "~/.azure/msal_token_cache"),
    ("~/.azure", "~/.azure"),
    ("$home/.azure", "$HOME/.azure"),
    ("${home}/.azure", "${HOME}/.azure"),
    ("'.azure'", "~/.azure"),
    ("\".azure\"", "~/.azure"),
    (
        "gcloud/application_default_credentials.json",
        "gcloud application_default_credentials.json",
    ),
    (
        "'application_default_credentials.json'",
        "gcloud application_default_credentials.json",
    ),
    (
        "\"application_default_credentials.json\"",
        "gcloud application_default_credentials.json",
    ),
    (".config/gcloud", "~/.config/gcloud"),
    (".config/gh/hosts.yml", "~/.config/gh/hosts.yml"),
    (".kube/config", "~/.kube/config"),
    ("'.kube'", "~/.kube"),
    ("\".kube\"", "~/.kube"),
    ("'.gnupg'", "~/.gnupg"),
    ("\".gnupg\"", "~/.gnupg"),
    ("~/.gnupg", "~/.gnupg"),
    ("/.netrc", "~/.netrc"),
    ("~/.netrc", "~/.netrc"),
    ("'.netrc'", "~/.netrc"),
    ("\".netrc\"", "~/.netrc"),
    (".pgpass", "~/.pgpass"),
    (".my.cnf", "~/.my.cnf"),
    (".vault-token", "~/.vault-token"),
    ("credentials.tfrc.json", "Terraform credentials.tfrc.json"),
    (".terraformrc", "~/.terraformrc"),
    (".databrickscfg", "~/.databrickscfg"),
    (".s3cfg", "~/.s3cfg"),
    (".git-credentials", "~/.git-credentials"),
    ("'.git-credentials'", "~/.git-credentials"),
    ("\".git-credentials\"", "~/.git-credentials"),
    ("/.npmrc", "~/.npmrc"),
    ("~/.npmrc", "~/.npmrc"),
    ("$home/.npmrc", "$HOME/.npmrc"),
    ("${home}/.npmrc", "${HOME}/.npmrc"),
    ("'.npmrc'", "~/.npmrc"),
    ("\".npmrc\"", "~/.npmrc"),
    (".pypirc", "~/.pypirc"),
    (".docker/config.json", "~/.docker/config.json"),
    ("'.docker'", "~/.docker"),
    ("\".docker\"", "~/.docker"),
    ("/etc/shadow", "/etc/shadow"),
    (".claude/.credentials.json", "~/.claude/.credentials.json"),
    ("/.credentials.json", "~/.claude/.credentials.json"),
    ("'.credentials.json'", "~/.claude/.credentials.json"),
    ("\".credentials.json\"", "~/.claude/.credentials.json"),
    (".codex/auth.json", "~/.codex/auth.json"),
    ("oauth_creds.json", "~/.gemini/oauth_creds.json"),
    ("gh/hosts.yml", "~/.config/gh/hosts.yml"),
    ("cookies.sqlite", "Firefox cookies.sqlite"),
    ("key4.db", "Firefox key4.db"),
    ("logins.json", "Firefox logins.json"),
    ("cookies.binarycookies", "Safari Cookies.binarycookies"),
    ("/login data", "Chromium Login Data SQLite store"),
    ("\\login data", "Chromium Login Data SQLite store"),
    ("'login data'", "Chromium Login Data SQLite store"),
    ("\"login data\"", "Chromium Login Data SQLite store"),
    ("/default/cookies", "Chromium Cookies SQLite store"),
    ("/network/cookies", "Chromium Cookies SQLite store"),
    (
        "security find-generic-password",
        "macOS Keychain (`security find-generic-password`)",
    ),
    (
        "find-generic-password",
        "macOS Keychain (`security find-generic-password`)",
    ),
    (
        "security find-internet-password",
        "macOS Keychain (`security find-internet-password`)",
    ),
    (
        "find-internet-password",
        "macOS Keychain (`security find-internet-password`)",
    ),
    (
        "security dump-keychain",
        "macOS Keychain (`security dump-keychain`)",
    ),
    ("dump-keychain", "macOS Keychain (`security dump-keychain`)"),
    (
        "claude code-credentials",
        "Claude Code Keychain credentials (`Claude Code-credentials`)",
    ),
    ("secret-tool lookup", "Linux keyring (`secret-tool lookup`)"),
];

struct PluginRegexes {
    pipe_to_shell: Regex,
    ps_download_exec: Regex,
    ps_encoded_cmd: Regex,
    base64_exec: Regex,
    eval_net: Regex,
    dynamic_code_exec: Regex,
    reflective_code_exec: Regex,
    py_empty_join: Regex,
    js_empty_join: Regex,
    download_then_exec: Regex,
    download_output_cmd: Regex,
    cred_path_join: Regex,
    url_var_assign: Regex,
    prompt_override: Regex,
    prompt_stealth: Regex,
    prompt_exfil: Regex,
    prompt_img_exfil: Regex,
    prompt_prose_exfil: Regex,
    prompt_prose_secret_source: Regex,
    prompt_prose_outbound_verb: Regex,
    html_comment: Regex,
    html_comment_dotenv: Regex,
    net_call: Regex,
    exfil_net_sink: Regex,
    url_extract: Regex,
    wholesale_env_dump: Regex,
    sensitive_env_name: Regex,
    dotenv_file_read: Regex,
}

fn plugin_regexes() -> &'static PluginRegexes {
    static RE: OnceLock<PluginRegexes> = OnceLock::new();
    RE.get_or_init(|| PluginRegexes {
        pipe_to_shell: Regex::new(
            r"(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:env\s+)?(?:/bin/|/usr/bin/|/usr/local/bin/)?(?:sh|bash|zsh|dash|ksh|ash|fish|python3?|node|bun|deno|perl|ruby)\b",
        )
        .expect("pipe_to_shell regex"),
        ps_download_exec: Regex::new(
            r"(?i)(?:\b(?:irm|iwr|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]*\|\s*(?:iex|Invoke-Expression)\b|Invoke-Expression[^\n]*DownloadString)",
        )
        .expect("ps_download_exec regex"),
        ps_encoded_cmd: Regex::new(
            r#"(?i)\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b[^\n;|&]{0,120}?\s-(?:e|ec|enc|encodedcommand)\s+['"]?([A-Za-z0-9+/=]{16,8192})['"]?"#,
        )
        .expect("ps_encoded_cmd regex"),
        base64_exec: Regex::new(
            r"(?i)\bbase64\s+(?:-d|--decode|-D)\b[^\n|]*\|\s*(?:sudo\s+)?(?:/bin/|/usr/bin/)?(?:sh|bash|zsh|dash|ksh|ash|python3?|node|perl|ruby)\b",
        )
        .expect("base64_exec regex"),
        eval_net: Regex::new(
            r#"(?i)(?:\b(?:eval|source)\s+"?(?:\$\(|<\()\s*(?:curl|wget)\b|\b(?:sh|bash|zsh|dash|ksh)\s+-[a-z]*c\s+"?\$\(\s*(?:curl|wget)\b)"#,
        )
        .expect("eval_net regex"),
        dynamic_code_exec: Regex::new(
            r"(?is)(?:\b(?:exec|eval)\s*\([^\n;]{0,200}\b(?:urllib|urlopen|requests\.|httpx\.|b64decode|fetch\s*\(|atob\s*\(|Buffer\.from\s*\()|\bnew\s+Function\s*\([^\n;]{0,200}\b(?:fetch|atob|Buffer\.from)\b)",
        )
        .expect("dynamic_code_exec regex"),
        reflective_code_exec: Regex::new(
            r#"(?i)(?:\b__import__\s*\(\s*['"](?:os|posix|subprocess|pty|socket|shutil|urllib(?:\.request)?|http(?:\.client)?|ctypes|builtins)['"]|\bimportlib\.import_module\s*\(\s*['"](?:os|posix|subprocess|pty|socket|shutil|urllib(?:\.request)?|http(?:\.client)?|ctypes|builtins)['"]|\bgetattr\s*\(\s*(?:__import__\s*\(|importlib\.import_module\s*\()|\bgetattr\s*\(\s*(?:os|posix|subprocess|shutil|builtins|__builtins__)\b[^;\n]{0,120}?['"](?:system|popen|spawn[A-Za-z]*|exec[A-Za-z]*|run|Popen|check_output|check_call|eval|compile|__import__)['"]|\b(?:__builtins__|builtins)\s*(?:\.\s*__dict__\s*)?\[\s*['"](?:eval|exec|__import__|compile|getattr)['"]\s*\]|\bglobals\s*\(\s*\)\s*\[\s*['"](?:eval|exec|__import__|getattr)['"]\s*\]|\b(?:globalThis|global|window)\s*\[\s*['"`](?:eval|Function|require|child_process)['"`]\s*\]|\bprocess\s*\.\s*(?:mainModule\s*\.\s*require|binding|dlopen)\s*\(|\bReflect\.construct\s*\(\s*Function\b|\brequire\s*\(\s*['"`](?:node:)?child_process['"`]\s*\)\s*\[\s*['"`](?:exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)['"`]\s*\])"#,
        )
        .expect("reflective_code_exec regex"),
        py_empty_join: Regex::new(
            r#"(?:""|'')\s*\.\s*join\s*\(\s*\[\s*((?:['"][^'"\n\\]{1,24}['"]\s*,\s*)+['"][^'"\n\\]{1,24}['"]\s*,?)\s*\]\s*\)"#,
        )
        .expect("py_empty_join regex"),
        js_empty_join: Regex::new(
            r#"\[\s*((?:['"][^'"\n\\]{1,24}['"]\s*,\s*)+['"][^'"\n\\]{1,24}['"]\s*,?)\s*\]\s*\.\s*join\s*\(\s*(?:""|'')\s*\)"#,
        )
        .expect("js_empty_join regex"),
        download_then_exec: Regex::new(
            r"(?i)\b(?:curl|wget)\b[^\n;&|]{0,160}\s(?:-o|-O|>)\s*(?:/tmp/|\$TMPDIR/|\./)?[A-Za-z0-9._-]+[^\n]{0,120}(?:&&|;)\s*(?:chmod\s+\+x\s+\S+\s*(?:&&|;)\s*)?(?:sh|bash|zsh|dash|python3?|node|bun|\./|/tmp/)",
        )
        .expect("download_then_exec regex"),
        download_output_cmd: Regex::new(
            r#"(?i)\b(?:curl|wget|Invoke-WebRequest|iwr)\b[^\n;|&]*"#,
        )
        .expect("download_output_cmd regex"),
        cred_path_join: Regex::new(
            r#"(?i)(?:['"]gh['"]\s*,\s*['"]hosts\.yml['"]|['"]\.aws['"]\s*,\s*['"](?:credentials|config)['"]|['"]\.kube['"]\s*,\s*['"]config['"]|['"]\.codex['"]\s*,\s*['"]auth\.json['"]|['"]\.docker['"]\s*,\s*['"]config\.json['"]|['"]\.azure['"]\s*,\s*['"](?:accesstokens\.json|msal_token_cache[^'"]*)['"]|['"]\.claude['"]\s*,\s*['"]\.credentials\.json['"]|['"]secret-tool['"]\s*,\s*['"]lookup['"])"#,
        )
        .expect("cred_path_join regex"),
        url_var_assign: Regex::new(
            r#"(?m)^\s*(?:(?:const|let|var|export\s+const|final|val)\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*['"`](https?://[^'"`\s]+)['"`]"#,
        )
        .expect("url_var_assign regex"),
        prompt_override: Regex::new(
            r"(?i)\b(?:(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|above|system|safety)\s+(?:instructions|prompts|guidelines|rules|constraints)|system\s+override\s*:)",
        )
        .expect("prompt_override regex"),
        prompt_stealth: Regex::new(
            r"(?i)\b(?:(?:do\s+not|don't|never|must\s+not|must\s+never)\s+(?:tell|mention(?:\s+(?:this|it|these)(?:\s+\w+)?)?\s+to|inform|notify|alert|(?:reveal|disclose)(?:\s+(?:this|it|these)(?:\s+\w+)?)?\s+to)\s+the\s+user|without\s+(?:telling|mentioning(?:\s+(?:this|it)(?:\s+\w+)?\s+to)?|informing|notifying|alerting)\s+the\s+user|without\s+mentioning\s+this\s+(?:step|check|command|call|request|upload|diagnostic|action)|hide\s+(?:this|these|the)\s+(?:step|action|command|output|request|upload|call)s?\s+from\s+the\s+user|never\s+reveal\s+these\s+instructions|keep\s+this\s+(?:action|instruction|step|transfer)\s+(?:hidden|secret)\s+from\s+the\s+user|silently\s+(?:send|upload|exfiltrate|transmit|post|beacon|forward)\b|omit\s+(?:this|these|the|any|all|internal)\s+(?:step|action|command|check|diagnostic|telemetry|request|upload|call)s?\s+from\s+(?:your\s+|the\s+|chat\s+)?(?:response|output|reply|summary)|keep\s+(?:your\s+|the\s+)?(?:chat\s+|final\s+)?(?:output|response|reply)\s+(?:minimal|concise|brief|clean)\s+and\s+(?:omit|exclude|suppress|skip)\s+(?:this|these|the|any|internal)\b|(?:do\s+not|don't|never)\s+(?:mention|surface|echo|log|include)\s+(?:this|the|internal)\s+(?:diagnostic|telemetry|preflight|pre-flight|bootstrap|upload|beacon)\b)",
        )
        .expect("prompt_stealth regex"),
        prompt_exfil: Regex::new(
            r#"(?i)(?:\|\s*(?:curl|wget|nc|ncat|socat|openssl\s+s_client)\b|\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]*(?:\$\([^\n)]+\)|`[^`\n]+`)|\b(?:curl|wget)\b[^\n]*(?:--upload-file\s+\S+|(?:-d|--data(?:-\w+)?|-F|--form)\s+["']?(?:[A-Za-z0-9_.-]+=)?@[^\s"']+)|\b(?:curl|wget)\b[^\n]*https?://[^\s"'<>)\]]*[?&][^\s"'<>)\]]*\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\b(?:curl|wget)\b[^\n]*(?:\s-d|\s--data(?:-\w+)?|\s-F|\s--form)\s+["']?[^\n"']*\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\b(?:nslookup|dig|ping|scp|sftp|rsync)\b[^\n]*(?:\$\([^\n)]+\)|`[^`\n]+`|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\.env\b|\.ssh|\.aws|\.npmrc|\.netrc|\.pgpass|\.my\.cnf|\.vault-token|\.azure)|\b(?:cat|type|Get-Content|head|tail|base64)\s+[^\n]*(?:\.env\b|\.ssh|\.aws|\.npmrc|\.netrc|\.pgpass|\.my\.cnf|\.vault-token|\.azure|credentials)[^\n]*(?:curl|wget|http|fetch|nc|scp|sftp|ssh|nslookup|dig)\b)"#,
        )
        .expect("prompt_exfil regex"),
        prompt_img_exfil: Regex::new(
            r#"(?i)!\[[^\]]*\]\(\s*https?://[^\s)]*(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\{\{[^}\n]+\}\}|\$\([^\n)]+\))"#,
        )
        .expect("prompt_img_exfil regex"),
        prompt_prose_exfil: Regex::new(
            r#"(?i)\b(?:read|load|collect|gather|extract|dump|encode|include|attach|append|send|post|upload|transmit|forward|exfiltrate)\b[^.!?\n]{0,140}(?:(?:^|[\s`'"])\.env(?:\.[A-Za-z0-9_-]+)?\b|\b(?:api\s+keys?|secret\s+keys?|private\s+keys?|access\s+tokens?|ssh\s+keys?|environment\s+variables?|process\.env|os\.environ|credentials)\b|~/\.(?:ssh|aws|pgpass|my\.cnf|vault-token|azure|kube|npmrc|netrc|gnupg|pypirc))[^.!?\n]{0,160}\b(?:send|post|upload|transmit|forward|exfiltrate|include|attach|append|fetch|request|webhook|to|via|into|at)\b[^.!?\n]{0,100}https?://[^\s"'`<>)\]]+"#,
        )
        .expect("prompt_prose_exfil regex"),
        prompt_prose_secret_source: Regex::new(
            r#"(?i)\b(?:read|load|collect|gather|extract|dump|inspect|parse|grab|copy|open|cat)\b[^\n]{0,120}(?:(?:^|[\s`'"])\.env(?:\.[A-Za-z0-9_-]+)?(?:\b|$)|(?:\b(?:api\s+keys?|secret\s+keys?|private\s+keys?|access\s+tokens?|ssh\s+keys?|environment\s+variables?|process\.env|os\.environ|credentials|keychain)\b)|~/\.(?:ssh|aws|pgpass|my\.cnf|vault-token|azure|kube|npmrc|netrc|gnupg|pypirc))"#,
        )
        .expect("prompt_prose_secret_source regex"),
        prompt_prose_outbound_verb: Regex::new(
            r#"(?i)\b(?:send|post|upload|transmit|forward|exfiltrate|submit|report|dispatch|push|webhook|curl|wget|fetch)\b"#,
        )
        .expect("prompt_prose_outbound_verb regex"),
        html_comment: Regex::new(r"(?s)<!--(.*?)-->").expect("html_comment regex"),
        html_comment_dotenv: Regex::new(r"(?i)(?:^|[^A-Za-z0-9_])\.env(?:\.(?:local|production|prod|staging|development|dev|test))?(?:$|[^A-Za-z0-9_.])")
            .expect("html_comment_dotenv regex"),
        net_call: Regex::new(
            r#"(?i)(?:\b(?:curl|wget|nc|ncat|netcat|socat|scp|sftp|ssh|nslookup|dig|ping|telnet|Invoke-WebRequest|Invoke-RestMethod)\b|\bopenssl\s+s_client\b|\brsync\b[^\n;|&]*(?:rsync://|[A-Za-z0-9._-]+@[A-Za-z0-9._-]+:|[A-Za-z0-9._-]+\.[A-Za-z]{2,}:)|/dev/(?:tcp|udp)/|\bfetch\s*\(|\bnavigator\.sendBeacon\s*\(|\baxios\.(?:get|post|put|patch|delete|request)\b|\bhttps?\.(?:get|request)\s*\(|\b(?:net|tls)\.(?:connect|createConnection)\s*\(|\brequire\s*\(\s*['"](?:node:)?(?:https?|http2|net|tls|dns|dgram)['"]\s*\)|\bfrom\s+['"](?:node:)?(?:https?|http2|net|tls|dns|dgram)['"]|\bnew\s+WebSocket\s*\(|\brequests\.(?:get|post|put|patch|request|Session)\s*\(|\burllib\.request\b|\burllib3\b|\bhttp\.client\b|\bHTTPS?Connection\s*\(|\baiohttp\b|\bhttpx\.(?:get|post|put|Client|AsyncClient)\b|\bsocket\.(?:socket|create_connection|gethostbyname|getaddrinfo|sendto)\s*\()"#,
        )
        .expect("net_call regex"),
        exfil_net_sink: Regex::new(
            r#"(?i)(?:\b(?:curl|wget|nc|ncat|netcat|socat|scp|sftp|nslookup|dig|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b|\bopenssl\s+s_client\b|\brsync\b[^\n;|&]*(?:rsync://|[A-Za-z0-9._-]+@[A-Za-z0-9._-]+:|[A-Za-z0-9._-]+\.[A-Za-z]{2,}:)|/dev/(?:tcp|udp)/|\bfetch\s*\(|\bnavigator\.sendBeacon\s*\(|\baxios\s*(?:\(|\.\s*(?:get|post|put|patch|delete|request)\s*\()|\bhttps?\s*\.\s*(?:get|request)\s*\(|\bhttp2\s*\.\s*connect\s*\(|\b(?:net|tls)\s*\.\s*(?:connect|createConnection)\s*\(|\bdgram\s*\.\s*createSocket\s*\(|\bdns\s*\.\s*(?:lookup|resolve\w*)\s*\(|\bnew\s+WebSocket\s*\(|\burllib\.request\.urlopen\s*\(|\burlopen\s*\(|\brequests\s*\.\s*(?:get|post|put|patch|delete|request|Session)\s*\(|\bhttpx\s*\.\s*(?:get|post|put|patch|delete|request|Client|AsyncClient)\s*\(|\bHTTPS?Connection\s*\(|\baiohttp\.ClientSession\s*\(|\bsocket\s*\.\s*(?:create_connection|connect|sendto|gethostbyname|getaddrinfo)\s*\(|\bNet::HTTP\b|\bcurl_exec\s*\(|\bhttp\.(?:Get|Post|NewRequest)\s*\()"#,
        )
        .expect("exfil_net_sink regex"),
        url_extract: Regex::new(r#"https?://[^\s"'`<>)\]]+"#).expect("url_extract regex"),
        wholesale_env_dump: Regex::new(
            r#"(?im)(?:\bdict\s*\(\s*os\.environ\s*\)|\bos\.environ\.(?:copy|items|values|keys)\s*\(\s*\)|\bfor\s+[A-Za-z0-9_,\s]+\s+in\s+os\.environ\b|\bos\.environ\s*\[\s*[A-Za-z_][A-Za-z0-9_]*\s*\]|\bos\.environ\b[ \t]*(?:[,)\]};#]|$)|\bJSON\.stringify\s*\(\s*process\.env\b|\.\.\.\s*process\.env\b|\bObject\.(?:entries|values|keys|assign|fromEntries)\s*\([^)\n]*\bprocess\.env\b|\bfor\s*\(\s*(?:const|let|var)?\s*[A-Za-z_$][A-Za-z0-9_$]*\s+in\s+process\.env\b|\bprocess\.env\s*\[\s*[A-Za-z_$][A-Za-z0-9_$]*\s*\]|\b(?:process|Bun)\.env\b[ \t]*(?:[,)\]};]|//|$)|\bDeno\.env\.toObject\s*\(\s*\)|\b(?:printenv|export\s+-p)\b|(?:^|[;|&`$(])\s*env\s*(?:\||>))"#,
        )
        .expect("wholesale_env_dump regex"),
        sensitive_env_name: Regex::new(
            r#"\b(?:ANTHROPIC_API_KEY|CLAUDE_API_KEY|CLAUDE_CODE_OAUTH_TOKEN|OPENAI_API_KEY|GEMINI_API_KEY|GOOGLE_API_KEY|OPENROUTER_API_KEY|XAI_API_KEY|GROQ_API_KEY|CURSOR_API_KEY|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|NPM_TOKEN|PYPI_API_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|AZURE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS|DATABASE_URL|SUPABASE_SERVICE_ROLE_KEY|STRIPE_SECRET_KEY|SLACK_BOT_TOKEN|PRIVATE_KEY|SSH_AUTH_SOCK)\b"#,
        )
        .expect("sensitive_env_name regex"),
        dotenv_file_read: Regex::new(
            r#"(?i)(?:\b(?:readFileSync|readFile|createReadStream|open|read_text|read_bytes|dotenv_values)\s*\([^\n)]{0,120}['"`/\\]\.(?:env(?:\.[A-Za-z0-9_-]+)?|npmrc|pypirc|netrc|git-credentials|pgpass|my\.cnf|vault-token)['"`]|\bPath\s*\([^\n)]{0,120}['"`/\\]\.(?:env(?:\.[A-Za-z0-9_-]+)?|npmrc|pypirc|netrc|git-credentials|pgpass|my\.cnf|vault-token)['"`]\s*\)\s*\.\s*(?:read_text|read_bytes|open)\b|\bPath(?:\.cwd\(\))?\s*/\s*['"]\.(?:env(?:\.[A-Za-z0-9_-]+)?|npmrc|pypirc|netrc|git-credentials)['"]|\b(?:cat|Get-Content|type)\s+['"]?(?:\./|\$PWD/|\$\{PWD\}/)?\.(?:env(?:\.[A-Za-z0-9_-]+)?|npmrc|pypirc|netrc|git-credentials)\b)"#,
        )
        .expect("dotenv_file_read regex"),
    })
}

/// Strips `//` line comments, `/* ... */` block comments, and trailing commas outside JSON strings
/// so JSONC files (such as Antigravity `plugin.json`, `hooks.json`, and `mcp_config.json`) parse cleanly.
pub fn strip_jsonc(raw: &str) -> String {
    let mut no_comments = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;

    while let Some(c) = chars.next() {
        if in_string {
            no_comments.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }

        if c == '"' {
            in_string = true;
            no_comments.push(c);
        } else if c == '/' && chars.peek() == Some(&'/') {
            chars.next();
            for nc in chars.by_ref() {
                if nc == '\n' {
                    no_comments.push('\n');
                    break;
                }
            }
        } else if c == '/' && chars.peek() == Some(&'*') {
            chars.next();
            while let Some(nc) = chars.next() {
                if nc == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    break;
                }
                if nc == '\n' {
                    no_comments.push('\n');
                }
            }
        } else {
            no_comments.push(c);
        }
    }

    let vec_chars: Vec<char> = no_comments.chars().collect();
    let mut out = String::with_capacity(no_comments.len());
    in_string = false;
    escaped = false;

    for i in 0..vec_chars.len() {
        let c = vec_chars[i];
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }

        if c == '"' {
            in_string = true;
            out.push(c);
        } else if c == ',' {
            let mut j = i + 1;
            while j < vec_chars.len() && vec_chars[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < vec_chars.len() && (vec_chars[j] == '}' || vec_chars[j] == ']') {
                continue;
            }
            out.push(c);
        } else {
            out.push(c);
        }
    }

    out
}

/// Strips `//`, `/* ... */`, and `#` comments outside string literals so comments (like
/// `// fallback rpc http://localhost:9000`) can never spoof localhost-only checks.
fn strip_code_comments(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut prev_was_space_or_bol = true;
    let mut prev_char: Option<char> = None;

    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            prev_char = Some(c);
            continue;
        }

        if c == '"' || c == '\'' || c == '`' {
            quote = Some(c);
            out.push(c);
            prev_was_space_or_bol = false;
            prev_char = Some(c);
        } else if c == '/' && chars.peek() == Some(&'/') && prev_char != Some(':') {
            chars.next();
            for nc in chars.by_ref() {
                if nc == '\n' {
                    out.push('\n');
                    prev_was_space_or_bol = true;
                    prev_char = Some('\n');
                    break;
                }
            }
        } else if c == '/' && chars.peek() == Some(&'*') {
            chars.next();
            while let Some(nc) = chars.next() {
                if nc == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    break;
                }
                if nc == '\n' {
                    out.push('\n');
                }
            }
            prev_was_space_or_bol = true;
            prev_char = Some(' ');
        } else if c == '#' && prev_was_space_or_bol {
            for nc in chars.by_ref() {
                if nc == '\n' {
                    out.push('\n');
                    prev_was_space_or_bol = true;
                    prev_char = Some('\n');
                    break;
                }
            }
        } else {
            prev_was_space_or_bol = c.is_ascii_whitespace() || c == ';';
            prev_char = Some(c);
            out.push(c);
        }
    }

    out
}

pub fn parse_json_or_jsonc(raw: &str) -> Option<Value> {
    serde_json::from_str::<Value>(raw).ok().or_else(|| {
        let cleaned = strip_jsonc(raw);
        serde_json::from_str::<Value>(&cleaned).ok()
    })
}

pub fn audit_plugin_files(files: &[PathBuf], engine: &RuleEngine) -> Vec<McpFinding> {
    audit_plugin_files_with_policy(files, engine, None)
}

pub fn audit_plugin_files_with_policy(
    files: &[PathBuf],
    engine: &RuleEngine,
    policy: Option<&PolicyConfig>,
) -> Vec<McpFinding> {
    let mut findings = Vec::new();
    let mut seen_fingerprints = HashSet::new();

    for path in files {
        if policy.is_some_and(|p| p.is_path_ignored(path)) {
            continue;
        }
        audit_single_plugin_file(
            path,
            path,
            None,
            engine,
            &mut findings,
            &mut seen_fingerprints,
        );
    }

    if let Some(pol) = policy {
        findings.retain(|f| {
            !pol.is_rule_disabled_for(f.rule_id, Some(&f.config_path))
                && !pol.is_fingerprint_ignored_for(&f.fingerprint, Some(&f.config_path))
        });
    }

    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.config_file.cmp(&b.config_file))
            .then_with(|| a.server_name.cmp(&b.server_name))
    });
    findings
}

/// Audits `disk_path` (e.g., a materialized git index or commit blob) while attributing findings,
/// handler script resolutions, stable fingerprints, and scoped `.leaktap.toml` rules/allowlists
/// to `logical_path` (and `sandbox_remap` `(sandbox_root, repo_root)` when handler scripts exist).
pub fn audit_plugin_file_as(
    disk_path: &Path,
    logical_path: &Path,
    commit_sha: Option<&str>,
    sandbox_remap: Option<(&Path, &Path)>,
    engine: &RuleEngine,
    policy: Option<&PolicyConfig>,
) -> Vec<McpFinding> {
    if policy.is_some_and(|p| p.is_path_ignored(logical_path)) {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let mut seen_fp = HashSet::new();
    audit_single_plugin_file(
        disk_path,
        logical_path,
        sandbox_remap,
        engine,
        &mut findings,
        &mut seen_fp,
    );

    if let Some(sha) = commit_sha {
        for f in &mut findings {
            let rel_str = if let Some((_, repo_root)) = sandbox_remap {
                f.config_path
                    .strip_prefix(repo_root)
                    .map(|r| r.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| f.config_file.clone())
            } else {
                f.config_file.clone()
            };
            f.config_file = format!("git:{sha}:{rel_str}");
        }
    }

    if let Some(pol) = policy {
        findings.retain(|f| {
            !pol.is_path_ignored(&f.config_path)
                && !pol.is_rule_disabled_for(f.rule_id, Some(&f.config_path))
                && !pol.is_fingerprint_ignored_for(&f.fingerprint, Some(&f.config_path))
        });
    }
    findings
}

fn audit_single_plugin_file(
    disk_path: &Path,
    logical_path: &Path,
    sandbox_remap: Option<(&Path, &Path)>,
    engine: &RuleEngine,
    out: &mut Vec<McpFinding>,
    seen_fp: &mut HashSet<String>,
) {
    let Ok(meta) = fs::metadata(disk_path) else {
        return;
    };
    let Some(file_name) = logical_path.file_name().and_then(|n| n.to_str()) else {
        return;
    };
    let display = shorten_home(logical_path);
    let is_settings_file = matches!(file_name, "settings.json" | "settings.local.json");
    let is_hooks_file = file_name == "hooks.json" || is_settings_file;
    let is_json_config =
        is_hooks_file || matches!(file_name, "plugin.json" | "gemini-extension.json");
    let is_prompt_doc = is_instruction_doc_file(logical_path, file_name);

    if !crate::scanner::is_sqlite_extension(logical_path)
        && (crate::discovery::is_compiled_binary_file(disk_path)
            || is_likely_compiled_binary(disk_path))
    {
        let label = component_label(logical_path, "");
        let _ = audit_compiled_binary_file(
            disk_path,
            logical_path,
            &display,
            &label,
            1,
            engine,
            out,
            seen_fp,
        );
        return;
    }

    if is_json_config && meta.len() > MAX_JSON_CONFIG_BYTES {
        let label = component_label(logical_path, "");
        let fp = fingerprint_match("plugin-oversized-config", &display);
        push_finding(
            out,
            seen_fp,
            McpFinding {
                rule_id: "plugin-oversized-config",
                server_name: label,
                config_file: display.clone(),
                config_path: logical_path.to_path_buf(),
                line: 1,
                severity: Severity::High,
                fingerprint: fp,
                message: format!(
                    "Plugin or workspace config file exceeds 16 MiB ({:.1} MiB > 16.0 MiB AST limit) — structured JSON checks cannot inspect full AST",
                    meta.len() as f64 / (1024.0 * 1024.0)
                ),
            },
        );
        if meta.len() <= MAX_STREAM_PLUGIN_BYTES {
            let _ = audit_streamed_plugin_file(
                disk_path,
                logical_path,
                &display,
                false,
                engine,
                out,
                seen_fp,
            );
        }
        return;
    }

    if meta.len() > MAX_STREAM_PLUGIN_BYTES {
        eprintln!(
            "[leaktap:warn] Skipping oversized plugin file {} ({:.1} MiB > 64 MiB limit)",
            display,
            meta.len() as f64 / (1024.0 * 1024.0)
        );
        return;
    }

    let in_mem_limit = if is_json_config {
        MAX_JSON_CONFIG_BYTES
    } else {
        MAX_PLUGIN_FILE_BYTES
    };

    if meta.len() > in_mem_limit {
        let _ = audit_streamed_plugin_file(
            disk_path,
            logical_path,
            &display,
            is_prompt_doc,
            engine,
            out,
            seen_fp,
        );
        return;
    }

    let Ok(raw) = crate::scanner::read_text_auto_encoding(disk_path, in_mem_limit) else {
        return;
    };
    let label = component_label(logical_path, &raw);

    // 0. Check hidden bidirectional override, Unicode Tag, Variation Selector Supplement, or zero-width smuggling
    // across BOTH prompt files and scripts/configs, then strip invisible codepoints before regex checks.
    check_unicode_smuggling(
        logical_path,
        &display,
        &label,
        &raw,
        is_prompt_doc,
        1,
        out,
        seen_fp,
    );
    let norm_raw = strip_invisible_unicode(&raw);
    let parsed_json_opt = if file_name.ends_with(".json") || file_name.ends_with(".jsonc") {
        parse_json_or_jsonc(&norm_raw)
    } else {
        None
    };

    // 1. Audit lifecycle hooks, helper commands, and `env` overrides in `hooks.json` and `settings*.json`
    if is_hooks_file {
        if let Some(ref json) = parsed_json_opt {
            audit_hooks_config(
                disk_path,
                logical_path,
                sandbox_remap,
                &display,
                &label,
                &norm_raw,
                json,
                file_name == "hooks.json",
                engine,
                out,
                seen_fp,
            );
        }
    }

    // 2. Check remote code execution (`curl ... | sh`, `irm ... | iex`, `base64 -d | sh`, `exec(urllib...)`)
    check_remote_code_exec(
        logical_path,
        &display,
        &label,
        &norm_raw,
        is_prompt_doc,
        1,
        out,
        seen_fp,
    );

    // 3. Check credential harvesting (`~/.ssh`, `~/.aws/credentials`, `~/.pgpass`, Keychain, browser DBs),
    // pruning defensive `permissions.deny` / `permissions.ask` / `exclude` JSON subtrees first.
    if let Some(ref json) = parsed_json_opt {
        let mut pruned = json.clone();
        prune_defensive_json_subtrees(&mut pruned);
        let pruned_str = serde_json::to_string_pretty(&pruned).unwrap_or_default();
        let before_len = out.len();
        check_credential_harvest(
            logical_path,
            &display,
            &label,
            &pruned_str,
            false,
            1,
            out,
            seen_fp,
        );
        for f in &mut out[before_len..] {
            if f.config_path == logical_path {
                for &(needle, human_target) in CREDENTIAL_HARVEST_PATTERNS {
                    if f.message.contains(human_target) {
                        let mapped = find_line_number(&norm_raw, needle);
                        if mapped > 1 || norm_raw.to_ascii_lowercase().contains(needle) {
                            f.line = mapped;
                            break;
                        }
                    }
                }
            }
        }
    } else {
        check_credential_harvest(
            logical_path,
            &display,
            &label,
            &norm_raw,
            is_prompt_doc,
            1,
            out,
            seen_fp,
        );
    }

    // 3b. Check code/script environment & secret exfiltration (`process.env` / `os.environ` / `.env` -> external network)
    check_env_and_secret_exfiltration(
        logical_path,
        &display,
        &label,
        &norm_raw,
        is_prompt_doc,
        1,
        out,
        seen_fp,
    );

    // 3c. Check outbound external network calls inside executable skill/plugin scripts (`skills/*/scripts/*`, standalone `SKILL.md` / `plugin.json` bundles)
    if !is_prompt_doc && is_skill_script_path(disk_path, logical_path) {
        let net_hit = detect_non_official_external_network_call(&norm_raw).or_else(|| {
            decode_powershell_encoded_commands(&norm_raw)
                .into_iter()
                .find_map(|(ps_ln, ps_txt)| {
                    detect_non_official_external_network_call(&ps_txt)
                        .map(|(_, desc)| (ps_ln, desc))
                })
        });
        if let Some((net_line, target_desc)) = net_hit {
            let fp = fingerprint_match("plugin-skill-network", &format!("{display}:{target_desc}"));
            push_finding(
                out,
                seen_fp,
                McpFinding {
                    rule_id: "plugin-skill-network",
                    server_name: label.clone(),
                    config_file: display.clone(),
                    config_path: logical_path.to_path_buf(),
                    line: net_line.max(1),
                    severity: Severity::Medium,
                    fingerprint: fp,
                    message: format!(
                        "Skill or plugin script makes an outbound network call ({target_desc}) — inspect script inputs for data exfiltration"
                    ),
                },
            );
        }
    }

    // 4. Check prompt injection, stealth directives, & exfiltration commands in markdown/rule instruction files
    if is_prompt_doc {
        check_prompt_injection(logical_path, &display, &label, &norm_raw, 1, out, seen_fp);
    }

    // 5. Check hardcoded live secrets (Secret category only — never flag author emails in plugin.json)
    check_hardcoded_secrets(
        logical_path,
        &display,
        &label,
        &norm_raw,
        1,
        engine,
        out,
        seen_fp,
    );

    // 6. Check outbound third-party telemetry/analytics ingestion endpoints in manifests, hooks, and scripts
    if !is_prompt_doc {
        check_telemetry_domains(logical_path, &display, &label, &norm_raw, 1, out, seen_fp);
    }
}

fn audit_streamed_plugin_file(
    disk_path: &Path,
    logical_path: &Path,
    display: &str,
    is_prompt_doc: bool,
    engine: &RuleEngine,
    out: &mut Vec<McpFinding>,
    seen_fp: &mut HashSet<String>,
) -> Option<String> {
    let Ok(mut file) = File::open(disk_path) else {
        return None;
    };
    let label = component_label(logical_path, "");
    let mut overlap = Vec::<u8>::new();
    let mut chunk = vec![0u8; STREAM_CHUNK_BYTES];
    let mut base_line = 1usize;
    let mut detected_net: Option<String> = None;

    while let Ok(n) = file.read(&mut chunk) {
        if n == 0 {
            break;
        }
        let mut combined = Vec::with_capacity(overlap.len() + n);
        combined.extend_from_slice(&overlap);
        combined.extend_from_slice(&chunk[..n]);

        let raw_text = String::from_utf8_lossy(&combined);
        check_unicode_smuggling(
            logical_path,
            display,
            &label,
            &raw_text,
            is_prompt_doc,
            base_line,
            out,
            seen_fp,
        );
        let text = strip_invisible_unicode(&raw_text);
        check_remote_code_exec(
            logical_path,
            display,
            &label,
            &text,
            is_prompt_doc,
            base_line,
            out,
            seen_fp,
        );
        check_credential_harvest(
            logical_path,
            display,
            &label,
            &text,
            is_prompt_doc,
            base_line,
            out,
            seen_fp,
        );
        check_env_and_secret_exfiltration(
            logical_path,
            display,
            &label,
            &text,
            is_prompt_doc,
            base_line,
            out,
            seen_fp,
        );
        if is_prompt_doc {
            check_prompt_injection(
                logical_path,
                display,
                &label,
                &text,
                base_line,
                out,
                seen_fp,
            );
        } else {
            check_telemetry_domains(
                logical_path,
                display,
                &label,
                &text,
                base_line,
                out,
                seen_fp,
            );
            if detected_net.is_none() {
                detected_net = detect_external_network_call(&text);
            }
        }
        check_hardcoded_secrets(
            logical_path,
            display,
            &label,
            &text,
            base_line,
            engine,
            out,
            seen_fp,
        );

        let advance_len = combined.len().saturating_sub(STREAM_OVERLAP_BYTES);
        base_line += combined[..advance_len]
            .iter()
            .filter(|&&b| b == b'\n')
            .count();
        overlap.clear();
        overlap.extend_from_slice(&combined[advance_len..]);
    }
    detected_net
}

#[allow(clippy::too_many_arguments)]
fn audit_compiled_binary_file(
    disk_path: &Path,
    logical_path: &Path,
    display: &str,
    label: &str,
    line: usize,
    engine: &RuleEngine,
    out: &mut Vec<McpFinding>,
    seen_fp: &mut HashSet<String>,
) -> Option<String> {
    let fp = fingerprint_match("plugin-compiled-binary", display);
    push_finding(
        out,
        seen_fp,
        McpFinding {
            rule_id: "plugin-compiled-binary",
            server_name: label.to_string(),
            config_file: display.to_string(),
            config_path: logical_path.to_path_buf(),
            line,
            severity: Severity::High,
            fingerprint: fp,
            message: format!(
                "Opaque compiled binary (`{display}`) bundled or executed by plugin, hook, skill, or MCP config — inspect binary provenance"
            ),
        },
    );

    let extracted = extract_printable_binary_strings(disk_path, 32 * 1024 * 1024)?;
    check_remote_code_exec(
        logical_path,
        display,
        label,
        &extracted,
        false,
        1,
        out,
        seen_fp,
    );
    check_credential_harvest(
        logical_path,
        display,
        label,
        &extracted,
        false,
        1,
        out,
        seen_fp,
    );
    check_env_and_secret_exfiltration(
        logical_path,
        display,
        label,
        &extracted,
        false,
        1,
        out,
        seen_fp,
    );
    check_hardcoded_secrets(
        logical_path,
        display,
        label,
        &extracted,
        1,
        engine,
        out,
        seen_fp,
    );
    check_telemetry_domains(logical_path, display, label, &extracted, 1, out, seen_fp);
    detect_external_network_call(&extracted)
}

fn extract_printable_binary_strings(disk_path: &Path, max_bytes: u64) -> Option<String> {
    let meta = fs::metadata(disk_path).ok()?;
    if meta.len() > max_bytes {
        return None;
    }
    let mut f = File::open(disk_path).ok()?;
    let mut io_buf = vec![0u8; 64 * 1024];
    let mut run = Vec::with_capacity(256);
    let mut out = String::new();

    loop {
        let n = match f.read(&mut io_buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        for &b in &io_buf[..n] {
            if b.is_ascii_graphic() || b == b' ' || b == b'\t' {
                run.push(b);
                if run.len() >= 8192 {
                    if let Ok(s) = std::str::from_utf8(&run) {
                        out.push_str(s);
                        out.push('\n');
                    }
                    run.clear();
                }
            } else {
                if run.len() >= 6 {
                    if let Ok(s) = std::str::from_utf8(&run) {
                        out.push_str(s);
                        out.push('\n');
                    }
                }
                run.clear();
            }
            if out.len() >= 4 * 1024 * 1024 {
                break;
            }
        }
        if out.len() >= 4 * 1024 * 1024 {
            break;
        }
    }
    if run.len() >= 6 {
        if let Ok(s) = std::str::from_utf8(&run) {
            out.push_str(s);
            out.push('\n');
        }
    }
    Some(out)
}

fn prune_defensive_json_subtrees(val: &mut Value) {
    match val {
        Value::Object(map) => {
            for def_key in [
                "disallowedTools",
                "deniedTools",
                "blockedPaths",
                "exclude",
                "watcherExclude",
                "ignorePatterns",
                "files.exclude",
                "search.exclude",
                "files.watcherExclude",
                "claude.exclude",
                "cursor.general.globalCursorIgnoreList",
            ] {
                map.remove(def_key);
            }
            if let Some(Value::Object(perms)) = map.get_mut("permissions") {
                perms.remove("deny");
                perms.remove("ask");
            }
            if let Some(Value::Object(sb)) = map.get_mut("sandbox") {
                sb.remove("deny");
                sb.remove("denyRead");
                sb.remove("denyWrite");
            }
            for child in map.values_mut() {
                prune_defensive_json_subtrees(child);
            }
        }
        Value::Array(arr) => {
            for item in arr {
                prune_defensive_json_subtrees(item);
            }
        }
        _ => {}
    }
}

fn is_skill_script_path(disk_path: &Path, logical_path: &Path) -> bool {
    let in_hooks = logical_path
        .components()
        .chain(disk_path.components())
        .any(|c| matches!(c.as_os_str().to_str(), Some("hooks" | "hooks-handlers")));
    if in_hooks {
        return false;
    }
    let in_skill_or_plugin_tree =
        logical_path
            .components()
            .chain(disk_path.components())
            .any(|c| {
                matches!(
                    c.as_os_str().to_str(),
                    Some(
                        "skills"
                            | "commands"
                            | "workflows"
                            | "plugins"
                            | "extensions"
                            | ".claude-plugin"
                            | ".codex-plugin"
                    )
                )
            })
            || crate::discovery::has_plugin_or_skill_root_ancestor(disk_path);

    in_skill_or_plugin_tree
        && (has_script_extension(logical_path)
            || has_script_extension(disk_path)
            || is_shebang_script(disk_path))
}

fn is_false_positive_cli_net_token(code: &str, start: usize, end: usize) -> bool {
    let matched = code[start..end].trim();
    let lower = matched.to_ascii_lowercase();
    let is_cli_bin = matches!(
        lower.as_str(),
        "curl"
            | "wget"
            | "nc"
            | "ncat"
            | "netcat"
            | "socat"
            | "scp"
            | "sftp"
            | "ssh"
            | "nslookup"
            | "dig"
            | "ping"
            | "telnet"
            | "iwr"
            | "irm"
            | "invoke-webrequest"
            | "invoke-restmethod"
    );
    if !is_cli_bin {
        return false;
    }
    if start > 0 {
        let prev = code.as_bytes()[start - 1];
        if matches!(prev, b'.' | b'-' | b':' | b'@') {
            return true;
        }
        if prev == b'/' {
            let prefix = code[..start].to_ascii_lowercase();
            if !prefix.ends_with("/bin/") && !prefix.ends_with("/sbin/") {
                return true;
            }
        }
    }
    let after = &code[end..];
    if let Some(first) = after.chars().next() {
        if first == ' ' || first == '\t' {
            let line_rem = after.split('\n').next().unwrap_or("").trim();
            if line_rem.is_empty()
                || line_rem.starts_with('#')
                || line_rem.starts_with("//")
                || matches!(
                    line_rem.as_bytes()[0],
                    b'|' | b';' | b')' | b']' | b'}' | b','
                )
            {
                return true;
            }
            return false;
        }
        if first == '\'' || first == '"' {
            let rest = after[1..].trim_start();
            if let Some(after_comma) = rest.strip_prefix(',') {
                let next_tok = after_comma.trim_start();
                if next_tok.starts_with('[')
                    || next_tok.starts_with("\"http")
                    || next_tok.starts_with("'http")
                    || next_tok.starts_with("\"-")
                    || next_tok.starts_with("'-")
                {
                    return false;
                }
            }
        }
    }
    true
}

fn detect_non_official_external_network_call(text: &str) -> Option<(usize, String)> {
    let code = strip_code_comments(text);
    let re = plugin_regexes();
    if !re.net_call.is_match(&code) {
        return None;
    }

    let resolved_url_vars = resolve_url_identifiers(&code);
    for mat in re.net_call.find_iter(&code) {
        if is_false_positive_cli_net_token(&code, mat.start(), mat.end()) {
            continue;
        }
        let line_start = code[..mat.start()].rfind('\n').map_or(0, |i| i + 1);
        let window_end = (mat.end() + 240).min(code.len());
        let mut safe_end = window_end;
        while safe_end < code.len() && !code.is_char_boundary(safe_end) {
            safe_end += 1;
        }
        let call_window = &code[line_start..safe_end];
        let urls = urls_for_call_window(call_window, &resolved_url_vars);
        let non_local_urls: Vec<&str> = urls
            .iter()
            .copied()
            .filter(|u| !is_localhost_url(u))
            .collect();
        if !urls.is_empty() && non_local_urls.is_empty() {
            continue;
        }
        if urls.is_empty() && call_window_targets_localhost_only(call_window) {
            continue;
        }
        if !non_local_urls.is_empty() && non_local_urls.iter().all(|u| is_official_llm_api_url(u)) {
            continue;
        }

        let ln = line_at_offset(text, mat.start());
        if let Some(&first_url) = non_local_urls.first() {
            let host = extract_url_host(first_url).unwrap_or(first_url);
            return Some((ln, format!("`{host}`")));
        }
        let matched = mat.as_str().trim().trim_end_matches('(').trim();
        return Some((ln, format!("via `{matched}`")));
    }

    None
}

fn is_non_system_binary_path(path: &Path) -> bool {
    let s = path.to_string_lossy();
    let lower = s.to_ascii_lowercase();
    for sys_prefix in [
        "/bin/",
        "/sbin/",
        "/usr/bin/",
        "/usr/sbin/",
        "/usr/local/bin/",
        "/usr/lib/",
        "/lib/",
        "/lib64/",
        "/system/",
        "/library/apple/",
        "/opt/homebrew/",
        "/nix/store/",
        "/snap/",
        "c:\\windows\\",
        "c:/windows/",
        "c:\\program files\\",
        "c:/program files/",
    ] {
        if lower.starts_with(sys_prefix) {
            return false;
        }
    }
    true
}

fn is_suspicious_invisible_codepoint(
    cp: u32,
    byte_idx: usize,
    prev: Option<char>,
    next: Option<char>,
) -> bool {
    if (0x202A..=0x202E).contains(&cp)
        || (0x2066..=0x2069).contains(&cp)
        || matches!(cp, 0x200E | 0x200F | 0x061C)
        || (0xE0000..=0xE007F).contains(&cp)
        || (0xE0100..=0xE01EF).contains(&cp)
        || matches!(cp, 0x200B | 0x2060 | 0x2061 | 0x2062 | 0x2063 | 0x2064)
        || (cp == 0xFEFF && byte_idx > 0)
    {
        return true;
    }
    if matches!(cp, 0x200C | 0x200D) || (0xFE00..=0xFE0F).contains(&cp) {
        let adj_ascii = prev.is_some_and(|c| c.is_ascii_alphanumeric())
            || next.is_some_and(|c| c.is_ascii_alphanumeric());
        if adj_ascii {
            return true;
        }
    }
    false
}

pub(crate) fn strip_invisible_unicode(raw: &str) -> String {
    let has_candidate = raw.chars().any(|c| {
        let cp = c as u32;
        (0x200B..=0x200F).contains(&cp)
            || (0x202A..=0x202E).contains(&cp)
            || (0x2060..=0x2069).contains(&cp)
            || cp == 0x061C
            || cp == 0xFEFF
            || (0xFE00..=0xFE0F).contains(&cp)
            || (0xE0000..=0xE007F).contains(&cp)
            || (0xE0100..=0xE01EF).contains(&cp)
    });
    if !has_candidate {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        let cp = c as u32;
        let is_invis = (0x200B..=0x200F).contains(&cp)
            || (0x202A..=0x202E).contains(&cp)
            || (0x2060..=0x2069).contains(&cp)
            || cp == 0x061C
            || cp == 0xFEFF
            || (0xFE00..=0xFE0F).contains(&cp)
            || (0xE0000..=0xE007F).contains(&cp)
            || (0xE0100..=0xE01EF).contains(&cp);
        if !is_invis {
            out.push(c);
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn check_unicode_smuggling(
    path: &Path,
    display: &str,
    label: &str,
    raw: &str,
    is_prompt_doc: bool,
    base_line: usize,
    out: &mut Vec<McpFinding>,
    seen_fp: &mut HashSet<String>,
) {
    let indexed: Vec<(usize, char)> = raw.char_indices().collect();
    for (i, &(byte_idx, ch)) in indexed.iter().enumerate() {
        let prev = i.checked_sub(1).and_then(|p| indexed.get(p)).map(|x| x.1);
        let next = indexed.get(i + 1).map(|x| x.1);
        if is_suspicious_invisible_codepoint(ch as u32, byte_idx, prev, next) {
            let line = base_line + line_at_offset(raw, byte_idx).saturating_sub(1);
            let fp = fingerprint_match(
                "plugin-prompt-injection",
                &format!("{display}:unicode-smuggling"),
            );
            let kind = if is_prompt_doc {
                "Prompt file"
            } else {
                "Plugin script or config"
            };
            push_finding(
                out,
                seen_fp,
                McpFinding {
                    rule_id: "plugin-prompt-injection",
                    server_name: label.to_string(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    line,
                    severity: Severity::High,
                    fingerprint: fp,
                    message: format!(
                        "{kind} contains hidden bidirectional override, zero-width, Variation Selector, or Unicode tag smuggling characters"
                    ),
                },
            );
            return;
        }
    }
}

fn is_instruction_doc_file(path: &Path, file_name: &str) -> bool {
    if file_name.ends_with(".md")
        || file_name.ends_with(".mdc")
        || (file_name.ends_with(".txt") && !file_name.eq_ignore_ascii_case("LICENSE.txt"))
        || matches!(
            file_name,
            ".cursorrules" | ".windsurfrules" | ".clinerules" | ".roomodes"
        )
    {
        return true;
    }
    !has_script_extension(path)
        && path.extension().is_none()
        && path.components().any(|c| {
            matches!(
                c.as_os_str().to_str(),
                Some(".clinerules" | "rules" | "instructions" | "prompts")
            )
        })
}

fn push_finding(out: &mut Vec<McpFinding>, seen_fp: &mut HashSet<String>, finding: McpFinding) {
    if seen_fp.insert(finding.fingerprint.clone()) {
        out.push(finding);
    }
}

enum HookAction {
    Command(String),
    Http {
        url: String,
        allowed_env_vars: Vec<String>,
        headers_raw: String,
    },
    Prompt(String),
}

enum ResolvedScriptBody {
    InMemory(String),
    StreamedLargeFile,
    CompiledBinary,
}

fn infer_project_root<'a>(hooks_dir: &'a Path, plugin_root: &'a Path) -> &'a Path {
    let is_agent_dotdir = |p: &Path| {
        matches!(
            p.file_name().and_then(|s| s.to_str()),
            Some(
                ".claude"
                    | ".codex"
                    | ".cursor"
                    | ".gemini"
                    | ".agents"
                    | ".agent"
                    | ".vscode"
                    | ".continue"
                    | ".windsurf"
                    | ".roo"
                    | ".cline"
                    | ".junie"
                    | ".amazonq"
                    | ".kiro"
                    | ".augment"
                    | ".trae"
                    | ".zed"
            )
        )
    };
    if is_agent_dotdir(plugin_root) {
        plugin_root.parent().unwrap_or(plugin_root)
    } else if is_agent_dotdir(hooks_dir) {
        hooks_dir.parent().unwrap_or(hooks_dir)
    } else {
        plugin_root
    }
}

pub(crate) fn is_user_home_global_agent_path(path: &Path) -> bool {
    let Some(home) = crate::discovery::home_dir() else {
        return false;
    };
    let canon_home = home.canonicalize().unwrap_or_else(|_| home.clone());
    let canon_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    for base in [&home, &canon_home] {
        for cand in [path, canon_path.as_path()] {
            if let Ok(rel) = cand.strip_prefix(base) {
                if let Some(Component::Normal(first)) = rel.components().next() {
                    let s = first.to_string_lossy();
                    if matches!(
                        s.as_ref(),
                        ".claude"
                            | ".claude.json"
                            | ".codex"
                            | ".gemini"
                            | ".cursor"
                            | ".agents"
                            | ".agent"
                            | ".config"
                            | ".codeium"
                            | ".windsurf"
                            | ".clinerules"
                            | ".continue"
                            | "Library"
                            | "AppData"
                    ) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn is_workspace_hook_config(path: &Path, plugin_root: &Path) -> bool {
    if is_user_home_global_agent_path(path) {
        return false;
    }
    // Standalone plugin bundles (`plugin.json` / `.claude-plugin` / `.codex-plugin` / `gemini-extension.json`)
    // are expected to declare `hooks/hooks.json`; workspace `.claude/settings*.json`, `.gemini/settings*.json`,
    // and repo-level `.codex/hooks.json` / `.claude/hooks.json` are project configs.
    let is_plugin_bundle = plugin_root.join("plugin.json").is_file()
        || plugin_root.join("gemini-extension.json").is_file()
        || plugin_root.join(".claude-plugin").is_dir()
        || plugin_root.join(".codex-plugin").is_dir()
        || path.components().any(|c| {
            matches!(
                c,
                Component::Normal(s)
                    if matches!(s.to_str(), Some("plugins" | "extensions"))
            )
        });
    !is_plugin_bundle
}

fn is_pure_env_var_reference(s: &str) -> bool {
    let inner = if let Some(rest) = s.strip_prefix("${").and_then(|r| r.strip_suffix('}')) {
        rest
    } else if let Some(rest) = s.strip_prefix('$') {
        rest
    } else {
        return false;
    };
    let mut chars = inner.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn has_only_benign_node_options(val: &str) -> bool {
    let tokens = split_shell_tokens(val);
    if tokens.is_empty() {
        return true;
    }
    tokens.iter().all(|tok| {
        let lower = tok.to_ascii_lowercase();
        lower.starts_with("--max-old-space-size=")
            || lower.starts_with("--max-semi-space-size=")
            || lower.starts_with("--dns-result-order=")
            || matches!(
                lower.as_str(),
                "--no-warnings" | "--no-deprecation" | "--enable-source-maps" | "--ipv6first"
            )
    })
}

fn extract_helper_command(val: &Value) -> Option<&str> {
    if let Some(s) = val.as_str() {
        let t = s.trim();
        if !t.is_empty() {
            return Some(t);
        }
    } else if let Some(obj) = val.as_object() {
        if obj.get("enabled").and_then(|v| v.as_bool()) == Some(false) {
            return None;
        }
        if let Some(cmd) = obj.get("command").and_then(|v| v.as_str()) {
            let t = cmd.trim();
            if !t.is_empty() {
                return Some(t);
            }
        }
    }
    None
}

pub(crate) fn is_official_llm_api_host(host_port: &str) -> bool {
    if host_port.contains('@') {
        return false;
    }
    let host = host_port
        .split(':')
        .next()
        .unwrap_or(host_port)
        .to_ascii_lowercase();
    matches!(
        host.as_str(),
        "api.anthropic.com"
            | "api.openai.com"
            | "chatgpt.com"
            | "generativelanguage.googleapis.com"
            | "aiplatform.googleapis.com"
    ) || host.ends_with("-aiplatform.googleapis.com")
        || (host.starts_with("bedrock-runtime.") && host.ends_with(".amazonaws.com"))
}

pub(crate) fn is_official_llm_api_url(url: &str) -> bool {
    let trimmed = url.trim();
    if !trimmed.to_ascii_lowercase().starts_with("https://") {
        return false;
    }
    let Some(authority) = extract_url_authority(trimmed) else {
        return false;
    };
    is_official_llm_api_host(authority)
}

#[allow(clippy::too_many_arguments)]
fn audit_settings_env_overrides(
    path: &Path,
    display: &str,
    raw_file: &str,
    json: &Value,
    is_workspace_cfg: bool,
    engine: &RuleEngine,
    out: &mut Vec<McpFinding>,
    seen_fp: &mut HashSet<String>,
) {
    let Some(env_obj) = json.get("env").and_then(|v| v.as_object()) else {
        return;
    };
    audit_env_object_overrides(
        path,
        display,
        raw_file,
        env_obj,
        "settings:env",
        "Settings",
        is_workspace_cfg,
        true,
        engine,
        out,
        seen_fp,
    );
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn audit_env_object_overrides(
    path: &Path,
    display: &str,
    raw_file: &str,
    env_obj: &serde_json::Map<String, Value>,
    scope_prefix: &str,
    context_noun: &str,
    is_workspace_cfg: bool,
    check_generic_secrets: bool,
    engine: &RuleEngine,
    out: &mut Vec<McpFinding>,
    seen_fp: &mut HashSet<String>,
) {
    for (key, val_node) in env_obj {
        let owned_scalar;
        let Some(val) = (if let Some(s) = val_node.as_str() {
            Some(s)
        } else if val_node.is_number() || val_node.is_boolean() {
            owned_scalar = val_node.to_string();
            Some(owned_scalar.as_str())
        } else {
            None
        }) else {
            continue;
        };
        let trimmed = val.trim();
        if trimmed.is_empty() || is_pure_env_var_reference(trimmed) {
            continue;
        }

        let line = find_line_number(raw_file, key);
        let upper = key.to_ascii_uppercase();
        let server_label = format!("{scope_prefix}.{key}");

        // 1a. Check code-execution, dynamic linker, shell startup, & git binary hijack env vars
        let is_unconditional_code_exec_var = matches!(
            upper.as_str(),
            "BASH_ENV"
                | "ENV"
                | "ZDOTDIR"
                | "PROMPT_COMMAND"
                | "SHELLOPTS"
                | "BASHOPTS"
                | "LD_PRELOAD"
                | "LD_LIBRARY_PATH"
                | "LD_AUDIT"
                | "DYLD_INSERT_LIBRARIES"
                | "DYLD_LIBRARY_PATH"
                | "DYLD_FRAMEWORK_PATH"
                | "PYTHONPATH"
                | "PYTHONSTARTUP"
                | "PYTHONHOME"
                | "RUBYOPT"
                | "RUBYLIB"
                | "PERL5OPT"
                | "PERL5LIB"
                | "JAVA_TOOL_OPTIONS"
                | "JDK_JAVA_OPTIONS"
                | "DOTNET_STARTUP_HOOKS"
                | "GIT_SSH_COMMAND"
                | "GIT_EXEC_PATH"
                | "GIT_TEMPLATE_DIR"
                | "GIT_CONFIG_GLOBAL"
                | "GIT_CONFIG_SYSTEM"
                | "LESSOPEN"
        );
        let is_dangerous_node_opts =
            upper == "NODE_OPTIONS" && !has_only_benign_node_options(trimmed);
        let is_workspace_path_hijack = is_workspace_cfg
            && matches!(
                upper.as_str(),
                "PATH" | "EDITOR" | "VISUAL" | "PAGER" | "GIT_PAGER"
            );

        if is_unconditional_code_exec_var || is_dangerous_node_opts || is_workspace_path_hijack {
            let val_snip = truncate_snippet(trimmed, 64);
            let fp = fingerprint_match(
                "plugin-env-code-exec",
                &format!("{display}:{scope_prefix}:{key}:{trimmed}"),
            );
            push_finding(
                out,
                seen_fp,
                McpFinding {
                    rule_id: "plugin-env-code-exec",
                    server_name: server_label.clone(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    line,
                    severity: Severity::Critical,
                    fingerprint: fp,
                    message: format!(
                        "{context_noun} override process execution environment `{key}={val_snip}`, enabling arbitrary code or binary hijacking"
                    ),
                },
            );
        }

        // 1b. Check LLM API base URL, proxy, custom CA, and TLS-verification-disable overrides
        let is_llm_base_var = matches!(
            upper.as_str(),
            "ANTHROPIC_BASE_URL"
                | "ANTHROPIC_BEDROCK_BASE_URL"
                | "ANTHROPIC_VERTEX_BASE_URL"
                | "ANTHROPIC_FOUNDRY_BASE_URL"
                | "CLAUDE_CODE_API_BASE_URL"
                | "OPENAI_BASE_URL"
                | "OPENAI_API_BASE"
                | "AZURE_OPENAI_ENDPOINT"
                | "GOOGLE_GEMINI_BASE_URL"
                | "GEMINI_API_BASE_URL"
                | "VERTEX_BASE_URL"
        );
        if is_llm_base_var && !is_localhost_url(trimmed) && !is_official_llm_api_url(trimmed) {
            let host = extract_url_host(trimmed).unwrap_or(trimmed);
            let fp = fingerprint_match(
                "plugin-api-base-override",
                &format!("{display}:{scope_prefix}:{key}:{trimmed}"),
            );
            push_finding(
                out,
                seen_fp,
                McpFinding {
                    rule_id: "plugin-api-base-override",
                    server_name: server_label.clone(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    line,
                    severity: Severity::Critical,
                    fingerprint: fp,
                    message: format!(
                        "{context_noun} redirect `{key}` to external or unencrypted endpoint `{host}` (`{trimmed}`), routing prompts and API credentials through a third-party endpoint"
                    ),
                },
            );
        }

        let is_proxy_var = matches!(upper.as_str(), "HTTPS_PROXY" | "HTTP_PROXY" | "ALL_PROXY");
        if is_proxy_var && (!is_localhost_url(trimmed) || is_workspace_cfg) {
            let host = extract_url_host(trimmed).unwrap_or(trimmed);
            let sev = if is_localhost_url(trimmed) {
                Severity::High
            } else {
                Severity::Critical
            };
            let fp = fingerprint_match(
                "plugin-api-base-override",
                &format!("{display}:{scope_prefix}:{key}:{trimmed}"),
            );
            push_finding(
                out,
                seen_fp,
                McpFinding {
                    rule_id: "plugin-api-base-override",
                    server_name: server_label.clone(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    line,
                    severity: sev,
                    fingerprint: fp,
                    message: format!(
                        "{context_noun} route outbound CLI traffic through proxy `{key}` (`{host}`), enabling prompt/token interception"
                    ),
                },
            );
        }

        let is_tls_disable = (matches!(
            upper.as_str(),
            "NODE_TLS_REJECT_UNAUTHORIZED" | "PYTHONHTTPSVERIFY"
        ) && trimmed == "0")
            || (upper == "GIT_SSL_NO_VERIFY"
                && !matches!(trimmed.to_ascii_lowercase().as_str(), "0" | "false"));
        let is_custom_ca_var = matches!(
            upper.as_str(),
            "SSL_CERT_FILE"
                | "SSL_CERT_DIR"
                | "NODE_EXTRA_CA_CERTS"
                | "REQUESTS_CA_BUNDLE"
                | "CURL_CA_BUNDLE"
                | "DENO_CERT"
                | "GIT_SSL_CAINFO"
                | "CARGO_HTTP_CAINFO"
        ) && (is_workspace_cfg
            || (!trimmed.starts_with("/etc/ssl/") && !trimmed.starts_with("/etc/pki/")));

        if is_tls_disable || is_custom_ca_var {
            let val_snip = truncate_snippet(trimmed, 64);
            let fp = fingerprint_match(
                "plugin-api-base-override",
                &format!("{display}:{scope_prefix}:{key}:{trimmed}"),
            );
            push_finding(
                out,
                seen_fp,
                McpFinding {
                    rule_id: "plugin-api-base-override",
                    server_name: server_label.clone(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    line,
                    severity: Severity::Critical,
                    fingerprint: fp,
                    message: format!(
                        "{context_noun} override TLS trust or disable certificate verification (`{key}={val_snip}`), enabling MITM interception"
                    ),
                },
            );
        }

        // 2. Check OpenTelemetry exporter redirection to external endpoints
        if upper.starts_with("OTEL_EXPORTER_OTLP") && !is_localhost_url(trimmed) {
            let host = extract_url_host(trimmed).unwrap_or(trimmed);
            let fp = fingerprint_match(
                "plugin-telemetry-endpoint",
                &format!("{display}:{scope_prefix}:{key}:{trimmed}"),
            );
            push_finding(
                out,
                seen_fp,
                McpFinding {
                    rule_id: "plugin-telemetry-endpoint",
                    server_name: server_label.clone(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    line,
                    severity: Severity::High,
                    fingerprint: fp,
                    message: format!(
                        "{context_noun} export OpenTelemetry traces/logs (`{key}`) to external host `{host}` (`{trimmed}`)"
                    ),
                },
            );
        }

        if !check_generic_secrets {
            continue;
        }

        // 3. Check hardcoded high-entropy secrets assigned to sensitive env keys (e.g. CUSTOM_API_KEY)
        let matches = engine.scan_text_for_path(trimmed, Some(path));
        if matches.iter().any(|m| m.category == RuleCategory::Secret) {
            continue; // Caught by file-level `check_hardcoded_secrets` with exact rule name
        }
        let is_non_secret = upper.contains("PUBLIC_KEY")
            || upper.contains("PUBKEY")
            || upper.contains("BASE_URL")
            || upper.contains("ENDPOINT");
        let looks_sensitive = !is_non_secret
            && (upper.contains("SECRET")
                || upper.contains("TOKEN")
                || upper.contains("PASSWORD")
                || upper.contains("API_KEY")
                || upper.contains("PRIVATE_KEY")
                || upper.contains("ACCESS_KEY")
                || upper.ends_with("_KEY"));
        if looks_sensitive
            && trimmed.len() >= 16
            && !crate::rules::is_likely_placeholder(trimmed)
            && crate::rules::shannon_entropy(trimmed) >= 3.75
        {
            let masked = crate::rules::mask_value("dotenv-generic-secret", trimmed);
            let fp = fingerprint_match(
                "plugin-hardcoded-secret",
                &format!("{display}:{scope_prefix}:{key}:{trimmed}"),
            );
            push_finding(
                out,
                seen_fp,
                McpFinding {
                    rule_id: "plugin-hardcoded-secret",
                    server_name: server_label,
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    line,
                    severity: Severity::Critical,
                    fingerprint: fp,
                    message: format!("Hardcoded secret (`{masked}`) stored in `{key}`"),
                },
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn audit_hooks_config(
    disk_path: &Path,
    path: &Path,
    sandbox_remap: Option<(&Path, &Path)>,
    display: &str,
    label: &str,
    raw_hooks_file: &str,
    json: &Value,
    is_dedicated_hooks_file: bool,
    engine: &RuleEngine,
    out: &mut Vec<McpFinding>,
    seen_fp: &mut HashSet<String>,
) {
    let hooks_dir = disk_path.parent().unwrap_or_else(|| Path::new("."));
    let plugin_root = if hooks_dir.file_name().and_then(|s| s.to_str()) == Some("hooks") {
        hooks_dir.parent().unwrap_or(hooks_dir)
    } else {
        hooks_dir
    };
    let project_root = infer_project_root(hooks_dir, plugin_root);

    let logical_hooks_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let logical_plugin_root =
        if logical_hooks_dir.file_name().and_then(|s| s.to_str()) == Some("hooks") {
            logical_hooks_dir.parent().unwrap_or(logical_hooks_dir)
        } else {
            logical_hooks_dir
        };
    let is_workspace_cfg = is_workspace_hook_config(path, logical_plugin_root);

    audit_settings_env_overrides(
        path,
        display,
        raw_hooks_file,
        json,
        is_workspace_cfg,
        engine,
        out,
        seen_fp,
    );

    let mut entries = Vec::new();
    extract_hook_entries(json, is_dedicated_hooks_file, &mut entries);

    // Inspect helper command hooks in Claude `settings.json` / `settings.local.json`
    // (`apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, `otelHeadersHelper`, `statusLine`, `fileSuggestion`)
    for &helper_key in SETTINGS_HELPER_KEYS {
        if let Some(val) = json.get(helper_key) {
            if let Some(helper_cmd) = extract_helper_command(val) {
                entries.push((
                    helper_key.to_string(),
                    HookAction::Command(helper_cmd.to_string()),
                ));
            }
        }
    }

    for (event_name, action) in entries {
        let hook_line = find_line_number(raw_hooks_file, &event_name);
        let hook_label = if label == "hooks" || label == "settings-hooks" {
            format!("hook:{event_name}")
        } else {
            label.to_string()
        };

        match action {
            HookAction::Command(cmd) => {
                if is_workspace_cfg {
                    let cmd_snip = truncate_snippet(&cmd, 64);
                    let fp = fingerprint_match(
                        "plugin-workspace-hook-exec",
                        &format!("{display}:{event_name}:{cmd}"),
                    );
                    push_finding(
                        out,
                        seen_fp,
                        McpFinding {
                            rule_id: "plugin-workspace-hook-exec",
                            server_name: hook_label.clone(),
                            config_file: display.to_string(),
                            config_path: path.to_path_buf(),
                            line: hook_line,
                            severity: Severity::Medium,
                            fingerprint: fp,
                            message: format!(
                                "Workspace config registers automatic shell command for `{event_name}` (`{cmd_snip}`) — opening this project can execute repo-controlled code"
                            ),
                        },
                    );
                }

                check_unicode_smuggling(
                    path,
                    display,
                    &hook_label,
                    &cmd,
                    false,
                    hook_line,
                    out,
                    seen_fp,
                );
                let cmd = strip_invisible_unicode(&cmd);

                check_remote_code_exec(
                    path,
                    display,
                    &hook_label,
                    &cmd,
                    false,
                    hook_line,
                    out,
                    seen_fp,
                );
                check_credential_harvest(
                    path,
                    display,
                    &hook_label,
                    &cmd,
                    false,
                    hook_line,
                    out,
                    seen_fp,
                );
                check_env_and_secret_exfiltration(
                    path,
                    display,
                    &hook_label,
                    &cmd,
                    false,
                    hook_line,
                    out,
                    seen_fp,
                );
                check_hardcoded_secrets(
                    path,
                    display,
                    &hook_label,
                    &cmd,
                    hook_line,
                    engine,
                    out,
                    seen_fp,
                );

                if let Some(target_desc) = detect_external_network_call(&cmd) {
                    let fp = fingerprint_match(
                        "plugin-hook-network",
                        &format!("{display}:{event_name}:{cmd}"),
                    );
                    push_finding(
                        out,
                        seen_fp,
                        McpFinding {
                            rule_id: "plugin-hook-network",
                            server_name: hook_label.clone(),
                            config_file: display.to_string(),
                            config_path: path.to_path_buf(),
                            line: hook_line,
                            severity: Severity::High,
                            fingerprint: fp,
                            message: format!(
                                "Lifecycle hook `{event_name}` makes an outbound network call ({target_desc}) automatically"
                            ),
                        },
                    );
                }

                // Resolve and fully audit every local handler script or binary referenced by the hook command
                for (script_path, script_rel, resolved_body) in resolve_hook_handler_scripts(
                    &cmd,
                    hooks_dir,
                    plugin_root,
                    project_root,
                    sandbox_remap,
                ) {
                    let logical_script_path = if let Some((sandbox_root, repo_root)) = sandbox_remap
                    {
                        let canon_sandbox = sandbox_root
                            .canonicalize()
                            .unwrap_or_else(|_| sandbox_root.to_path_buf());
                        script_path
                            .strip_prefix(&canon_sandbox)
                            .or_else(|_| script_path.strip_prefix(sandbox_root))
                            .map(|r| repo_root.join(r))
                            .unwrap_or_else(|_| script_path.clone())
                    } else {
                        script_path.clone()
                    };
                    let script_display = shorten_home(&logical_script_path);
                    let net_target = match resolved_body {
                        ResolvedScriptBody::InMemory(raw_script_body) => {
                            let script_label =
                                component_label(&logical_script_path, &raw_script_body);
                            check_unicode_smuggling(
                                &logical_script_path,
                                &script_display,
                                &script_label,
                                &raw_script_body,
                                false,
                                1,
                                out,
                                seen_fp,
                            );
                            let script_body = strip_invisible_unicode(&raw_script_body);
                            check_remote_code_exec(
                                &logical_script_path,
                                &script_display,
                                &script_label,
                                &script_body,
                                false,
                                1,
                                out,
                                seen_fp,
                            );
                            check_credential_harvest(
                                &logical_script_path,
                                &script_display,
                                &script_label,
                                &script_body,
                                false,
                                1,
                                out,
                                seen_fp,
                            );
                            check_env_and_secret_exfiltration(
                                &logical_script_path,
                                &script_display,
                                &script_label,
                                &script_body,
                                false,
                                1,
                                out,
                                seen_fp,
                            );
                            check_hardcoded_secrets(
                                &logical_script_path,
                                &script_display,
                                &script_label,
                                &script_body,
                                1,
                                engine,
                                out,
                                seen_fp,
                            );
                            check_telemetry_domains(
                                &logical_script_path,
                                &script_display,
                                &script_label,
                                &script_body,
                                1,
                                out,
                                seen_fp,
                            );
                            detect_external_network_call(&script_body)
                        }
                        ResolvedScriptBody::StreamedLargeFile => audit_streamed_plugin_file(
                            &script_path,
                            &logical_script_path,
                            &script_display,
                            false,
                            engine,
                            out,
                            seen_fp,
                        ),
                        ResolvedScriptBody::CompiledBinary => audit_compiled_binary_file(
                            &script_path,
                            &logical_script_path,
                            &script_display,
                            &hook_label,
                            hook_line,
                            engine,
                            out,
                            seen_fp,
                        ),
                    };

                    if let Some(target_desc) = net_target {
                        let fp = fingerprint_match(
                            "plugin-hook-network",
                            &format!("{display}:{event_name}:{script_rel}"),
                        );
                        push_finding(
                            out,
                            seen_fp,
                            McpFinding {
                                rule_id: "plugin-hook-network",
                                server_name: hook_label.clone(),
                                config_file: display.to_string(),
                                config_path: path.to_path_buf(),
                                line: hook_line,
                                severity: Severity::High,
                                fingerprint: fp,
                                message: format!(
                                    "Lifecycle hook `{event_name}` runs handler `{script_rel}` with an outbound network call ({target_desc})"
                                ),
                            },
                        );
                    }
                }
            }
            HookAction::Http {
                url,
                allowed_env_vars,
                headers_raw,
            } => {
                let url_line = find_line_number(raw_hooks_file, &url).max(hook_line);
                check_hardcoded_secrets(
                    path,
                    display,
                    &hook_label,
                    &url,
                    url_line,
                    engine,
                    out,
                    seen_fp,
                );
                if !headers_raw.is_empty() {
                    check_hardcoded_secrets(
                        path,
                        display,
                        &hook_label,
                        &headers_raw,
                        hook_line,
                        engine,
                        out,
                        seen_fp,
                    );
                }
                if !is_localhost_url(&url) {
                    let host = extract_url_host(&url).unwrap_or(&url);
                    let is_plaintext_http = url.to_ascii_lowercase().starts_with("http://");
                    let forwards_env = !allowed_env_vars.is_empty();
                    let sev = if is_plaintext_http || forwards_env {
                        Severity::Critical
                    } else {
                        Severity::High
                    };
                    let env_note = if forwards_env {
                        format!(" and forwards env var(s) [{}]", allowed_env_vars.join(", "))
                    } else {
                        String::new()
                    };
                    let fp = fingerprint_match(
                        "plugin-hook-network",
                        &format!("{display}:{event_name}:http:{url}"),
                    );
                    push_finding(
                        out,
                        seen_fp,
                        McpFinding {
                            rule_id: "plugin-hook-network",
                            server_name: hook_label,
                            config_file: display.to_string(),
                            config_path: path.to_path_buf(),
                            line: url_line,
                            severity: sev,
                            fingerprint: fp,
                            message: format!(
                                "Lifecycle HTTP webhook `{event_name}` posts session/tool events to `{host}` (`{url}`){env_note}"
                            ),
                        },
                    );
                }
            }
            HookAction::Prompt(raw_prompt_body) => {
                check_unicode_smuggling(
                    path,
                    display,
                    &hook_label,
                    &raw_prompt_body,
                    true,
                    hook_line,
                    out,
                    seen_fp,
                );
                let prompt_body = strip_invisible_unicode(&raw_prompt_body);
                check_prompt_injection(
                    path,
                    display,
                    &hook_label,
                    &prompt_body,
                    hook_line,
                    out,
                    seen_fp,
                );
                check_remote_code_exec(
                    path,
                    display,
                    &hook_label,
                    &prompt_body,
                    true,
                    hook_line,
                    out,
                    seen_fp,
                );
                check_credential_harvest(
                    path,
                    display,
                    &hook_label,
                    &prompt_body,
                    true,
                    hook_line,
                    out,
                    seen_fp,
                );
                check_env_and_secret_exfiltration(
                    path,
                    display,
                    &hook_label,
                    &prompt_body,
                    true,
                    hook_line,
                    out,
                    seen_fp,
                );
                check_hardcoded_secrets(
                    path,
                    display,
                    &hook_label,
                    &prompt_body,
                    hook_line,
                    engine,
                    out,
                    seen_fp,
                );
            }
        }
    }
}

fn extract_hook_entries(
    json: &Value,
    is_dedicated_hooks_file: bool,
    out: &mut Vec<(String, HookAction)>,
) {
    if let Some(hooks_obj) = json.get("hooks").and_then(|v| v.as_object()) {
        for (event_key, val) in hooks_obj {
            collect_actions_from_hook_value(event_key, val, out);
        }
    }

    if !is_dedicated_hooks_file {
        return;
    }

    let Some(root_obj) = json.as_object() else {
        return;
    };

    for (top_key, top_val) in root_obj {
        if matches!(
            top_key.as_str(),
            "hooks" | "$schema" | "description" | "version" | "enabled"
        ) {
            continue;
        }

        if HOOK_EVENTS.iter().any(|e| e.eq_ignore_ascii_case(top_key)) {
            collect_actions_from_hook_value(top_key, top_val, out);
            continue;
        }

        if let Some(named_group) = top_val.as_object() {
            if named_group.get("enabled").and_then(|v| v.as_bool()) == Some(false) {
                continue;
            }
            for (k, v) in named_group {
                if HOOK_EVENTS.iter().any(|e| e.eq_ignore_ascii_case(k)) {
                    collect_actions_from_hook_value(k, v, out);
                }
            }
        }
    }
}

fn collect_actions_from_hook_value(
    event_label: &str,
    val: &Value,
    out: &mut Vec<(String, HookAction)>,
) {
    match val {
        Value::String(s) => out.push((event_label.to_string(), HookAction::Command(s.clone()))),
        Value::Object(map) => {
            if map.get("enabled").and_then(|v| v.as_bool()) == Some(false) {
                return;
            }
            if let Some(cmd) = map.get("command").and_then(|v| v.as_str()) {
                out.push((
                    event_label.to_string(),
                    HookAction::Command(cmd.to_string()),
                ));
            }
            if let Some(url) = map.get("url").and_then(|v| v.as_str()) {
                let allowed_env_vars = map
                    .get("allowedEnvVars")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                let headers_raw = map.get("headers").map(Value::to_string).unwrap_or_default();
                out.push((
                    event_label.to_string(),
                    HookAction::Http {
                        url: url.to_string(),
                        allowed_env_vars,
                        headers_raw,
                    },
                ));
            }
            if let Some(prompt) = map.get("prompt").and_then(|v| v.as_str()) {
                out.push((
                    event_label.to_string(),
                    HookAction::Prompt(prompt.to_string()),
                ));
            }
            if let Some(nested) = map.get("hooks") {
                collect_actions_from_hook_value(event_label, nested, out);
            }
        }
        Value::Array(arr) => {
            for item in arr {
                collect_actions_from_hook_value(event_label, item, out);
            }
        }
        _ => {}
    }
}

fn resolve_hook_handler_scripts(
    cmd: &str,
    hooks_dir: &Path,
    plugin_root: &Path,
    project_root: &Path,
    sandbox_remap: Option<(&Path, &Path)>,
) -> Vec<(PathBuf, String, ResolvedScriptBody)> {
    let mut results = Vec::new();
    let mut seen_paths = HashSet::new();
    let plugin_root_str = plugin_root.to_string_lossy();
    let project_root_str = project_root.to_string_lossy();
    let canon_sandbox =
        sandbox_remap.map(|(sb, _)| fs::canonicalize(sb).unwrap_or_else(|_| sb.to_path_buf()));

    for raw_tok in split_shell_tokens(cmd) {
        let tok = raw_tok.trim_matches(|c| c == '"' || c == '\'' || c == ';');
        if tok.is_empty()
            || tok.starts_with('-')
            || tok.starts_with("http://")
            || tok.starts_with("https://")
            || matches!(tok, "&&" | "||" | "|")
        {
            continue;
        }

        let expanded = tok
            .replace("${CLAUDE_PLUGIN_ROOT}", &plugin_root_str)
            .replace("$CLAUDE_PLUGIN_ROOT", &plugin_root_str)
            .replace("${PLUGIN_ROOT}", &plugin_root_str)
            .replace("$PLUGIN_ROOT", &plugin_root_str)
            .replace("${CLAUDE_PROJECT_DIR}", &project_root_str)
            .replace("$CLAUDE_PROJECT_DIR", &project_root_str)
            .replace("${PROJECT_DIR}", &project_root_str)
            .replace("$PROJECT_DIR", &project_root_str)
            .replace("${WORKSPACE_FOLDER}", &project_root_str)
            .replace("$WORKSPACE_FOLDER", &project_root_str)
            .replace("${workspaceFolder}", &project_root_str)
            .replace("$workspaceFolder", &project_root_str);

        let exp_path = Path::new(&expanded);
        if !has_script_extension(exp_path) && is_known_runtime_binary_name(exp_path) {
            continue;
        }

        let looks_like_script =
            expanded.contains('/') || expanded.contains('\\') || has_script_extension(exp_path);
        if !looks_like_script {
            continue;
        }

        let mut candidate_paths = Vec::with_capacity(4);
        if sandbox_remap.is_none() || Path::new(&expanded).starts_with(project_root) {
            candidate_paths.push(PathBuf::from(&expanded));
        }
        let rel_expanded = expanded.trim_start_matches(['/', '\\']);
        candidate_paths.push(hooks_dir.join(&expanded));
        candidate_paths.push(plugin_root.join(&expanded));
        candidate_paths.push(project_root.join(&expanded));
        if sandbox_remap.is_some() && Path::new(&expanded).is_absolute() && !rel_expanded.is_empty()
        {
            candidate_paths.push(project_root.join(rel_expanded));
        }

        for cand in candidate_paths {
            if let Ok(meta) = fs::metadata(&cand) {
                if meta.is_file() && meta.len() <= MAX_STREAM_PLUGIN_BYTES {
                    let canon = fs::canonicalize(&cand).unwrap_or_else(|_| cand.clone());
                    if let Some(ref sb_root) = canon_sandbox {
                        if !canon.starts_with(sb_root) {
                            continue;
                        }
                    }
                    let rel = cand
                        .strip_prefix(project_root)
                        .or_else(|_| cand.strip_prefix(plugin_root))
                        .unwrap_or(&cand)
                        .to_string_lossy()
                        .into_owned();
                    if crate::discovery::is_compiled_binary_file(&cand)
                        || is_likely_compiled_binary(&cand)
                    {
                        if is_non_system_binary_path(&cand) && seen_paths.insert(canon) {
                            results.push((cand, rel, ResolvedScriptBody::CompiledBinary));
                        }
                        break;
                    }
                    if !seen_paths.insert(canon) {
                        break;
                    }
                    if meta.len() <= MAX_PLUGIN_FILE_BYTES {
                        if let Ok(body) =
                            crate::scanner::read_text_auto_encoding(&cand, MAX_PLUGIN_FILE_BYTES)
                        {
                            results.push((cand, rel, ResolvedScriptBody::InMemory(body)));
                            break;
                        }
                    } else {
                        results.push((cand, rel, ResolvedScriptBody::StreamedLargeFile));
                        break;
                    }
                }
            }
        }
    }
    results
}

fn split_shell_tokens(cmd: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut chars = cmd.chars();

    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            if c == '\\' {
                if let Some(next_c) = chars.next() {
                    cur.push(next_c);
                }
            } else if c == q {
                quote = None;
            } else {
                cur.push(c);
            }
            continue;
        }

        if c == '"' || c == '\'' {
            quote = Some(c);
        } else if c.is_ascii_whitespace() {
            if !cur.is_empty() {
                tokens.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(c);
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

pub fn detect_external_network_call(text: &str) -> Option<String> {
    let code = collapse_adjacent_string_literals(&strip_code_comments(text));
    let re = plugin_regexes();
    let valid_matches: Vec<(usize, usize)> = re
        .net_call
        .find_iter(&code)
        .filter(|m| !is_false_positive_cli_net_token(&code, m.start(), m.end()))
        .map(|m| (m.start(), m.end()))
        .collect();
    if valid_matches.is_empty() {
        return None;
    }

    // 1. If any explicit non-localhost URL appears in active code alongside a real network call, report that host
    for m in re.url_extract.find_iter(&code) {
        let u = m.as_str();
        if !is_localhost_url(u) {
            let host = extract_url_host(u).unwrap_or(u);
            return Some(format!("`{host}`"));
        }
    }

    // 2. Check each individual network call site so a dummy `http://localhost` variable elsewhere
    // cannot mask an un-schemed `curl evil.io/ldr`, `https.get({hostname: 'evil.io'})`, or `socket.connect`.
    for (m_start, m_end) in valid_matches {
        let line_start = code[..m_start].rfind('\n').map_or(0, |i| i + 1);
        let window_end = (m_end + 220).min(code.len());
        let mut safe_end = window_end;
        while safe_end < code.len() && !code.is_char_boundary(safe_end) {
            safe_end += 1;
        }
        let call_window = &code[line_start..safe_end];
        if !call_window_targets_localhost_only(call_window) {
            let matched = code[m_start..m_end].trim().trim_end_matches('(');
            return Some(format!("via `{matched}`"));
        }
    }

    None
}

fn call_window_targets_localhost_only(window: &str) -> bool {
    let re = plugin_regexes();
    let urls: Vec<&str> = re
        .url_extract
        .find_iter(window)
        .map(|m| m.as_str())
        .collect();
    if !urls.is_empty() {
        return urls.iter().all(|u| is_localhost_url(u));
    }
    let lower = window.to_ascii_lowercase();
    if lower.contains('@') {
        return false;
    }
    if let Some(pos) = lower.find("antigravity_ls_address") {
        let before = &lower[..pos];
        let in_query = before.ends_with('?')
            || before.ends_with('&')
            || before.ends_with('=')
            || before.ends_with("${") && before[..before.len() - 2].ends_with(['?', '&', '=']);
        if !in_query {
            return true;
        }
    }
    lower.contains("\"localhost\"")
        || lower.contains("'localhost'")
        || lower.contains("\"127.0.0.1\"")
        || lower.contains("'127.0.0.1'")
        || lower.contains("\"::1\"")
        || lower.contains("'::1'")
}

fn extract_url_authority(url: &str) -> Option<&str> {
    let trimmed = url
        .trim()
        .trim_matches(['"', '\'', '`', ')', ']', '>', ',', ';']);
    let after_scheme = if let Some((scheme, rest)) = trimmed.split_once("://") {
        if !matches!(
            scheme.to_ascii_lowercase().as_str(),
            "http" | "https" | "ws" | "wss"
        ) {
            return None;
        }
        rest
    } else if trimmed
        .to_ascii_lowercase()
        .starts_with("${antigravity_ls_address}")
    {
        trimmed
    } else {
        return None;
    };
    let authority = after_scheme.split(['/', '?', '#', '\\']).next()?;
    if authority.is_empty() {
        None
    } else {
        Some(authority)
    }
}

pub fn is_localhost_url(url: &str) -> bool {
    let Some(authority) = extract_url_authority(url) else {
        return false;
    };
    // Reject RFC 3986 userinfo (`http://localhost@attacker.com`) completely
    if authority.contains('@') {
        return false;
    }

    let lower_auth = authority.to_ascii_lowercase();
    if lower_auth == "${antigravity_ls_address}" {
        return true;
    }
    if let Some(port_part) = lower_auth.strip_prefix("${antigravity_ls_address}:") {
        return port_part.parse::<u16>().is_ok()
            || (port_part.starts_with("${") && port_part.ends_with('}'));
    }

    if let Some(after_open) = authority.strip_prefix('[') {
        let Some((ipv6_str, rest)) = after_open.split_once(']') else {
            return false;
        };
        if !rest.is_empty() {
            let Some(port_str) = rest.strip_prefix(':') else {
                return false;
            };
            if port_str.parse::<u16>().is_err() {
                return false;
            }
        }
        return ipv6_str.parse::<std::net::Ipv6Addr>().is_ok_and(|addr| {
            addr.is_loopback() || addr.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        });
    }

    if authority.contains('[') || authority.contains(']') {
        return false;
    }

    let host = if let Some((h, port_str)) = authority.split_once(':') {
        if port_str.contains(':') || port_str.parse::<u16>().is_err() {
            return false;
        }
        h
    } else {
        authority
    };

    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn extract_url_host(url: &str) -> Option<&str> {
    let authority = extract_url_authority(url)?;
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn fold_backslash_continuations(raw: &str) -> (String, Vec<usize>) {
    let mut out = String::with_capacity(raw.len());
    let mut line_map = Vec::new();
    let mut orig_line = 1usize;
    let mut continuing = false;

    for seg in raw.split_inclusive('\n') {
        let has_nl = seg.ends_with('\n');
        let no_nl = seg.trim_end_matches(['\n', '\r']);
        if !continuing {
            line_map.push(orig_line);
        }
        let trailing_bs = no_nl.bytes().rev().take_while(|&b| b == b'\\').count();
        if has_nl && trailing_bs % 2 == 1 {
            out.push_str(&no_nl[..no_nl.len() - 1]);
            continuing = true;
        } else {
            out.push_str(no_nl);
            if has_nl {
                out.push('\n');
            }
            continuing = false;
        }
        if has_nl {
            orig_line += 1;
        }
    }
    if line_map.is_empty() {
        line_map.push(1);
    }
    (out, line_map)
}

fn map_folded_line(line_map: &[usize], folded_one_based_line: usize) -> usize {
    line_map
        .get(folded_one_based_line.saturating_sub(1))
        .copied()
        .or_else(|| line_map.last().copied())
        .unwrap_or(1)
}

fn scan_single_quoted_literal(s: &str, start: usize) -> Option<(String, usize)> {
    let bytes = s.as_bytes();
    let quote = *bytes.get(start)?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    let mut inner = String::new();
    let mut idx = start + 1;
    let max_end = (start + 512).min(bytes.len());
    while idx < max_end {
        let ch = s[idx..].chars().next()?;
        let clen = ch.len_utf8();
        if ch == '\n' || ch == '\r' {
            return None;
        }
        if ch == '\\' {
            let next_idx = idx + clen;
            let next_ch = s.get(next_idx..)?.chars().next()?;
            if next_ch == '\n' || next_ch == '\r' {
                return None;
            }
            if next_ch == '"' || next_ch == '\'' {
                inner.push(next_ch);
            } else {
                inner.push('\\');
                inner.push(next_ch);
            }
            idx = next_idx + next_ch.len_utf8();
            continue;
        }
        if ch as u8 == quote && clen == 1 {
            return Some((inner, idx + 1));
        }
        inner.push(ch);
        idx += clen;
    }
    None
}

fn extract_comma_joined_string_items(items_raw: &str) -> Option<String> {
    let mut acc = String::new();
    for part in items_raw.split(',') {
        let t = part.trim();
        if t.is_empty() {
            continue;
        }
        let q = t.as_bytes()[0];
        if (q != b'"' && q != b'\'') || t.len() < 2 || t.as_bytes()[t.len() - 1] != q {
            return None;
        }
        acc.push_str(&t[1..t.len() - 1]);
    }
    if acc.is_empty() {
        None
    } else {
        Some(acc)
    }
}

fn collapse_array_char_joins(raw: &str) -> String {
    if !raw.contains("join") {
        return raw.to_string();
    }
    let re = plugin_regexes();
    let after_py = re.py_empty_join.replace_all(raw, |caps: &regex::Captures| {
        if let Some(joined) = caps
            .get(1)
            .and_then(|m| extract_comma_joined_string_items(m.as_str()))
        {
            format!("\"{joined}\"")
        } else {
            caps[0].to_string()
        }
    });
    re.js_empty_join
        .replace_all(&after_py, |caps: &regex::Captures| {
            if let Some(joined) = caps
                .get(1)
                .and_then(|m| extract_comma_joined_string_items(m.as_str()))
            {
                format!("\"{joined}\"")
            } else {
                caps[0].to_string()
            }
        })
        .into_owned()
}

/// Folds adjacent string-literal concatenations (`"sys" + "tem"` -> `"system"`,
/// `'child_' + 'process'` -> `'child_process'`, and `"".join(["s","y","s"])` -> `"sys"`)
/// while preserving exact `\n` counts so downstream line numbers remain accurate.
pub(crate) fn collapse_adjacent_string_literals(raw: &str) -> String {
    let joined = collapse_array_char_joins(raw);
    if !joined.contains('+') {
        return joined;
    }
    let bytes = joined.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0usize;

    while i < len {
        let ch = joined[i..].chars().next().expect("valid utf8");
        if ch != '"' && ch != '\'' {
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        if i + 2 < len && bytes[i + 1] == ch as u8 && bytes[i + 2] == ch as u8 {
            out.push(ch);
            out.push(ch);
            out.push(ch);
            i += 3;
            continue;
        }
        let open_quote = ch;
        let Some((first_inner, after_first)) = scan_single_quoted_literal(&joined, i) else {
            out.push(ch);
            i += ch.len_utf8();
            continue;
        };

        let mut merged_inner = first_inner;
        let mut cursor = after_first;
        let mut trailing_newlines = 0usize;
        let mut did_merge = false;

        loop {
            let mut probe = cursor;
            let mut nl_here = 0usize;
            while probe < len {
                match bytes[probe] {
                    b' ' | b'\t' | b'\r' => probe += 1,
                    b'\n' => {
                        nl_here += 1;
                        probe += 1;
                    }
                    _ => break,
                }
            }
            if probe >= len || bytes[probe] != b'+' {
                break;
            }
            probe += 1;
            if probe < len && (bytes[probe] == b'=' || bytes[probe] == b'+') {
                break;
            }
            while probe < len {
                match bytes[probe] {
                    b' ' | b'\t' | b'\r' => probe += 1,
                    b'\n' => {
                        nl_here += 1;
                        probe += 1;
                    }
                    _ => break,
                }
            }
            if probe >= len || (bytes[probe] != b'"' && bytes[probe] != b'\'') {
                break;
            }
            let q2 = bytes[probe];
            if probe + 2 < len && bytes[probe + 1] == q2 && bytes[probe + 2] == q2 {
                break;
            }
            let Some((next_inner, after_next)) = scan_single_quoted_literal(&joined, probe) else {
                break;
            };
            merged_inner.push_str(&next_inner);
            trailing_newlines += nl_here;
            cursor = after_next;
            did_merge = true;
        }

        if did_merge {
            out.push(open_quote);
            for mc in merged_inner.chars() {
                if mc == open_quote {
                    out.push('\\');
                }
                out.push(mc);
            }
            out.push(open_quote);
            for _ in 0..trailing_newlines {
                out.push('\n');
            }
            i = cursor;
        } else {
            out.push_str(&joined[i..after_first]);
            i = after_first;
        }
    }
    out
}

pub fn decode_powershell_encoded_commands(text: &str) -> Vec<(usize, String)> {
    let re = plugin_regexes();
    let mut out = Vec::new();
    for caps in re.ps_encoded_cmd.captures_iter(text) {
        let Some(b64_m) = caps.get(1) else {
            continue;
        };
        let b64_str = b64_m.as_str();
        let trimmed = b64_str.trim_end_matches('=');
        let decoded_opt = base64::engine::general_purpose::STANDARD
            .decode(b64_str)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed))
            .ok();
        let Some(bytes) = decoded_opt else {
            continue;
        };
        if bytes.len() < 8 || bytes.len() > 32 * 1024 {
            continue;
        }
        let script_opt =
            if bytes.len().is_multiple_of(2) && bytes.iter().skip(1).step_by(2).any(|&b| b == 0) {
                let u16s: Vec<u16> = bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|&[b0, b1]| u16::from_le_bytes([b0, b1]))
                    .collect();
                String::from_utf16(&u16s).ok()
            } else {
                String::from_utf8(bytes).ok()
            };
        if let Some(script) = script_opt {
            let printable = script
                .chars()
                .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                .count();
            let total = script.chars().count().max(1);
            if printable * 10 >= total * 8 {
                let ln = line_at_offset(text, caps.get(0).map_or(b64_m.start(), |m| m.start()));
                out.push((ln, script));
            }
        }
    }
    out
}

pub fn detect_inline_rce(raw: &str) -> Option<String> {
    let (folded, _) = fold_backslash_continuations(raw);
    let collapsed = collapse_adjacent_string_literals(&folded);
    let re = plugin_regexes();
    if let Some(m) = re
        .pipe_to_shell
        .find(&collapsed)
        .or_else(|| re.ps_download_exec.find(&collapsed))
        .or_else(|| re.base64_exec.find(&collapsed))
        .or_else(|| re.eval_net.find(&collapsed))
        .or_else(|| re.dynamic_code_exec.find(&collapsed))
        .or_else(|| re.reflective_code_exec.find(&collapsed))
        .or_else(|| re.download_then_exec.find(&collapsed))
    {
        return Some(truncate_snippet(m.as_str().trim(), 64));
    }
    for (_, decoded_ps) in decode_powershell_encoded_commands(&folded) {
        let dec_collapsed = collapse_adjacent_string_literals(&decoded_ps);
        if let Some(m) = re
            .ps_download_exec
            .find(&dec_collapsed)
            .or_else(|| re.pipe_to_shell.find(&dec_collapsed))
            .or_else(|| re.dynamic_code_exec.find(&dec_collapsed))
            .or_else(|| re.reflective_code_exec.find(&dec_collapsed))
            .or_else(|| re.download_then_exec.find(&dec_collapsed))
        {
            return Some(format!(
                "EncodedCommand: {}",
                truncate_snippet(m.as_str().trim(), 48)
            ));
        }
    }
    None
}

fn extract_download_output_target(cmd_segment: &str) -> Option<String> {
    let tokens = split_shell_tokens(cmd_segment);
    if tokens.is_empty() {
        return None;
    }
    let mut remote_name_flag = false;
    let mut url_basename: Option<String> = None;
    let mut idx = 0usize;
    while idx < tokens.len() {
        let tok = tokens[idx].as_str();
        if let Some(val) = tok
            .strip_prefix("--output=")
            .or_else(|| tok.strip_prefix("--output-document="))
            .or_else(|| {
                tok.strip_prefix("-o")
                    .filter(|v| !v.is_empty() && !tok.starts_with("--"))
            })
            .or_else(|| {
                tok.strip_prefix("-O")
                    .filter(|v| !v.is_empty() && !tok.starts_with("--"))
            })
        {
            let cleaned = val.trim_matches(['"', '\'', '`']);
            if cleaned.len() >= 2 && cleaned != "-" && !cleaned.starts_with("/dev/") {
                return Some(cleaned.to_string());
            }
        }
        if matches!(
            tok,
            "-o" | "--output" | "--output-document" | "-OutFile" | "-outfile"
        ) || (tok.starts_with('-')
            && !tok.starts_with("--")
            && tok.len() >= 2
            && (tok.ends_with('o')
                || (tok.ends_with('O') && cmd_segment.to_ascii_lowercase().contains("wget"))))
        {
            if let Some(next_tok) = tokens.get(idx + 1) {
                let cleaned = next_tok.trim_matches(['"', '\'', '`']);
                if !cleaned.starts_with('-')
                    && cleaned.len() >= 2
                    && cleaned != "-"
                    && !cleaned.starts_with("/dev/")
                    && !cleaned.contains("://")
                {
                    return Some(cleaned.to_string());
                }
            }
        }
        if tok == "-O" || tok == "--remote-name" {
            if let Some(next_tok) = tokens.get(idx + 1) {
                let cleaned = next_tok.trim_matches(['"', '\'', '`']);
                if !cleaned.starts_with('-')
                    && !cleaned.contains("://")
                    && cleaned.len() >= 2
                    && cleaned != "-"
                {
                    return Some(cleaned.to_string());
                }
            }
            remote_name_flag = true;
        }
        if let Some(redir) = tok.strip_prefix('>') {
            let target = if redir.is_empty() {
                tokens.get(idx + 1).map(String::as_str).unwrap_or("")
            } else {
                redir
            };
            let cleaned = target.trim_matches(['"', '\'', '`']);
            if cleaned.len() >= 2
                && !cleaned.starts_with('&')
                && !cleaned.starts_with("/dev/")
                && !cleaned.starts_with('-')
            {
                return Some(cleaned.to_string());
            }
        }
        if tok.starts_with("http://") || tok.starts_with("https://") {
            let no_q = tok.split(['?', '#']).next().unwrap_or(tok);
            if let Some(base) = no_q.rsplit('/').next() {
                if !base.is_empty() {
                    url_basename = Some(base.to_string());
                }
            }
        }
        idx += 1;
    }
    if remote_name_flag {
        if let Some(base) = url_basename {
            if base.len() >= 2 {
                return Some(base);
            }
        }
    }
    None
}

fn line_executes_downloaded_target(line: &str, target_raw: &str, target_norm: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
        return false;
    }
    for seg in trimmed.split([';', '|', '&']) {
        let seg_trim = seg.trim();
        if seg_trim.is_empty() {
            continue;
        }
        let toks = split_shell_tokens(seg_trim);
        if toks.is_empty() {
            continue;
        }
        let mut i = 0usize;
        while i < toks.len()
            && (matches!(
                toks[i].as_str(),
                "sudo" | "env" | "nohup" | "setsid" | "exec"
            ) || toks[i].contains('='))
        {
            i += 1;
        }
        let Some(cmd0) = toks.get(i) else {
            continue;
        };
        let cmd_clean = cmd0.trim_matches(['"', '\'', '`']);
        if matches!(
            cmd_clean,
            "chmod" | "chown" | "rm" | "mv" | "cp" | "ls" | "stat" | "sha256sum" | "shasum"
        ) {
            continue;
        }
        let cmd_base = Path::new(cmd_clean)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(cmd_clean)
            .to_ascii_lowercase();
        let is_interp = matches!(
            cmd_base.as_str(),
            "sh" | "bash"
                | "zsh"
                | "dash"
                | "ksh"
                | "ash"
                | "fish"
                | "source"
                | "."
                | "python"
                | "python3"
                | "python2"
                | "node"
                | "nodejs"
                | "bun"
                | "deno"
                | "ruby"
                | "perl"
                | "php"
                | "pwsh"
                | "powershell"
        ) || cmd_base.starts_with("python3.");

        if is_interp {
            for arg in &toks[i + 1..] {
                let a = arg.trim_matches(['"', '\'', '`']);
                let a_norm = a.strip_prefix("./").unwrap_or(a);
                if a == target_raw || (!target_norm.is_empty() && a_norm == target_norm) {
                    return true;
                }
            }
        } else {
            let cmd_norm = cmd_clean.strip_prefix("./").unwrap_or(cmd_clean);
            let has_explicit_path = cmd_clean.starts_with('/')
                || cmd_clean.starts_with("./")
                || cmd_clean.starts_with("$TMPDIR/")
                || cmd_clean.starts_with("${TMPDIR}/")
                || cmd_clean.starts_with("~/")
                || cmd_clean.starts_with("$HOME/");
            if has_explicit_path
                && (cmd_clean == target_raw || (!target_norm.is_empty() && cmd_norm == target_norm))
            {
                return true;
            }
        }
    }
    false
}

fn detect_multiline_download_then_exec(
    folded: &str,
    is_prompt_doc: bool,
    line_states: Option<&[PromptLineState]>,
) -> Option<(usize, String)> {
    let re = plugin_regexes();
    let lines: Vec<&str> = folded.lines().collect();
    let mut downloads: Vec<(usize, String, String)> = Vec::new();

    for (idx, &line) in lines.iter().enumerate() {
        if let Some(m) = re.download_output_cmd.find(line) {
            if !call_window_targets_localhost_only(line) {
                let prohibited = is_prompt_doc
                    && line_states.and_then(|st| st.get(idx)).is_some_and(|info| {
                        is_rce_explicitly_prohibited_on_line(&info.lower_line, m.start())
                            || is_target_defensively_negated_on_line(
                                &info.lower_line,
                                m.start(),
                                info.in_defensive_list,
                            )
                    });
                if !prohibited {
                    if let Some(target_raw) = extract_download_output_target(m.as_str()) {
                        let target_norm = target_raw
                            .strip_prefix("./")
                            .unwrap_or(&target_raw)
                            .to_string();
                        if downloads.len() < 16 {
                            downloads.push((idx, target_raw, target_norm));
                        }
                    }
                }
            }
        }

        for (dl_idx, target_raw, target_norm) in &downloads {
            if idx > *dl_idx
                && idx.saturating_sub(*dl_idx) <= 40
                && line_executes_downloaded_target(line, target_raw, target_norm)
            {
                let exec_prohibited = is_prompt_doc
                    && line_states.and_then(|st| st.get(idx)).is_some_and(|info| {
                        is_rce_explicitly_prohibited_on_line(
                            &info.lower_line,
                            info.lower_line.len(),
                        ) || is_target_defensively_negated_on_line(
                            &info.lower_line,
                            info.lower_line.len(),
                            info.in_defensive_list,
                        )
                    });
                if !exec_prohibited {
                    return Some((
                        *dl_idx + 1,
                        format!(
                            "downloads `{target_raw}` then executes `{}`",
                            truncate_snippet(line.trim(), 48)
                        ),
                    ));
                }
            }
        }
    }
    None
}

pub fn detect_credential_store_ref(raw: &str) -> Option<&'static str> {
    let (folded_raw, _) = fold_backslash_continuations(raw);
    let folded = collapse_adjacent_string_literals(&folded_raw);
    let lower = folded.to_ascii_lowercase();
    for &(needle, human_target) in CREDENTIAL_HARVEST_PATTERNS {
        for (byte_idx, _) in lower.match_indices(needle) {
            if !is_benign_ignore_or_filter_context(&folded, byte_idx, needle) {
                return Some(human_target);
            }
        }
    }
    let re = plugin_regexes();
    if let Some(mat) = re.cred_path_join.find(&folded) {
        return Some(describe_joined_cred_target(mat.as_str()));
    }
    for (_, decoded_ps) in decode_powershell_encoded_commands(&folded_raw) {
        let ps_collapsed = collapse_adjacent_string_literals(&decoded_ps);
        let ps_lower = ps_collapsed.to_ascii_lowercase();
        for &(needle, human_target) in CREDENTIAL_HARVEST_PATTERNS {
            if ps_lower.contains(needle) {
                return Some(human_target);
            }
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn check_remote_code_exec(
    path: &Path,
    display: &str,
    label: &str,
    raw: &str,
    is_prompt_doc: bool,
    base_line: usize,
    out: &mut Vec<McpFinding>,
    seen_fp: &mut HashSet<String>,
) {
    let (folded, line_map) = fold_backslash_continuations(raw);
    let collapsed = collapse_adjacent_string_literals(&folded);
    let re = plugin_regexes();
    let rce_regexes = [
        &re.pipe_to_shell,
        &re.ps_download_exec,
        &re.base64_exec,
        &re.eval_net,
        &re.dynamic_code_exec,
        &re.download_then_exec,
    ];

    if !is_prompt_doc {
        for rx in rce_regexes {
            if let Some(m) = rx.find(&collapsed) {
                let snippet = truncate_snippet(m.as_str().trim(), 64);
                let folded_ln = line_at_offset(&collapsed, m.start());
                let line = base_line + map_folded_line(&line_map, folded_ln).saturating_sub(1);
                let fp =
                    fingerprint_match("plugin-remote-code-exec", &format!("{display}:{snippet}"));
                push_finding(
                    out,
                    seen_fp,
                    McpFinding {
                        rule_id: "plugin-remote-code-exec",
                        server_name: label.to_string(),
                        config_file: display.to_string(),
                        config_path: path.to_path_buf(),
                        line,
                        severity: Severity::Critical,
                        fingerprint: fp,
                        message: format!(
                            "Executes remote, piped, or decoded code payload (`{snippet}`) inside plugin/hook/skill"
                        ),
                    },
                );
                return;
            }
        }
        for (ps_ln, decoded_ps) in decode_powershell_encoded_commands(&folded) {
            if let Some(snippet) = detect_inline_rce(&decoded_ps) {
                let line = base_line + map_folded_line(&line_map, ps_ln).saturating_sub(1);
                let fp = fingerprint_match(
                    "plugin-remote-code-exec",
                    &format!("{display}:ps-enc:{snippet}"),
                );
                push_finding(
                    out,
                    seen_fp,
                    McpFinding {
                        rule_id: "plugin-remote-code-exec",
                        server_name: label.to_string(),
                        config_file: display.to_string(),
                        config_path: path.to_path_buf(),
                        line,
                        severity: Severity::Critical,
                        fingerprint: fp,
                        message: format!(
                            "Executes UTF-16/Base64 PowerShell `-EncodedCommand` payload (`{snippet}`) inside plugin/hook/skill"
                        ),
                    },
                );
                return;
            }
        }
        if let Some((folded_ln, desc)) =
            detect_multiline_download_then_exec(&collapsed, false, None)
        {
            let line = base_line + map_folded_line(&line_map, folded_ln).saturating_sub(1);
            let fp = fingerprint_match("plugin-remote-code-exec", &format!("{display}:{desc}"));
            push_finding(
                out,
                seen_fp,
                McpFinding {
                    rule_id: "plugin-remote-code-exec",
                    server_name: label.to_string(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    line,
                    severity: Severity::Critical,
                    fingerprint: fp,
                    message: format!(
                        "Multi-step remote code execution ({desc}) inside plugin/hook/skill"
                    ),
                },
            );
            return;
        }
        let code_no_comments = strip_code_comments(&collapsed);
        if let Some(m) = re.reflective_code_exec.find(&code_no_comments) {
            let snippet = truncate_snippet(m.as_str().trim(), 64);
            let folded_ln = line_at_offset(&code_no_comments, m.start());
            let line = base_line + map_folded_line(&line_map, folded_ln).saturating_sub(1);
            let fp = fingerprint_match("plugin-dynamic-code-exec", &format!("{display}:{snippet}"));
            push_finding(
                out,
                seen_fp,
                McpFinding {
                    rule_id: "plugin-dynamic-code-exec",
                    server_name: label.to_string(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    line,
                    severity: Severity::High,
                    fingerprint: fp,
                    message: format!(
                        "Uses reflective or dynamic code execution (`{snippet}`) inside plugin/hook/skill"
                    ),
                },
            );
        }
        return;
    }

    let line_meta = build_prompt_line_defensive_states(&collapsed);

    for rx in rce_regexes {
        for m in rx.find_iter(&collapsed) {
            let folded_ln = line_at_offset(&collapsed, m.start());
            let line_idx = folded_ln.saturating_sub(1);
            if let Some(info) = line_meta.get(line_idx) {
                let col_byte = m.start().saturating_sub(info.line_start_byte);
                if is_rce_explicitly_prohibited_on_line(&info.lower_line, col_byte) {
                    continue;
                }
            }
            let snippet = truncate_snippet(m.as_str().trim(), 64);
            let line = base_line + map_folded_line(&line_map, folded_ln).saturating_sub(1);
            let fp = fingerprint_match("plugin-remote-code-exec", &format!("{display}:{snippet}"));
            push_finding(
                out,
                seen_fp,
                McpFinding {
                    rule_id: "plugin-remote-code-exec",
                    server_name: label.to_string(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    line,
                    severity: Severity::Critical,
                    fingerprint: fp,
                    message: format!(
                        "Executes remote, piped, or decoded code payload (`{snippet}`) inside plugin/hook/skill"
                    ),
                },
            );
            return;
        }
    }

    for (ps_ln, decoded_ps) in decode_powershell_encoded_commands(&folded) {
        let line_idx = ps_ln.saturating_sub(1);
        if let Some(info) = line_meta.get(line_idx) {
            if is_rce_explicitly_prohibited_on_line(&info.lower_line, info.lower_line.len()) {
                continue;
            }
        }
        if let Some(snippet) = detect_inline_rce(&decoded_ps) {
            let line = base_line + map_folded_line(&line_map, ps_ln).saturating_sub(1);
            let fp = fingerprint_match(
                "plugin-remote-code-exec",
                &format!("{display}:ps-enc:{snippet}"),
            );
            push_finding(
                out,
                seen_fp,
                McpFinding {
                    rule_id: "plugin-remote-code-exec",
                    server_name: label.to_string(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    line,
                    severity: Severity::Critical,
                    fingerprint: fp,
                    message: format!(
                        "Executes UTF-16/Base64 PowerShell `-EncodedCommand` payload (`{snippet}`) inside plugin/hook/skill"
                    ),
                },
            );
            return;
        }
    }

    if let Some((folded_ln, desc)) =
        detect_multiline_download_then_exec(&collapsed, true, Some(&line_meta))
    {
        let line = base_line + map_folded_line(&line_map, folded_ln).saturating_sub(1);
        let fp = fingerprint_match("plugin-remote-code-exec", &format!("{display}:{desc}"));
        push_finding(
            out,
            seen_fp,
            McpFinding {
                rule_id: "plugin-remote-code-exec",
                server_name: label.to_string(),
                config_file: display.to_string(),
                config_path: path.to_path_buf(),
                line,
                severity: Severity::Critical,
                fingerprint: fp,
                message: format!(
                    "Multi-step remote code execution ({desc}) inside plugin/hook/skill"
                ),
            },
        );
        return;
    }

    for m in re.reflective_code_exec.find_iter(&collapsed) {
        let folded_ln = line_at_offset(&collapsed, m.start());
        let line_idx = folded_ln.saturating_sub(1);
        if let Some(info) = line_meta.get(line_idx) {
            let col_byte = m.start().saturating_sub(info.line_start_byte);
            if is_rce_explicitly_prohibited_on_line(&info.lower_line, col_byte)
                || is_target_defensively_negated_on_line(
                    &info.lower_line,
                    col_byte,
                    info.in_defensive_list,
                )
            {
                continue;
            }
        }
        let snippet = truncate_snippet(m.as_str().trim(), 64);
        let line = base_line + map_folded_line(&line_map, folded_ln).saturating_sub(1);
        let fp = fingerprint_match("plugin-dynamic-code-exec", &format!("{display}:{snippet}"));
        push_finding(
            out,
            seen_fp,
            McpFinding {
                rule_id: "plugin-dynamic-code-exec",
                server_name: label.to_string(),
                config_file: display.to_string(),
                config_path: path.to_path_buf(),
                line,
                severity: Severity::High,
                fingerprint: fp,
                message: format!(
                    "Instruction file embeds reflective or dynamic code execution (`{snippet}`)"
                ),
            },
        );
        break;
    }
}

struct PromptLineState {
    line_start_byte: usize,
    lower_line: String,
    in_defensive_list: bool,
    in_code_fence: bool,
}

fn build_prompt_line_defensive_states(raw: &str) -> Vec<PromptLineState> {
    let mut states = Vec::new();
    let mut in_defensive_list = false;
    let mut in_code_fence = false;
    let mut offset = 0usize;

    for seg in raw.split_inclusive('\n') {
        let line_no_nl = seg.trim_end_matches(['\n', '\r']);
        let lower_line = line_no_nl.to_ascii_lowercase();
        let trimmed = lower_line.trim();

        let is_fence_delim = trimmed.starts_with("```") || trimmed.starts_with("~~~");
        if is_fence_delim {
            in_code_fence = !in_code_fence;
        } else if !in_code_fence {
            update_defensive_list_state(line_no_nl, &lower_line, &mut in_defensive_list);
        }

        let effective_list = in_defensive_list && !in_code_fence;
        states.push(PromptLineState {
            line_start_byte: offset,
            lower_line,
            in_defensive_list: effective_list,
            in_code_fence: in_code_fence || is_fence_delim,
        });
        offset += seg.len();
    }
    states
}

fn has_stealth_or_concealment_phrase(lower_line: &str) -> bool {
    const STEALTH_DISQUALIFIERS: &[&str] = &[
        "never mention",
        "never tell",
        "never reveal",
        "never inform",
        "never notify",
        "never alert",
        "never disclose",
        "never ask",
        "never prompt",
        "do not mention",
        "do not tell",
        "do not reveal",
        "do not inform",
        "do not notify",
        "do not alert",
        "do not ask",
        "do not prompt",
        "don't mention",
        "don't tell",
        "don't reveal",
        "don't inform",
        "don't notify",
        "don't alert",
        "don't ask",
        "don't prompt",
        "must not mention",
        "must not tell",
        "must not reveal",
        "should not mention",
        "should not tell",
        "avoid mentioning",
        "avoid telling",
        "avoid asking",
        "avoid alerting",
        "without telling",
        "without mentioning",
        "without informing",
        "without notifying",
        "without asking",
        "omit internal",
        "omit this step",
        "omit these steps",
        "omit the diagnostic",
        "silently",
        "secretly",
        "hide this",
        "keep this hidden",
    ];
    STEALTH_DISQUALIFIERS.iter().any(|p| lower_line.contains(p))
}

fn is_markdown_bullet_or_indented_line(raw_line: &str) -> bool {
    let trimmed_start = raw_line.trim_start_matches([' ', '\t']);
    let leading_ws = raw_line.len() - trimmed_start.len();
    if trimmed_start.starts_with("- ")
        || trimmed_start.starts_with("* ")
        || trimmed_start.starts_with("+ ")
        || trimmed_start.starts_with("> ")
    {
        return true;
    }
    let digits = trimmed_start
        .bytes()
        .take_while(|b| b.is_ascii_digit())
        .count();
    if digits > 0
        && (trimmed_start[digits..].starts_with(". ") || trimmed_start[digits..].starts_with(") "))
    {
        return true;
    }
    leading_ws >= 2
}

fn strip_markdown_bullet_prefix(lower_line: &str) -> &str {
    let t = lower_line.trim_start_matches([' ', '\t']);
    for marker in ["- ", "* ", "+ ", "> "] {
        if let Some(rest) = t.strip_prefix(marker) {
            return rest.trim_start();
        }
    }
    let digits = t.bytes().take_while(|b| b.is_ascii_digit()).count();
    if digits > 0 {
        if let Some(rest) = t[digits..]
            .strip_prefix(". ")
            .or_else(|| t[digits..].strip_prefix(") "))
        {
            return rest.trim_start();
        }
    }
    t
}

fn has_clause_separator(s: &str) -> bool {
    const CLAUSE_BREAKS: &[&str] = &[
        ";",
        "&&",
        "||",
        ". ",
        "! ",
        "? ",
        " instead",
        " then ",
        ", then ",
        " unless ",
        ", unless ",
        " except ",
        ", except ",
        " but ",
        ", but ",
        " however ",
        ", however ",
        " otherwise ",
        ", otherwise ",
        ", first ",
        " before ",
        " until ",
        " without ",
        " after ",
        " once ",
        " — ",
        " - ",
        ", and ",
        ", or else ",
        ", or if ",
        ", or otherwise ",
        " and read ",
        " and cat ",
        " and run ",
        " and execute ",
        " and curl ",
        " and wget ",
        " and fetch ",
        " and upload ",
        " and send ",
        " and post ",
        " and open ",
        " and load ",
        " and copy ",
        " and check ",
        " and verify ",
        " and inspect ",
        " and use ",
        " and source ",
        " and pipe ",
        " and forward ",
        " and transmit ",
        " and exfiltrate ",
        " and invoke ",
        " and eval ",
        " and exec ",
        " and include ",
        " and dump ",
        " and print ",
    ];
    if CLAUSE_BREAKS.iter().any(|sep| s.contains(sep)) {
        return true;
    }
    let bytes = s.as_bytes();
    for (idx, &b) in bytes.iter().enumerate() {
        if b == b':' {
            // Allow URL schemes (`https://`) while treating prose colons (`offline: curl`) as clause breaks
            let is_scheme = bytes.get(idx + 1) == Some(&b'/') && bytes.get(idx + 2) == Some(&b'/');
            if !is_scheme {
                return true;
            }
        }
    }
    false
}

fn starts_with_non_prohibitive_negation(from_neg: &str) -> bool {
    const NON_PROHIBITIVE: &[&str] = &[
        "never skip",
        "do not skip",
        "don't skip",
        "never omit",
        "do not omit",
        "don't omit",
        "never forget",
        "do not forget",
        "don't forget",
        "never fail",
        "do not fail",
        "don't fail",
        "never crash",
        "do not crash",
        "don't crash",
        "never hesitate",
        "do not hesitate",
        "don't hesitate",
        "never wait",
        "do not wait",
        "don't wait",
        "never stop",
        "do not stop",
        "don't stop",
        "never delay",
        "do not delay",
        "don't delay",
        "never ask",
        "do not ask",
        "don't ask",
    ];
    NON_PROHIBITIVE.iter().any(|p| from_neg.starts_with(p))
}

fn is_rce_explicitly_prohibited_on_line(lower_line: &str, target_byte_idx: usize) -> bool {
    if has_stealth_or_concealment_phrase(lower_line) {
        return false;
    }
    let safe_idx = target_byte_idx.min(lower_line.len());
    let mut prefix_end = safe_idx;
    while prefix_end > 0 && !lower_line.is_char_boundary(prefix_end) {
        prefix_end -= 1;
    }
    let before_target = &lower_line[..prefix_end];

    const RCE_PROHIBITIONS: &[&str] = &[
        "never run ",
        "do not run ",
        "don't run ",
        "must not run ",
        "never execute ",
        "do not execute ",
        "don't execute ",
        "must not execute ",
        "never pipe ",
        "do not pipe ",
        "don't pipe ",
        "avoid running ",
        "avoid piping ",
        "prohibit running ",
        "forbid running ",
    ];
    for neg in RCE_PROHIBITIONS {
        if let Some(neg_pos) = before_target.rfind(neg) {
            let after_neg = &before_target[neg_pos + neg.len()..];
            if !has_clause_separator(after_neg) {
                return true;
            }
        }
    }
    false
}

fn is_passive_defensive_bullet(lower_line: &str) -> bool {
    if !is_markdown_bullet_or_indented_line(lower_line) {
        return false;
    }
    let body = strip_markdown_bullet_prefix(lower_line);
    if has_clause_separator(body) {
        return false;
    }

    const ACTIVE_CMD_MARKERS: &[&str] = &[
        "| sh",
        "| bash",
        "| zsh",
        "| dash",
        "| ksh",
        "| pwsh",
        "| powershell",
        "curl ",
        "wget ",
        "cat ",
        "head ",
        "tail ",
        "scp ",
        "rsync ",
        "nc ",
        "ncat ",
        "socat ",
        "bash -c",
        "sh -c",
        "python -c",
        "python3 -c",
        "node -e",
        "-f ",
        "-d @",
        "--data",
        "--upload-file",
        "$(",
        "ignore all previous",
        "ignore previous",
        "disregard previous",
        "disregard all",
        "override safety",
        "bypass safety",
    ];
    if ACTIVE_CMD_MARKERS.iter().any(|m| body.contains(m)) {
        return false;
    }

    const ALLOWED_BULLET_STARTS: &[&str] = &[
        "never ",
        "do not ",
        "don't ",
        "avoid ",
        "refuse ",
        "not ",
        "reading ",
        "accessing ",
        "opening ",
        "touching ",
        "modifying ",
        "inspecting ",
        "uploading ",
        "sending ",
        "posting ",
        "sharing ",
        "exfiltrating ",
        "executing ",
        "running ",
        "hiding ",
        "disclosing ",
        "using ",
        "storing ",
        "logging ",
        "committing ",
    ];
    if starts_with_non_prohibitive_negation(body) {
        return false;
    }
    ALLOWED_BULLET_STARTS.iter().any(|p| body.starts_with(p))
}

fn update_defensive_list_state(raw_line: &str, lower_line: &str, in_defensive_list: &mut bool) {
    let t = lower_line.trim();
    if t.is_empty() {
        return;
    }
    if has_stealth_or_concealment_phrase(lower_line) {
        *in_defensive_list = false;
        return;
    }

    const MANDATORY_EXEC_DISQUALIFIERS: &[&str] = &[
        "never skip",
        "do not skip",
        "don't skip",
        "never omit",
        "do not omit",
        "never forget",
        "do not forget",
        "never fail",
        "do not fail",
        "don't fail",
        "must run",
        "always run",
        "required step",
        "diagnostic step",
    ];

    const EXPLICIT_LIST_PROHIBITIONS: &[&str] = &[
        "never perform",
        "never do",
        "never run",
        "never execute",
        "never access",
        "never read",
        "do not perform",
        "do not run",
        "do not execute",
        "prohibited action",
        "forbidden action",
        "disallowed action",
        "actions to avoid",
        "things not to do",
        "what not to do",
        "must never",
        "strictly forbidden",
        "strictly prohibited",
        "under no circumstances",
        "don'ts",
    ];

    let is_heading = t.starts_with('#');
    let is_colon_introducer = t.ends_with(':')
        && !t.contains("://")
        && !t.contains("| sh")
        && !t.contains("| bash")
        && !t.contains("| curl");

    if is_heading || is_colon_introducer {
        if MANDATORY_EXEC_DISQUALIFIERS.iter().any(|d| t.contains(d)) {
            *in_defensive_list = false;
            return;
        }
        if EXPLICIT_LIST_PROHIBITIONS.iter().any(|p| t.contains(p)) {
            *in_defensive_list = true;
            return;
        }
        if is_heading {
            *in_defensive_list = false;
            return;
        }
    }

    if *in_defensive_list && !is_markdown_bullet_or_indented_line(raw_line) {
        *in_defensive_list = false;
    }
}

fn is_target_defensively_negated_on_line(
    lower_line: &str,
    target_byte_idx: usize,
    in_defensive_list: bool,
) -> bool {
    if has_stealth_or_concealment_phrase(lower_line) {
        return false;
    }

    let has_exfil_pipe = lower_line.contains("| curl")
        || lower_line.contains("| wget")
        || lower_line.contains("| nc")
        || lower_line.contains("| ncat")
        || lower_line.contains("| socat")
        || lower_line.contains("| sh")
        || lower_line.contains("| bash");
    if has_exfil_pipe {
        return false;
    }

    let safe_idx = target_byte_idx.min(lower_line.len());
    let mut prefix_end = safe_idx;
    while prefix_end > 0 && !lower_line.is_char_boundary(prefix_end) {
        prefix_end -= 1;
    }
    let before_target = &lower_line[..prefix_end];

    const PREFIX_NEGATIONS: &[&str] = &[
        "never ",
        "do not ",
        "don't ",
        "must not ",
        "must never ",
        "should not ",
        "shall not ",
        "cannot ",
        "can't ",
        "avoid ",
        "prohibit",
        "forbid",
        "refuse ",
        "disallow",
        "not read",
        "not access",
        "not touch",
        "not open",
        "not modify",
        "not inspect",
        "not run",
        "not execute",
        "block access",
        "deny access",
        "ignore ~/.ssh",
        "ignore ~/.aws",
        "exclude ~/.ssh",
        "exclude ~/.aws",
        "under no circumstances",
    ];

    for neg in PREFIX_NEGATIONS {
        if let Some(neg_pos) = before_target.rfind(neg) {
            let from_neg = &before_target[neg_pos..];
            if starts_with_non_prohibitive_negation(from_neg) {
                continue;
            }
            let after_neg = &before_target[neg_pos + neg.len()..];
            if !has_clause_separator(after_neg) {
                return true;
            }
        }
    }

    const PASSIVE_PROHIBITIONS: &[&str] = &[
        "is forbidden",
        "are forbidden",
        "is prohibited",
        "are prohibited",
        "is strictly forbidden",
        "is strictly prohibited",
        "is off-limits",
        "are off-limits",
        "is off limits",
        "are off limits",
        "is disallowed",
        "are disallowed",
        "are not allowed",
        "is not allowed",
    ];
    if !has_clause_separator(lower_line)
        && !lower_line.contains("curl ")
        && !lower_line.contains("wget ")
        && !lower_line.contains("cat ")
        && PASSIVE_PROHIBITIONS.iter().any(|p| lower_line.contains(p))
    {
        return true;
    }

    if in_defensive_list && is_passive_defensive_bullet(lower_line) {
        return true;
    }

    false
}

fn prompt_line_has_active_credential_access(lower_line: &str) -> bool {
    const ACTIVE_ACCESS_INDICATORS: &[&str] = &[
        "cat ",
        "cat\t",
        "head ",
        "tail ",
        "less ",
        "more ",
        "grep ",
        "awk ",
        "sed ",
        "cp ",
        "scp ",
        "rsync ",
        "tar ",
        "zip ",
        "curl ",
        "wget ",
        "nc ",
        "ncat ",
        "base64",
        "openssl ",
        "python",
        "node ",
        "bash ",
        "sh -c",
        "fetch(",
        "readfilesync",
        "readfile(",
        "read_text",
        "read_bytes",
        "pathlib",
        "os.path",
        "fs.",
        "open(",
        "$(",
        "security find-",
        "security dump-keychain",
        "secret-tool lookup",
        "read ",
        "include ",
        "output ",
        "print ",
        "dump ",
        "upload",
        "send ",
        "post ",
        "exfil",
        "copy ",
        "extract ",
    ];
    ACTIVE_ACCESS_INDICATORS
        .iter()
        .any(|ind| lower_line.contains(ind))
}

#[allow(clippy::too_many_arguments)]
fn check_credential_harvest(
    path: &Path,
    display: &str,
    label: &str,
    raw: &str,
    is_prompt_doc: bool,
    base_line: usize,
    out: &mut Vec<McpFinding>,
    seen_fp: &mut HashSet<String>,
) {
    let (folded, line_map) = fold_backslash_continuations(raw);
    if is_prompt_doc {
        let line_states = build_prompt_line_defensive_states(&folded);
        for (idx, state) in line_states.iter().enumerate() {
            let lower_line = &state.lower_line;
            if !prompt_line_has_active_credential_access(lower_line) {
                continue;
            }
            for &(needle, human_target) in CREDENTIAL_HARVEST_PATTERNS {
                if let Some(needle_pos) = lower_line.find(needle) {
                    if is_target_defensively_negated_on_line(
                        lower_line,
                        needle_pos,
                        state.in_defensive_list,
                    ) {
                        continue;
                    }
                    let line = base_line + map_folded_line(&line_map, idx + 1).saturating_sub(1);
                    let fp = fingerprint_match(
                        "plugin-credential-harvest",
                        &format!("{display}:{human_target}"),
                    );
                    push_finding(
                        out,
                        seen_fp,
                        McpFinding {
                            rule_id: "plugin-credential-harvest",
                            server_name: label.to_string(),
                            config_file: display.to_string(),
                            config_path: path.to_path_buf(),
                            line,
                            severity: Severity::Critical,
                            fingerprint: fp,
                            message: format!(
                                "Instruction file directs agent to access host credential store (`{human_target}`)"
                            ),
                        },
                    );
                    return;
                }
            }
        }
        return;
    }

    let re = plugin_regexes();
    let folded_code = collapse_adjacent_string_literals(&folded);
    let lower = folded_code.to_ascii_lowercase();
    for &(needle, human_target) in CREDENTIAL_HARVEST_PATTERNS {
        let mut found_line = None;
        for (byte_idx, _) in lower.match_indices(needle) {
            if is_benign_ignore_or_filter_context(&folded_code, byte_idx, needle) {
                continue;
            }
            found_line = Some(line_at_offset(&folded_code, byte_idx));
            break;
        }
        if let Some(folded_ln) = found_line {
            let line = base_line + map_folded_line(&line_map, folded_ln).saturating_sub(1);
            let fp = fingerprint_match(
                "plugin-credential-harvest",
                &format!("{display}:{human_target}"),
            );
            push_finding(
                out,
                seen_fp,
                McpFinding {
                    rule_id: "plugin-credential-harvest",
                    server_name: label.to_string(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    line,
                    severity: Severity::Critical,
                    fingerprint: fp,
                    message: format!(
                        "References sensitive host credential store (`{human_target}`) outside workspace"
                    ),
                },
            );
            return;
        }
    }

    if let Some(mat) = re.cred_path_join.find(&folded_code) {
        let human_target = describe_joined_cred_target(mat.as_str());
        let folded_ln = line_at_offset(&folded_code, mat.start());
        let line = base_line + map_folded_line(&line_map, folded_ln).saturating_sub(1);
        let fp = fingerprint_match(
            "plugin-credential-harvest",
            &format!("{display}:{human_target}"),
        );
        push_finding(
            out,
            seen_fp,
            McpFinding {
                rule_id: "plugin-credential-harvest",
                server_name: label.to_string(),
                config_file: display.to_string(),
                config_path: path.to_path_buf(),
                line,
                severity: Severity::Critical,
                fingerprint: fp,
                message: format!(
                    "References sensitive host credential store (`{human_target}`) outside workspace"
                ),
            },
        );
        return;
    }

    for (ps_ln, decoded_ps) in decode_powershell_encoded_commands(&folded) {
        if let Some(human_target) = detect_credential_store_ref(&decoded_ps) {
            let line = base_line + map_folded_line(&line_map, ps_ln).saturating_sub(1);
            let fp = fingerprint_match(
                "plugin-credential-harvest",
                &format!("{display}:{human_target}"),
            );
            push_finding(
                out,
                seen_fp,
                McpFinding {
                    rule_id: "plugin-credential-harvest",
                    server_name: label.to_string(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    line,
                    severity: Severity::Critical,
                    fingerprint: fp,
                    message: format!(
                        "PowerShell `-EncodedCommand` accesses host credential store (`{human_target}`)"
                    ),
                },
            );
            return;
        }
    }
}

fn describe_joined_cred_target(matched: &str) -> &'static str {
    let lower = matched.to_ascii_lowercase();
    if lower.contains("hosts.yml") {
        "~/.config/gh/hosts.yml"
    } else if lower.contains(".aws") {
        "~/.aws/credentials"
    } else if lower.contains(".kube") {
        "~/.kube/config"
    } else if lower.contains("auth.json") {
        "~/.codex/auth.json"
    } else if lower.contains(".docker") {
        "~/.docker/config.json"
    } else if lower.contains(".azure") {
        "~/.azure/accessTokens.json"
    } else if lower.contains("secret-tool") {
        "Linux keyring (`secret-tool lookup`)"
    } else {
        "~/.claude/.credentials.json"
    }
}

fn is_bare_filterable_dir_or_rc_needle(needle: &str) -> bool {
    matches!(
        needle,
        "'.ssh'"
            | "\".ssh\""
            | "'/.ssh'"
            | "\"/.ssh\""
            | "'.aws'"
            | "\".aws\""
            | "'/.aws'"
            | "\"/.aws\""
            | "'.azure'"
            | "\".azure\""
            | "'.kube'"
            | "\".kube\""
            | "'.gnupg'"
            | "\".gnupg\""
            | "'.docker'"
            | "\".docker\""
            | "'.npmrc'"
            | "\".npmrc\""
            | "'.netrc'"
            | "\".netrc\""
            | "'.git-credentials'"
            | "\".git-credentials\""
    )
}

fn is_benign_ignore_or_filter_context(folded: &str, match_byte_idx: usize, needle: &str) -> bool {
    if !is_bare_filterable_dir_or_rc_needle(needle) {
        return false;
    }
    let lines: Vec<&str> = folded.lines().collect();
    if lines.is_empty() {
        return false;
    }
    let line_idx = line_at_offset(folded, match_byte_idx)
        .saturating_sub(1)
        .min(lines.len() - 1);
    let cur_lower = lines[line_idx].to_ascii_lowercase();

    // Never suppress if the line itself performs path expansion, file reading, archiving, or network calls
    const ACTIVE_CODE_ACCESS: &[&str] = &[
        "open(",
        "read_text",
        "read_bytes",
        "readfilesync",
        "readfile(",
        "createreadstream",
        "expanduser",
        "homedir",
        "path.home",
        "user_home",
        "os.environ",
        "process.env",
        "shutil.copy",
        "copyfile",
        "tarfile",
        "zipfile",
        "subprocess",
        "curl ",
        "wget ",
        "fetch(",
        "requests.",
        "httpx.",
        "urlopen",
    ];
    if ACTIVE_CODE_ACCESS.iter().any(|m| cur_lower.contains(m)) {
        return false;
    }

    let win_start = line_idx.saturating_sub(8);
    let win_end = (line_idx + 5).min(lines.len());
    let window_lower = lines[win_start..win_end].join("\n").to_ascii_lowercase();
    if ACTIVE_CODE_ACCESS.iter().any(|m| window_lower.contains(m)) {
        return false;
    }

    const IGNORE_IDENT_MARKERS: &[&str] = &[
        "skip_dir",
        "skip_path",
        "skip_file",
        "skip_list",
        "skipped_",
        "ignore_dir",
        "ignore_path",
        "ignore_file",
        "ignore_list",
        "ignored_",
        "exclude_dir",
        "exclude_path",
        "exclude_file",
        "exclude_list",
        "excluded_",
        "prune_dir",
        "deny_list",
        "denylist",
        "blocklist",
        "block_list",
        "not in {",
        "not in [",
        "not in (",
    ];
    if IGNORE_IDENT_MARKERS
        .iter()
        .any(|m| window_lower.contains(m))
    {
        return true;
    }

    const VCS_BUILD_NOISE_PEERS: &[&str] = &[
        "\".git\"",
        "'.git'",
        "\"node_modules\"",
        "'node_modules'",
        "\"__pycache__\"",
        "'__pycache__'",
        "\".venv\"",
        "'.venv'",
        "\".ds_store\"",
        "'.ds_store'",
        "\".hg\"",
        "'.hg'",
        "\".svn\"",
        "'.svn'",
    ];
    let peer_hits = VCS_BUILD_NOISE_PEERS
        .iter()
        .filter(|&&p| window_lower.contains(p))
        .count();
    peer_hits >= 2 || (peer_hits >= 1 && cur_lower.contains(".git"))
}

fn resolve_url_identifiers(code: &str) -> Vec<(String, String)> {
    let re = plugin_regexes();
    let mut out = Vec::new();
    for caps in re.url_var_assign.captures_iter(code) {
        if let (Some(var_m), Some(url_m)) = (caps.get(1), caps.get(2)) {
            if out.len() < 32 {
                out.push((var_m.as_str().to_string(), url_m.as_str().to_string()));
            }
        }
    }
    out
}

fn contains_ident_token(haystack: &str, ident: &str) -> bool {
    if ident.is_empty() {
        return false;
    }
    let bytes = haystack.as_bytes();
    for (idx, _) in haystack.match_indices(ident) {
        let prev_ok = idx == 0
            || !bytes[idx - 1].is_ascii_alphanumeric()
                && !matches!(bytes[idx - 1], b'_' | b'$' | b'.');
        let end = idx + ident.len();
        let next_ok = end >= bytes.len()
            || (!bytes[end].is_ascii_alphanumeric() && !matches!(bytes[end], b'_' | b'$'));
        if prev_ok && next_ok {
            return true;
        }
    }
    false
}

fn urls_for_call_window<'a>(
    call_window: &'a str,
    resolved_vars: &'a [(String, String)],
) -> Vec<&'a str> {
    let re = plugin_regexes();
    let direct: Vec<&str> = re
        .url_extract
        .find_iter(call_window)
        .map(|m| m.as_str())
        .collect();
    if !direct.is_empty() {
        return direct;
    }
    let lower = call_window.to_ascii_lowercase();
    // Do not substitute an unrelated file-top URL variable if this call site specifies an explicit host option
    if lower.contains("hostname:")
        || lower.contains("\"hostname\"")
        || lower.contains("'hostname'")
        || lower.contains("host:")
    {
        return Vec::new();
    }
    let mut resolved = Vec::new();
    for (var_name, url_val) in resolved_vars {
        if contains_ident_token(call_window, var_name) {
            resolved.push(url_val.as_str());
        }
    }
    resolved
}

fn is_url_official_for_env_var(url: &str, env_var: &str) -> bool {
    if !url.trim().to_ascii_lowercase().starts_with("https://") {
        return false;
    }
    let Some(authority) = extract_url_authority(url) else {
        return false;
    };
    if authority.contains('@') {
        return false;
    }
    let host = authority
        .split(':')
        .next()
        .unwrap_or(authority)
        .to_ascii_lowercase();

    match env_var {
        "ANTHROPIC_API_KEY" | "CLAUDE_API_KEY" | "CLAUDE_CODE_OAUTH_TOKEN" => {
            host == "api.anthropic.com"
                || (host.starts_with("bedrock-runtime.") && host.ends_with(".amazonaws.com"))
                || host == "aiplatform.googleapis.com"
                || host.ends_with("-aiplatform.googleapis.com")
        }
        "OPENAI_API_KEY" => host == "api.openai.com" || host == "chatgpt.com",
        "GEMINI_API_KEY" | "GOOGLE_API_KEY" | "GOOGLE_APPLICATION_CREDENTIALS" => {
            host == "generativelanguage.googleapis.com"
                || host == "aiplatform.googleapis.com"
                || host.ends_with("-aiplatform.googleapis.com")
                || host == "oauth2.googleapis.com"
        }
        "OPENROUTER_API_KEY" => host == "openrouter.ai",
        "XAI_API_KEY" => host == "api.x.ai",
        "GROQ_API_KEY" => host == "api.groq.com",
        "GITHUB_TOKEN" | "GH_TOKEN" => {
            host == "api.github.com"
                || host == "uploads.github.com"
                || host == "api.githubcopilot.com"
        }
        "GITLAB_TOKEN" => host == "gitlab.com",
        "SLACK_BOT_TOKEN" => host == "slack.com" || host.ends_with(".slack.com"),
        "STRIPE_SECRET_KEY" => host == "api.stripe.com",
        _ => false,
    }
}

fn detect_code_env_exfiltration_in_block(
    block: &str,
    window_lines: usize,
) -> Option<(usize, String)> {
    let stripped = collapse_adjacent_string_literals(&strip_code_comments(block));
    let re = plugin_regexes();
    if !re.exfil_net_sink.is_match(&stripped) {
        return None;
    }
    if !re.wholesale_env_dump.is_match(&stripped)
        && !re.dotenv_file_read.is_match(&stripped)
        && !re.sensitive_env_name.is_match(&stripped)
    {
        return None;
    }

    let resolved_url_vars = resolve_url_identifiers(&stripped);
    let lines: Vec<&str> = stripped.lines().collect();
    for (idx, &line) in lines.iter().enumerate() {
        let Some(sink_mat) = re
            .exfil_net_sink
            .find_iter(line)
            .find(|m| !is_false_positive_cli_net_token(line, m.start(), m.end()))
        else {
            continue;
        };
        let win_start = idx.saturating_sub(window_lines);
        let win_end = (idx + window_lines + 1).min(lines.len());
        let window_text = lines[win_start..win_end].join("\n");

        // Inspect URLs strictly around this specific network sink (plus resolved URL variables passed
        // into this call site) so a decoy `http://localhost` or `https://api.anthropic.com` constant
        // elsewhere in the file can never blind an un-schemed `https.request({ hostname: "evil.io" })`!
        let call_start = idx.saturating_sub(2);
        let call_end = (idx + 6).min(lines.len());
        let call_site_text = lines[call_start..call_end].join("\n");
        let urls_at_sink = urls_for_call_window(&call_site_text, &resolved_url_vars);
        let non_local_urls: Vec<&str> = urls_at_sink
            .iter()
            .copied()
            .filter(|u| !is_localhost_url(u))
            .collect();
        if !urls_at_sink.is_empty() && non_local_urls.is_empty() {
            continue;
        }
        if urls_at_sink.is_empty() && call_window_targets_localhost_only(&call_site_text) {
            continue;
        }

        let sink_label = sink_mat
            .as_str()
            .trim()
            .trim_end_matches('(')
            .trim()
            .to_string();
        let dest_desc = if let Some(&first_url) = non_local_urls.first() {
            let host = extract_url_host(first_url).unwrap_or(first_url);
            format!("`{host}` via `{sink_label}`")
        } else {
            format!("outbound network sink `{sink_label}`")
        };

        if let Some(m) = re.wholesale_env_dump.find(&window_text) {
            let src_snip = truncate_snippet(m.as_str().trim(), 40);
            return Some((
                idx + 1,
                format!("dumps process environment (`{src_snip}`) to {dest_desc}"),
            ));
        }

        if let Some(m) = re.dotenv_file_read.find(&window_text) {
            let src_snip = truncate_snippet(m.as_str().trim(), 40);
            return Some((
                idx + 1,
                format!("reads `.env` secrets (`{src_snip}`) and sends to {dest_desc}"),
            ));
        }

        let matched_vars: Vec<&str> = re
            .sensitive_env_name
            .find_iter(&window_text)
            .map(|m| m.as_str())
            .collect();
        if !matched_vars.is_empty() {
            let all_official = !non_local_urls.is_empty()
                && non_local_urls.iter().all(|u| {
                    matched_vars
                        .iter()
                        .all(|var| is_url_official_for_env_var(u, var))
                });
            if !all_official {
                let first_var = matched_vars[0];
                return Some((
                    idx + 1,
                    format!("reads `{first_var}` and sends data to {dest_desc}"),
                ));
            }
        }
    }
    None
}

fn detect_multiline_prose_exfil(
    folded: &str,
    line_states: &[PromptLineState],
) -> Option<(usize, String)> {
    let re = plugin_regexes();
    let lines: Vec<&str> = folded.lines().collect();
    for (i, &src_line) in lines.iter().enumerate() {
        let Some(src_state) = line_states.get(i) else {
            continue;
        };
        if src_state.in_code_fence {
            continue;
        }
        let Some(src_mat) = re.prompt_prose_secret_source.find(src_line) else {
            continue;
        };
        if is_target_defensively_negated_on_line(
            &src_state.lower_line,
            src_mat.start(),
            src_state.in_defensive_list,
        ) {
            continue;
        }

        let max_j = (i + 12).min(lines.len());
        for (j, &dst_line) in lines.iter().enumerate().take(max_j).skip(i + 1) {
            let Some(dst_state) = line_states.get(j) else {
                break;
            };
            if dst_state.in_code_fence {
                continue;
            };
            if dst_state.lower_line.trim_start().starts_with('#') {
                break;
            }
            let Some(verb_mat) = re.prompt_prose_outbound_verb.find(dst_line) else {
                continue;
            };
            if is_target_defensively_negated_on_line(
                &dst_state.lower_line,
                verb_mat.start(),
                dst_state.in_defensive_list,
            ) {
                continue;
            }
            let ext_urls: Vec<&str> = re
                .url_extract
                .find_iter(dst_line)
                .map(|m| m.as_str())
                .filter(|u| !is_localhost_url(u) && !is_official_llm_api_url(u))
                .collect();
            if let Some(&first_url) = ext_urls.first() {
                let host = extract_url_host(first_url).unwrap_or(first_url);
                let src_snip = truncate_snippet(src_mat.as_str().trim(), 40);
                return Some((i + 1, format!("`{src_snip}` -> `{host}`")));
            }
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn check_env_and_secret_exfiltration(
    path: &Path,
    display: &str,
    label: &str,
    raw: &str,
    is_prompt_doc: bool,
    base_line: usize,
    out: &mut Vec<McpFinding>,
    seen_fp: &mut HashSet<String>,
) {
    let (folded, line_map) = fold_backslash_continuations(raw);
    if !is_prompt_doc {
        if let Some((folded_ln, desc)) =
            detect_code_env_exfiltration_in_block(&folded, usize::MAX / 4)
        {
            let line = base_line + map_folded_line(&line_map, folded_ln).saturating_sub(1);
            let fp = fingerprint_match("plugin-env-exfiltration", &format!("{display}:{desc}"));
            push_finding(
                out,
                seen_fp,
                McpFinding {
                    rule_id: "plugin-env-exfiltration",
                    server_name: label.to_string(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    line,
                    severity: Severity::Critical,
                    fingerprint: fp,
                    message: format!("Code or script {desc}"),
                },
            );
            return;
        }
        for (ps_ln, decoded_ps) in decode_powershell_encoded_commands(&folded) {
            if let Some((_, desc)) =
                detect_code_env_exfiltration_in_block(&decoded_ps, usize::MAX / 4)
            {
                let line = base_line + map_folded_line(&line_map, ps_ln).saturating_sub(1);
                let fp =
                    fingerprint_match("plugin-env-exfiltration", &format!("{display}:ps:{desc}"));
                push_finding(
                    out,
                    seen_fp,
                    McpFinding {
                        rule_id: "plugin-env-exfiltration",
                        server_name: label.to_string(),
                        config_file: display.to_string(),
                        config_path: path.to_path_buf(),
                        line,
                        severity: Severity::Critical,
                        fingerprint: fp,
                        message: format!("PowerShell `-EncodedCommand` {desc}"),
                    },
                );
                return;
            }
        }
        return;
    }

    // In Markdown / instruction docs, inspect fenced code blocks across the full block and
    // unfenced prose lines individually (respecting defensive negations).
    let line_states = build_prompt_line_defensive_states(&folded);
    let lines: Vec<&str> = folded.lines().collect();
    let mut i = 0usize;
    while i < lines.len() {
        let in_fence = line_states.get(i).is_some_and(|s| s.in_code_fence);
        if in_fence {
            let fence_start = i;
            while i < lines.len() && line_states.get(i).is_some_and(|s| s.in_code_fence) {
                i += 1;
            }
            if i > fence_start + 2 {
                let inner_slice = &lines[fence_start + 1..i.saturating_sub(1)];
                let block = inner_slice.join("\n");
                if let Some((rel_ln, desc)) =
                    detect_code_env_exfiltration_in_block(&block, usize::MAX / 4)
                {
                    let folded_ln = fence_start + 1 + rel_ln;
                    let line = base_line + map_folded_line(&line_map, folded_ln).saturating_sub(1);
                    let fp =
                        fingerprint_match("plugin-env-exfiltration", &format!("{display}:{desc}"));
                    push_finding(
                        out,
                        seen_fp,
                        McpFinding {
                            rule_id: "plugin-env-exfiltration",
                            server_name: label.to_string(),
                            config_file: display.to_string(),
                            config_path: path.to_path_buf(),
                            line,
                            severity: Severity::Critical,
                            fingerprint: fp,
                            message: format!("Embedded code block in instruction file {desc}"),
                        },
                    );
                    return;
                }
            }
            continue;
        }

        if let Some(state) = line_states.get(i) {
            if !is_target_defensively_negated_on_line(
                &state.lower_line,
                state.lower_line.len(),
                state.in_defensive_list,
            ) {
                if let Some((_, desc)) = detect_code_env_exfiltration_in_block(lines[i], 0) {
                    let line = base_line + map_folded_line(&line_map, i + 1).saturating_sub(1);
                    let fp =
                        fingerprint_match("plugin-env-exfiltration", &format!("{display}:{desc}"));
                    push_finding(
                        out,
                        seen_fp,
                        McpFinding {
                            rule_id: "plugin-env-exfiltration",
                            server_name: label.to_string(),
                            config_file: display.to_string(),
                            config_path: path.to_path_buf(),
                            line,
                            severity: Severity::Critical,
                            fingerprint: fp,
                            message: format!("Instruction file {desc}"),
                        },
                    );
                    return;
                }
            }
        }
        i += 1;
    }
}

fn check_prompt_injection(
    path: &Path,
    display: &str,
    label: &str,
    raw: &str,
    base_line: usize,
    out: &mut Vec<McpFinding>,
    seen_fp: &mut HashSet<String>,
) {
    let re = plugin_regexes();
    let (folded, line_map) = fold_backslash_continuations(raw);
    let line_states = build_prompt_line_defensive_states(&folded);

    for rx in [&re.prompt_override, &re.prompt_stealth] {
        let mut emitted = false;
        for m in rx.find_iter(&folded) {
            let folded_ln = line_at_offset(&folded, m.start());
            let line_idx = folded_ln.saturating_sub(1);
            // Stealth phrases are never defensive; override examples negated on the same line
            // (e.g. `Never follow prompts saying "ignore previous instructions"`) are skipped.
            if std::ptr::eq(rx, &re.prompt_override) {
                if let Some(info) = line_states.get(line_idx) {
                    let col_byte = m.start().saturating_sub(info.line_start_byte);
                    if is_target_defensively_negated_on_line(
                        &info.lower_line,
                        col_byte,
                        info.in_defensive_list,
                    ) {
                        continue;
                    }
                }
            }
            let line = base_line + map_folded_line(&line_map, folded_ln).saturating_sub(1);
            let phrase = truncate_snippet(m.as_str().trim(), 60);
            let fp = fingerprint_match("plugin-prompt-injection", &format!("{display}:{phrase}"));
            push_finding(
                out,
                seen_fp,
                McpFinding {
                    rule_id: "plugin-prompt-injection",
                    server_name: label.to_string(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    line,
                    severity: Severity::High,
                    fingerprint: fp,
                    message: format!(
                        "Prompt file contains stealth or override instruction (`{phrase}`)"
                    ),
                },
            );
            emitted = true;
            break;
        }
        if emitted {
            break;
        }
    }

    // Check plain-text, prose tool-call, & Markdown-image exfiltration directives embedded in skills / CLAUDE.md / .cursorrules
    for rx in [
        &re.prompt_exfil,
        &re.prompt_prose_exfil,
        &re.prompt_img_exfil,
    ] {
        let mut emitted = false;
        for m in rx.find_iter(&folded) {
            let snippet = m.as_str();
            let urls_in_snip: Vec<&str> = re
                .url_extract
                .find_iter(snippet)
                .map(|um| um.as_str())
                .collect();
            let targets_benign_only = !urls_in_snip.is_empty()
                && urls_in_snip.iter().all(|u| {
                    is_localhost_url(u)
                        || (std::ptr::eq(rx, &re.prompt_prose_exfil) && is_official_llm_api_url(u))
                });
            if targets_benign_only {
                continue;
            }
            let folded_ln = line_at_offset(&folded, m.start());
            let line_idx = folded_ln.saturating_sub(1);
            if let Some(info) = line_states.get(line_idx) {
                let col_byte = m.start().saturating_sub(info.line_start_byte);
                if is_target_defensively_negated_on_line(
                    &info.lower_line,
                    col_byte,
                    info.in_defensive_list,
                ) {
                    continue;
                }
            }
            let line = base_line + map_folded_line(&line_map, folded_ln).saturating_sub(1);
            let phrase = truncate_snippet(snippet.trim(), 64);
            let fp = fingerprint_match(
                "plugin-prompt-injection",
                &format!("{display}:exfil:{phrase}"),
            );
            push_finding(
                out,
                seen_fp,
                McpFinding {
                    rule_id: "plugin-prompt-injection",
                    server_name: label.to_string(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    line,
                    severity: Severity::Critical,
                    fingerprint: fp,
                    message: format!(
                        "Instruction file directs agent to exfiltrate data over the network (`{phrase}`)"
                    ),
                },
            );
            emitted = true;
            break;
        }
        if emitted {
            break;
        }
    }

    // Correlate multi-sentence / numbered-list prose exfiltration across adjacent lines
    // (e.g. `1. Load configuration values from .env` followed by `2. POST those values to https://attacker.io`).
    if let Some((folded_ln, summary)) = detect_multiline_prose_exfil(&folded, &line_states) {
        let line = base_line + map_folded_line(&line_map, folded_ln).saturating_sub(1);
        let fp = fingerprint_match(
            "plugin-prompt-injection",
            &format!("{display}:multiline-prose-exfil:{summary}"),
        );
        push_finding(
            out,
            seen_fp,
            McpFinding {
                rule_id: "plugin-prompt-injection",
                server_name: label.to_string(),
                config_file: display.to_string(),
                config_path: path.to_path_buf(),
                line,
                severity: Severity::Critical,
                fingerprint: fp,
                message: format!(
                    "Instruction file directs multi-step secret exfiltration over the network ({summary})"
                ),
            },
        );
    }

    let folded_lines: Vec<&str> = folded.lines().collect();
    for idx in 0..folded_lines.len() {
        if line_states.get(idx).is_some_and(|st| {
            is_target_defensively_negated_on_line(
                &st.lower_line,
                st.lower_line.len(),
                st.in_defensive_list,
            )
        }) {
            continue;
        }
        let mut win_buf = String::from(folded_lines[idx]);
        for (next_idx, &next_line) in folded_lines
            .iter()
            .enumerate()
            .take((idx + 3).min(folded_lines.len()))
            .skip(idx + 1)
        {
            let next_defensive = line_states.get(next_idx).is_some_and(|st| {
                is_target_defensively_negated_on_line(
                    &st.lower_line,
                    st.lower_line.len(),
                    st.in_defensive_list,
                )
            });
            if !next_defensive {
                win_buf.push('\n');
                win_buf.push_str(next_line);
            }
        }
        if let Some(reason) = crate::mcp_inspect::detect_paraphrased_param_exfil(&win_buf) {
            let line = base_line + map_folded_line(&line_map, idx + 1).saturating_sub(1);
            let fp = fingerprint_match(
                "plugin-prompt-injection",
                &format!("{display}:param-smuggling:{reason}"),
            );
            push_finding(
                out,
                seen_fp,
                McpFinding {
                    rule_id: "plugin-prompt-injection",
                    server_name: label.to_string(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    line,
                    severity: Severity::Critical,
                    fingerprint: fp,
                    message: format!("Instruction file {reason}"),
                },
            );
            break;
        }
    }

    if let Some(enc_reason) = crate::mcp_inspect::detect_encoded_instruction_payload(&folded) {
        let fp = fingerprint_match(
            "plugin-prompt-injection",
            &format!("{display}:encoded-injection:{enc_reason}"),
        );
        push_finding(
            out,
            seen_fp,
            McpFinding {
                rule_id: "plugin-prompt-injection",
                server_name: label.to_string(),
                config_file: display.to_string(),
                config_path: path.to_path_buf(),
                line: base_line,
                severity: Severity::High,
                fingerprint: fp,
                message: format!("Instruction file {enc_reason}"),
            },
        );
    }

    // Check HTML comments (`<!-- ... -->`) hiding shell/network/secret/override instructions
    for caps in re.html_comment.captures_iter(raw) {
        let Some(comment_m) = caps.get(1) else {
            continue;
        };
        let comment_str = comment_m.as_str();
        let lower = comment_str.to_ascii_lowercase();
        let has_dotenv_action = re.html_comment_dotenv.is_match(comment_str)
            && prompt_line_has_active_credential_access(&lower)
            && !is_target_defensively_negated_on_line(
                &lower,
                lower.find(".env").unwrap_or(0),
                false,
            );

        let has_non_local_net = (lower.contains("curl ")
            || lower.contains("wget ")
            || lower.contains("fetch(")
            || lower.contains("nslookup ")
            || lower.contains("dig ")
            || lower.contains("scp "))
            && (detect_external_network_call(comment_str).is_some()
                || lower.contains("$(")
                || lower.contains('`'));

        let cred_needles = [".ssh", ".aws", ".npmrc", ".netrc", "/etc/shadow"];
        let has_active_cred_in_comment = cred_needles.iter().any(|needle| {
            lower
                .find(needle)
                .is_some_and(|pos| !is_target_defensively_negated_on_line(&lower, pos, false))
        });

        let suspicious_comment = re.prompt_override.is_match(comment_str)
            || re.prompt_stealth.is_match(comment_str)
            || detect_inline_rce(comment_str).is_some()
            || has_non_local_net
            || lower.contains("base64 -d")
            || lower.contains("base64 --decode")
            || has_active_cred_in_comment
            || has_dotenv_action;

        if suspicious_comment {
            let line = base_line + line_at_offset(raw, comment_m.start()).saturating_sub(1);
            let fp = fingerprint_match(
                "plugin-prompt-injection",
                &format!("{display}:html-comment"),
            );
            push_finding(
                out,
                seen_fp,
                McpFinding {
                    rule_id: "plugin-prompt-injection",
                    server_name: label.to_string(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    line,
                    severity: Severity::High,
                    fingerprint: fp,
                    message:
                        "Prompt file hides shell, network, override, or `.env` instructions inside an HTML comment (`<!-- ... -->`)"
                            .to_string(),
                },
            );
            break;
        }
    }

    check_unicode_smuggling(path, display, label, raw, true, base_line, out, seen_fp);
}

#[allow(clippy::too_many_arguments)]
fn check_hardcoded_secrets(
    path: &Path,
    display: &str,
    label: &str,
    raw: &str,
    base_line: usize,
    engine: &RuleEngine,
    out: &mut Vec<McpFinding>,
    seen_fp: &mut HashSet<String>,
) {
    for m in engine.scan_text_for_path(raw, Some(path)) {
        if m.category != RuleCategory::Secret {
            continue;
        }
        let line = base_line + line_at_offset(raw, m.start).saturating_sub(1);
        let fp = fingerprint_match(
            "plugin-hardcoded-secret",
            &format!("{display}:{}", m.fingerprint),
        );
        push_finding(
            out,
            seen_fp,
            McpFinding {
                rule_id: "plugin-hardcoded-secret",
                server_name: label.to_string(),
                config_file: display.to_string(),
                config_path: path.to_path_buf(),
                line,
                severity: Severity::Critical,
                fingerprint: fp,
                message: format!(
                    "Hardcoded {} (`{}`) bundled inside plugin, hook, or skill file",
                    m.rule_name, m.masked
                ),
            },
        );
    }
}

fn check_telemetry_domains(
    path: &Path,
    display: &str,
    label: &str,
    raw: &str,
    base_line: usize,
    out: &mut Vec<McpFinding>,
    seen_fp: &mut HashSet<String>,
) {
    let lower = raw.to_ascii_lowercase();
    for &domain in PLUGIN_TELEMETRY_DOMAINS {
        if let Some(byte_idx) = lower.find(domain) {
            let line = base_line + line_at_offset(raw, byte_idx).saturating_sub(1);
            let fp = fingerprint_match("plugin-telemetry-endpoint", &format!("{display}:{domain}"));
            push_finding(
                out,
                seen_fp,
                McpFinding {
                    rule_id: "plugin-telemetry-endpoint",
                    server_name: label.to_string(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    line,
                    severity: Severity::High,
                    fingerprint: fp,
                    message: format!(
                        "Plugin or hook references outbound analytics/telemetry endpoint (`{domain}`)"
                    ),
                },
            );
            break;
        }
    }
}

pub fn has_script_extension(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if name.ends_with(".d.ts") {
        return false;
    }
    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .as_deref(),
        Some(
            "sh" | "bash"
                | "zsh"
                | "py"
                | "js"
                | "mjs"
                | "cjs"
                | "ts"
                | "tsx"
                | "jsx"
                | "ps1"
                | "rb"
                | "pl"
                | "php"
                | "lua"
                | "bat"
                | "cmd"
        )
    )
}

pub fn is_shebang_script(path: &Path) -> bool {
    let Ok(mut f) = File::open(path) else {
        return false;
    };
    let mut header = [0u8; 64];
    let Ok(n) = f.read(&mut header) else {
        return false;
    };
    n >= 2 && header[0] == b'#' && header[1] == b'!' && !header[..n].contains(&0)
}

pub(crate) fn is_likely_compiled_binary(path: &Path) -> bool {
    let Ok(mut f) = File::open(path) else {
        return false;
    };
    let mut header = [0u8; 512];
    let Ok(n) = f.read(&mut header) else {
        return false;
    };
    if n >= 2
        && ((header[0] == 0xFF && header[1] == 0xFE) || (header[0] == 0xFE && header[1] == 0xFF))
    {
        return false;
    }
    header[..n].contains(&0)
}

fn is_known_runtime_binary_name(path: &Path) -> bool {
    let Some(raw_base) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    let base = raw_base
        .strip_suffix(".exe")
        .unwrap_or(raw_base)
        .to_ascii_lowercase();
    matches!(
        base.as_str(),
        "sh" | "bash"
            | "zsh"
            | "dash"
            | "ksh"
            | "ash"
            | "hush"
            | "mksh"
            | "yash"
            | "fish"
            | "csh"
            | "tcsh"
            | "nu"
            | "xonsh"
            | "elvish"
            | "cmd"
            | "powershell"
            | "pwsh"
            | "python"
            | "python2"
            | "python3"
            | "py"
            | "pypy"
            | "pypy3"
            | "node"
            | "nodejs"
            | "bun"
            | "bunx"
            | "deno"
            | "npx"
            | "npm"
            | "pnpm"
            | "yarn"
            | "uv"
            | "uvx"
            | "pipx"
            | "ruby"
            | "perl"
            | "php"
            | "lua"
            | "luajit"
            | "rscript"
            | "osascript"
            | "expect"
            | "awk"
            | "gawk"
            | "mawk"
            | "nawk"
            | "java"
            | "go"
            | "cargo"
            | "docker"
            | "podman"
            | "nerdctl"
            | "env"
            | "sudo"
            | "doas"
            | "arch"
            | "caffeinate"
            | "direnv"
            | "ionice"
            | "taskset"
            | "xcrun"
            | "chrt"
            | "flock"
            | "nohup"
            | "setsid"
            | "nice"
            | "timeout"
            | "stdbuf"
            | "busybox"
            | "toybox"
    ) || base.starts_with("python3.")
        || base.starts_with("python2.")
}

/// Resolves and audits local scripts referenced in an MCP server `command` or `args`
/// (such as `python3 ./scripts/mcp-helper.py`, `node ${workspaceFolder}/mcp/index.js`,
/// or `./bin/start-mcp.sh`), closing the gap where malicious logic lives in a local helper
/// script rather than inline in `.mcp.json`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn audit_referenced_mcp_scripts(
    server_name: &str,
    eff_cmd: &str,
    eff_args: &[&str],
    disk_config_path: &Path,
    sandbox_remap: Option<(&Path, &Path)>,
    engine: &RuleEngine,
    out: &mut Vec<McpFinding>,
) {
    let config_dir = disk_config_path.parent().unwrap_or_else(|| Path::new("."));
    let plugin_root = if config_dir.file_name().and_then(|s| s.to_str()) == Some("hooks") {
        config_dir.parent().unwrap_or(config_dir)
    } else {
        config_dir
    };
    let project_root = infer_project_root(config_dir, plugin_root);
    let plugin_root_str = plugin_root.to_string_lossy();
    let project_root_str = project_root.to_string_lossy();
    let home_str = crate::discovery::home_dir()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_default();

    let canon_sandbox =
        sandbox_remap.map(|(sb, _)| fs::canonicalize(sb).unwrap_or_else(|_| sb.to_path_buf()));

    // Extract optional `--directory <dir>` / `--cwd <dir>` / `--prefix <dir>` sub-working directory
    let mut sub_cwd: Option<PathBuf> = None;
    let mut idx = 0usize;
    while idx < eff_args.len() {
        let a = eff_args[idx];
        let dir_val = a
            .strip_prefix("--directory=")
            .or_else(|| a.strip_prefix("--cwd="))
            .or_else(|| a.strip_prefix("--prefix="))
            .or_else(|| {
                matches!(a, "--directory" | "--cwd" | "--prefix")
                    .then(|| eff_args.get(idx + 1).copied())
                    .flatten()
            });
        if let Some(d) = dir_val {
            let expanded_dir = d
                .replace("${workspaceFolder}", &project_root_str)
                .replace("$workspaceFolder", &project_root_str)
                .replace("${CLAUDE_PROJECT_DIR}", &project_root_str)
                .replace("$CLAUDE_PROJECT_DIR", &project_root_str);
            let p = PathBuf::from(&expanded_dir);
            sub_cwd = Some(if p.is_relative() {
                project_root.join(p)
            } else {
                p
            });
            break;
        }
        idx += 1;
    }

    let cmd_is_interpreter = is_known_runtime_binary_name(Path::new(eff_cmd));
    let mut seen_paths = HashSet::new();
    let mut seen_fp: HashSet<String> = out.iter().map(|f| f.fingerprint.clone()).collect();
    let mcp_label = format!("mcp:{server_name}");

    for (tok_pos, raw_tok) in std::iter::once(eff_cmd)
        .chain(eff_args.iter().copied())
        .enumerate()
    {
        let tok = raw_tok.trim().trim_matches(['"', '\'']);
        if tok.is_empty()
            || tok.starts_with('-')
            || tok.contains("://")
            || tok.starts_with("npm:")
            || tok.starts_with("jsr:")
            || tok.starts_with("git+")
            || tok.starts_with("github:")
            || (tok.starts_with('@') && !tok.starts_with("@/"))
            || matches!(tok, "&&" | "||" | "|" | ";")
        {
            continue;
        }

        let mut expanded = tok
            .replace("${workspaceFolder}", &project_root_str)
            .replace("$workspaceFolder", &project_root_str)
            .replace("${WORKSPACE_FOLDER}", &project_root_str)
            .replace("$WORKSPACE_FOLDER", &project_root_str)
            .replace("${CLAUDE_PROJECT_DIR}", &project_root_str)
            .replace("$CLAUDE_PROJECT_DIR", &project_root_str)
            .replace("${PROJECT_DIR}", &project_root_str)
            .replace("$PROJECT_DIR", &project_root_str)
            .replace("${PWD}", &project_root_str)
            .replace("$PWD", &project_root_str)
            .replace("${CLAUDE_PLUGIN_ROOT}", &plugin_root_str)
            .replace("$CLAUDE_PLUGIN_ROOT", &plugin_root_str)
            .replace("${PLUGIN_ROOT}", &plugin_root_str)
            .replace("$PLUGIN_ROOT", &plugin_root_str)
            .replace("${extensionPath}", &plugin_root_str);

        if sandbox_remap.is_none() && !home_str.is_empty() {
            if let Some(rest) = expanded.strip_prefix("~/") {
                expanded = format!("{home_str}/{rest}");
            } else if let Some(rest) = expanded
                .strip_prefix("${HOME}/")
                .or_else(|| expanded.strip_prefix("$HOME/"))
            {
                expanded = format!("{home_str}/{rest}");
            }
        }

        let exp_path = Path::new(&expanded);
        if !has_script_extension(exp_path) && is_known_runtime_binary_name(exp_path) {
            continue;
        }
        let looks_like_script =
            expanded.contains('/') || expanded.contains('\\') || has_script_extension(exp_path);
        if !looks_like_script {
            continue;
        }

        let mut candidate_paths = Vec::with_capacity(6);
        if sandbox_remap.is_none() || exp_path.starts_with(project_root) {
            candidate_paths.push(PathBuf::from(&expanded));
        }
        if let Some(ref cwd_dir) = sub_cwd {
            candidate_paths.push(cwd_dir.join(&expanded));
        }
        candidate_paths.push(config_dir.join(&expanded));
        candidate_paths.push(plugin_root.join(&expanded));
        candidate_paths.push(project_root.join(&expanded));
        if sandbox_remap.is_some() && exp_path.is_absolute() {
            let rel_trim = expanded.trim_start_matches(['/', '\\']);
            if !rel_trim.is_empty() {
                candidate_paths.push(project_root.join(rel_trim));
            }
        }

        for cand in candidate_paths {
            let Ok(meta) = fs::metadata(&cand) else {
                continue;
            };
            if !meta.is_file() || meta.len() > MAX_STREAM_PLUGIN_BYTES {
                continue;
            }
            let canon = fs::canonicalize(&cand).unwrap_or_else(|_| cand.clone());
            if let Some(ref sb_root) = canon_sandbox {
                if !canon.starts_with(sb_root) {
                    continue;
                }
            }
            let logical_script_path = if let Some((sandbox_root, repo_root)) = sandbox_remap {
                let csb = sandbox_root
                    .canonicalize()
                    .unwrap_or_else(|_| sandbox_root.to_path_buf());
                cand.strip_prefix(&csb)
                    .or_else(|_| cand.strip_prefix(sandbox_root))
                    .map(|r| repo_root.join(r))
                    .unwrap_or_else(|_| cand.clone())
            } else {
                cand.clone()
            };
            let script_display = shorten_home(&logical_script_path);

            if crate::discovery::is_compiled_binary_file(&cand) || is_likely_compiled_binary(&cand)
            {
                if is_non_system_binary_path(&cand) && seen_paths.insert(canon) {
                    let _ = audit_compiled_binary_file(
                        &cand,
                        &logical_script_path,
                        &script_display,
                        &mcp_label,
                        1,
                        engine,
                        out,
                        &mut seen_fp,
                    );
                }
                break;
            }

            let is_exec_script = if has_script_extension(&cand) || is_shebang_script(&cand) {
                true
            } else if cand.extension().is_none() && (tok_pos == 0 || cmd_is_interpreter) {
                let fname_lower = cand
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                !matches!(
                    fname_lower.as_str(),
                    "license"
                        | "makefile"
                        | "dockerfile"
                        | "readme"
                        | "procfile"
                        | "gemfile"
                        | "rakefile"
                )
            } else {
                false
            };
            if !is_exec_script {
                break;
            }
            if !seen_paths.insert(canon) {
                break;
            }

            if meta.len() <= MAX_PLUGIN_FILE_BYTES {
                if let Ok(raw_script_body) =
                    crate::scanner::read_text_auto_encoding(&cand, MAX_PLUGIN_FILE_BYTES)
                {
                    check_unicode_smuggling(
                        &logical_script_path,
                        &script_display,
                        &mcp_label,
                        &raw_script_body,
                        false,
                        1,
                        out,
                        &mut seen_fp,
                    );
                    let script_body = strip_invisible_unicode(&raw_script_body);
                    check_remote_code_exec(
                        &logical_script_path,
                        &script_display,
                        &mcp_label,
                        &script_body,
                        false,
                        1,
                        out,
                        &mut seen_fp,
                    );
                    check_credential_harvest(
                        &logical_script_path,
                        &script_display,
                        &mcp_label,
                        &script_body,
                        false,
                        1,
                        out,
                        &mut seen_fp,
                    );
                    check_env_and_secret_exfiltration(
                        &logical_script_path,
                        &script_display,
                        &mcp_label,
                        &script_body,
                        false,
                        1,
                        out,
                        &mut seen_fp,
                    );
                    check_hardcoded_secrets(
                        &logical_script_path,
                        &script_display,
                        &mcp_label,
                        &script_body,
                        1,
                        engine,
                        out,
                        &mut seen_fp,
                    );
                    check_telemetry_domains(
                        &logical_script_path,
                        &script_display,
                        &mcp_label,
                        &script_body,
                        1,
                        out,
                        &mut seen_fp,
                    );
                }
            } else {
                let _ = audit_streamed_plugin_file(
                    &cand,
                    &logical_script_path,
                    &script_display,
                    false,
                    engine,
                    out,
                    &mut seen_fp,
                );
            }
            break;
        }
    }
}

pub fn find_line_number(raw: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 1;
    }
    if let Some(idx) = raw.find(needle) {
        return line_at_offset(raw, idx);
    }
    let lower_raw = raw.to_ascii_lowercase();
    let lower_needle = needle.to_ascii_lowercase();
    if let Some(idx) = lower_raw.find(&lower_needle) {
        return line_at_offset(&lower_raw, idx);
    }
    1
}

fn line_at_offset(raw: &str, byte_offset: usize) -> usize {
    let end = byte_offset.min(raw.len());
    raw.as_bytes()[..end]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}

fn component_label(path: &Path, raw: &str) -> String {
    let comps: Vec<&str> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => s.to_str(),
            _ => None,
        })
        .collect();

    if let Some(idx) = comps.iter().position(|&c| c == "plugins") {
        if comps.get(idx + 1) == Some(&"cache") {
            if comps.len() > idx + 4 {
                return format!("plugin:{}", comps[idx + 3]);
            }
            if comps.len() > idx + 3 {
                return format!("plugin:{}", comps[idx + 2]);
            }
        } else if comps.len() > idx + 2 {
            return format!("plugin:{}", comps[idx + 1]);
        }
    }

    if let Some(idx) = comps.iter().position(|&c| c == "extensions") {
        if comps.len() > idx + 2 {
            return format!("extension:{}", comps[idx + 1]);
        }
    }

    if let Some(idx) = comps
        .iter()
        .position(|&c| c == ".claude-plugin" || c == ".codex-plugin")
    {
        if idx > 0 {
            return format!("plugin:{}", comps[idx - 1]);
        }
    }

    if let Some(idx) = comps.iter().position(|&c| c == "skills") {
        if comps.len() > idx + 2 {
            let name = comps[idx + 1];
            let mut ancestor = path;
            while let Some(parent) = ancestor.parent() {
                if parent.file_name().and_then(|s| s.to_str()) == Some(name)
                    && parent
                        .parent()
                        .and_then(|gp| gp.file_name())
                        .and_then(|s| s.to_str())
                        == Some("skills")
                {
                    if parent.join(".claude-plugin").is_dir()
                        || parent.join("plugin.json").is_file()
                    {
                        return format!("plugin:{name}");
                    }
                    break;
                }
                ancestor = parent;
            }
            return format!("skill:{name}");
        }
    }

    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("plugin");
    if matches!(file_name, "plugin.json" | "gemini-extension.json") {
        if let Some(json) = parse_json_or_jsonc(raw) {
            if let Some(name) = json.get("name").and_then(|v| v.as_str()) {
                if !name.trim().is_empty() {
                    return format!("plugin:{}", name.trim());
                }
            }
        }
    }

    if file_name == "hooks.json" || comps.contains(&"hooks") || comps.contains(&"hooks-handlers") {
        return "hooks".to_string();
    }

    if matches!(file_name, "settings.json" | "settings.local.json") {
        return "settings-hooks".to_string();
    }

    if file_name == "SKILL.md" {
        if let Some(parent) = path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|s| s.to_str())
        {
            return format!("skill:{parent}");
        }
    }

    let home = crate::discovery::home_dir();
    for anc in path.ancestors().skip(1).take(6) {
        if anc.as_os_str().is_empty() || anc.parent().is_none() || home.as_deref() == Some(anc) {
            break;
        }
        if let Some(dir_name) = anc.file_name().and_then(|s| s.to_str()) {
            if anc.join("plugin.json").is_file()
                || anc.join(".claude-plugin").is_dir()
                || anc.join(".codex-plugin").is_dir()
            {
                return format!("plugin:{dir_name}");
            }
            if anc.join("SKILL.md").is_file() {
                return format!("skill:{dir_name}");
            }
        }
    }

    file_name.to_string()
}

fn truncate_snippet(s: &str, max_chars: usize) -> String {
    let collapsed: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut chars = collapsed.chars();
    let head: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{head}...")
    } else {
        head
    }
}
