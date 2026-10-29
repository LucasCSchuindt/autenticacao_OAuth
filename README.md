Laboratório de autenticação OAuth

Aplicação web de login com Google e GitHub usando o fluxo OAuth 2.0 (código de autorização com PKCE), com a sessão mantida no servidor. O navegador recebe apenas um cookie opaco: nenhum token de acesso chega ao front-end.

Demo: autenticacao-oauth.pages.dev

O que o projeto faz
Redireciona o usuário para o provedor escolhido (Google ou GitHub) para autenticação.
Trata o retorno (callback) do provedor e cria uma sessão local.
Guarda a sessão em um cookie opaco, sem expor tokens ao navegador.
Mostra na página se existe uma sessão ativa e permite encerrá-la com logout.

Como funciona o fluxo

O usuário clica em Google ou GitHub, que levam para /oauth/login/<provedor>.
O servidor gera state, nonce (Google) e o par PKCE, grava a transação no banco e redireciona para a tela de autorização do provedor.
O provedor devolve o usuário para /oauth/callback/<provedor> com um código de autorização.
O servidor valida a transação, troca o código pelo token e confirma a identidade do usuário.
Uma sessão é criada no banco e o navegador recebe um cookie opaco.
A página consulta /api/me para mostrar o estado da sessão.
Ao clicar em Sair, um POST em /oauth/logout apaga a sessão.

Tecnologias

OAuth 2.0 e OpenID Connect (Google e GitHub)
JavaScript
Cloudflare Pages e Pages Functions
Cloudflare D1 (SQLite) para sessões e transações de login
HTML5 e CSS3, sem frameworks
GitHub Actions (verificação de segredos, migrações e HTML)

Segurança

PKCE (S256), state e nonce em cada login.
ID token do Google validado no servidor: assinatura RS256 com as chaves públicas do provedor, além de iss, aud, exp, iat e nonce.
Token do GitHub descartado: é usado uma única vez para ler a identidade e a autorização é revogada antes de criar a sessão.
Cookie __Host- com HttpOnly, Secure e SameSite=Strict na sessão. Ele não contém dados do usuário nem tokens.
IDs de sessão e de transação guardados como hash SHA-256 no banco, nunca em texto puro.
Transações de login de uso único, com validade de 10 minutos. Sessões expiram em 8 horas.
Logout protegido: aceita apenas POST e confere o cabeçalho Origin.
Erros do fluxo de login não expõem detalhes internos ao usuário; os motivos ficam só nos logs do servidor.
Credenciais dos provedores ficam fora do código, em variáveis de ambiente do Cloudflare.

Estrutura
public/        página estática (HTML, CSS e JS do front-end)
functions/
  api/         /api/me e /api/health
  oauth/       login, callback e logout
  _shared/     cookies, criptografia, provedores e validação do ID token
migrations/    esquema do banco D1
.github/       verificação automática (CI)

Variáveis de ambiente

Configure no painel do Cloudflare Pages (Settings → Variables and Secrets). Nunca coloque esses valores no repositório.

Variável	Descrição
GOOGLE_CLIENT_ID	ID do cliente OAuth do Google
GOOGLE_CLIENT_SECRET	Segredo do cliente OAuth do Google
GITHUB_CLIENT_ID	ID do cliente do OAuth App do GitHub
GITHUB_CLIENT_SECRET	Segredo do cliente do OAuth App do GitHub
PUBLIC_BASE_URL	URL pública do site, sem barra no final (ex.: https://autenticacao-oauth.pages.dev)

O que aprendi

Funcionamento do fluxo OAuth 2.0 com código de autorização, PKCE e OpenID Connect.
Diferenças entre os provedores Google e GitHub na integração.
Gerenciamento de sessão no servidor e boas práticas com cookies.
Validação de ID token e proteção contra ataques comuns (CSRF, reutilização de código, fixação de sessão).
Tratamento de falhas no callback sem vazar informação ao usuário.
