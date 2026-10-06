Laboratório de autenticação OAuth

Aplicação web de login com Google e GitHub usando o fluxo OAuth 2.0, com sessão mantida no servidor. O navegador recebe apenas um cookie opaco: nenhum token de acesso chega ao front-end.

Demo: autenticacao-oauth.pages.dev

O que o projeto faz
Redireciona o usuário para o provedor escolhido (Google ou GitHub) para autenticação.
Trata o retorno (callback) do provedor e cria uma sessão local.
Guarda a sessão em cookie opaco, sem expor tokens ao navegador.
Mostra na página se existe uma sessão ativa e permite encerrá-la com logout.

Como funciona o fluxo
O usuário clica em Google ou GitHub, que levam para /oauth/login/<provedor>.
O servidor redireciona para a tela de autorização do provedor.
O provedor devolve o usuário ao callback com um código de autorização.
O servidor troca o código pelo token, cria a sessão e grava um cookie opaco.
A página consulta o estado da sessão e atualiza o indicador de status.
Ao clicar em Sair, um POST em /oauth/logout encerra a sessão.

Tecnologias
OAuth 2.0 (Google e GitHub)
JavaScript
Cloudflare Pages e Pages Functions
HTML5 e CSS3, sem frameworks

Segurança
Tokens de acesso ficam apenas no servidor.
A sessão usa cookie opaco, que não contém dados do usuário nem tokens.
Credenciais dos provedores ficam fora do código, em variáveis de ambiente do Cloudflare Pages.

O que aprendi
Funcionamento do fluxo OAuth 2.0 com código de autorização.
Diferenças entre os provedores Google e GitHub na integração.
Gerenciamento de sessão no servidor e boas práticas com cookies.
Tratamento de falhas no callback de autenticação.
