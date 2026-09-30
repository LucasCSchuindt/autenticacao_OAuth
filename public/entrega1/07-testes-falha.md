Preparação: Iniciei o login com Google em uma janela comum e parei na tela de escolha de conta do provedor, sem concluir.
Pedido enviado: Copiei a URL de autorização do Google e a abri em uma janela privativa (anônima), que não possuía o cookie __Host-oauth-tx, e concluí o login nela.
Resultado esperado: A rota de retorno deveria recusar a resposta e não criar uma sessão, por ausência do cookie de transação.
Resultado observado: A página retornou "Falha na autenticação" (motivo: cookie de transação ausente na requisição). Nenhuma sessão foi criada.
