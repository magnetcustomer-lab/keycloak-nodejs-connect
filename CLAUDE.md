# CLAUDE.md - keycloak-nodejs-connect

Fork do adapter oficial Keycloak para Node.js/Express. Customizado com metricas de validacao de token, retry em JWKS fetch e melhorias especificas para o MagnetCustomer.

## Stack

| Tecnologia | Uso |
|------------|-----|
| Node.js (18/20/22+) | Runtime |
| Express middleware | Integracao |
| jsonwebtoken + jwk-to-pem | Validacao JWT |
| tape | Framework de testes |
| standard | Linter |

## Comandos

```bash
npm run lint             # StandardJS linter
npm run test             # Executa run-tests.sh (tape)
npm run coverage         # Cobertura com nyc
npm run docs             # Gerar docs com jsdoc
npm run server:start     # Iniciar Keycloak local para testes
```

## Branch Principal

`main` (upstream: `keycloak/keycloak-nodejs-connect`)

## Estrutura

```
keycloak.js                    # Classe principal Keycloak - configura middleware chain
keycloak.d.ts                  # TypeScript definitions
middleware/
  setup.js                     # Inicializacao e configuracao de sessao
  admin.js                     # Admin callbacks (logout webhook)
  protect.js                   # Middleware protect() - exige autenticacao
  enforcer.js                  # Enforcer de permissoes (UMA)
  grant-attacher.js            # Anexa grant ao request
  check-sso.js                 # Verifica SSO silencioso
  logout.js                    # Handler de logout
  post-auth.js                 # Hook pos-autenticacao
  auth-utils/
    config.js                  # Parser de keycloak.json
    grant-manager.js           # Gerenciamento de grants (tokens)
    grant.js                   # Modelo Grant (access/refresh/id token)
    token.js                   # Modelo Token (decode, isExpired, hasPermission)
    rotation.js                # Rotacao de chaves JWKS
    signature.js               # Verificacao de assinatura JWT
    metrics.js                 # KeycloakMetrics - contadores e histogramas
stores/
  bearer-store.js              # Store via Authorization header
  cookie-store.js              # Store via cookies
  session-store.js             # Store via express-session
test/                          # Testes unitarios e integracao (tape)
```

## Customizacoes MagnetCustomer

- **metrics.js** - `KeycloakMetrics` com contadores para: tokenValidations, tokenRefresh, jwksFetch, httpRequests. Histogramas de duracao.
- Upstream: `keycloak/keycloak-nodejs-connect` (remotes/upstream/)
- Usado como dependencia via GitHub: `github:magnetcustomer/keycloak-nodejs-connect`

## Publicacao

Nao publicado no npm. Consumido diretamente via GitHub URL nos `package.json` dos servicos:
```json
"keycloak-connect": "github:magnetcustomer/keycloak-nodejs-connect"
```

## Cuidados

- **Nao quebrar retrocompatibilidade** - todos os servicos MagnetCustomer dependem deste pacote
- Manter compatibilidade com API do `keycloak-connect` original
- Testar com `npm run test` antes de qualquer merge em `main`
- Merges do upstream devem ser feitos com cuidado para nao sobrescrever customizacoes
