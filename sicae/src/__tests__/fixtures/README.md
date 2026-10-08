# SICAE pages, recorded live

Recorded from `http://www.sicae.pt/Consulta.aspx` on 2026-10-08 03:01 UTC with the handler's own GET + POST
(form variant `ctl00$MainContent$ipNipc`). The bodies are byte-for-byte what SICAE sent
(`Content-Type: text/html; charset=utf-8`, `Content-Length` framed, `Server: Microsoft-IIS/6.0`).

| File | NIF | What SICAE answered |
|---|---|---|
| `consulta-get.html` | - | the search page (the same bytes for every GET that day) |
| `post-found-503504564.html` | 503504564 | one results row: EDP COMERCIAL-COMERCIALIZAÇÃO DE ENERGIA, S.A., CAE 35151, secondary 35230 and 35152 |
| `post-no-data-980494796.html` | 980494796 | the results grid with one row, "Não existem dados para o critério de pesquisa indicado." |
| `post-invalid-nipc-123456788.html` | 123456788 | no grid; the error label (class `ClassErro`) "O campo 'NIPC' não é válido" (a bad check digit) |

The company is a large utility on the fixtures allowlist; the pages hold no session data (the session
cookie came in a response header, which is not kept).
