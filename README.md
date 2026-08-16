# gcp_utils

**Deprecated.** This repository is archived and no longer developed. Nothing in it was specific to
Google Cloud by the end, and what remained of use has been moved:

| What | Where it lives now |
| --- | --- |
| Sessions, single sign-on, magic links, passkeys, and the accounts they authenticate | [altshiftab/authentication_go](https://github.com/altshiftab/authentication_go) |
| Client code generation | [Motmedel/utils_go](https://github.com/Motmedel/utils_go) — `pkg/http/client_code_generation` |
| The HTTP context extractor, the logger and its entry size guard | `Motmedel/utils_go` — `pkg/http/types/http_context_extractor`, `pkg/log/http_logger`, `pkg/log/entry_size_guard` |
| The HTTP service, and what it answers with | `Motmedel/utils_go` — `pkg/http/service` |

A service set up through this repository is set up through `utils_go`'s service instead, which
decides what it answers with from the kind of service it is; see `pkg/http/service/service_config`.
