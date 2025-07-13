module github.com/zoobzio/sctx/demo

go 1.23.1

replace github.com/zoobzio/sctx => ../
replace github.com/zoobzio/sctx/processors/security => ../processors/security
replace github.com/zoobzio/sctx/processors/token => ../processors/token

require (
	github.com/zoobzio/sctx v0.0.0-00010101000000-000000000000
	github.com/zoobzio/sctx/processors/security v0.0.0-00010101000000-000000000000
)

require github.com/zoobzio/pipz v0.0.1 // indirect
