module github.com/derecalliance/lib-derec/bindings/go

go 1.23

require (
	github.com/derecalliance/lib-derec/packages/go v0.0.0-00010101000000-000000000000
	google.golang.org/protobuf v1.36.11
)

require github.com/ebitengine/purego v0.10.2 // indirect

replace github.com/derecalliance/lib-derec/packages/go => ../../packages/go
