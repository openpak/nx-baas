module nx-baas

go 1.24

require (
	google.golang.org/grpc v1.75.1
	openpak/account v0.0.0
)

require (
	golang.org/x/net v0.42.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	golang.org/x/text v0.28.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250707201910-8d1bb00bc6a7 // indirect
	google.golang.org/protobuf v1.36.9 // indirect
)

replace openpak/account => ../account
