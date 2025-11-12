
all: execute/collectfwdata execute/webserver execute/collectfwdata execute/utils

execute/utils: cmd/utils/utils.go pkg/sharedlib/parse.go pkg/sharedlib/database.go pkg/sharedlib/report.go
	go build -o execute/utils cmd/utils/utils.go

execute/webserver: cmd/webserver/webserver.go pkg/sharedlib/parse.go pkg/sharedlib/database.go pkg/sharedlib/report.go
	go build -o execute/webserver cmd/webserver/webserver.go

execute/collectfwdata: cmd/collectfwdata/collectfwdata.go pkg/sharedlib/parse.go pkg/sharedlib/database.go pkg/sharedlib/report.go
	go build -o execute/collectfwdata cmd/collectfwdata/collectfwdata.go

run:
	(cd execute; ./collectfwdata; ./compare_fw_listeners)

clean:
	rm -f execute/*
