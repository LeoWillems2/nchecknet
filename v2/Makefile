
all: bin/collectfwdata bin/webserver bin/collectfwdata bin/utils bin/testers

bin/utils: cmd/utils/utils.go pkg/sharedlib/parse.go pkg/sharedlib/database.go pkg/sharedlib/report.go
	go build -o bin/utils cmd/utils/utils.go

bin/testers: cmd/testers/testers.go pkg/sharedlib/parse.go pkg/sharedlib/database.go pkg/sharedlib/report.go
	go build -o bin/testers cmd/testers/testers.go

bin/webserver: cmd/webserver/webserver.go pkg/sharedlib/parse.go pkg/sharedlib/database.go pkg/sharedlib/report.go
	go build -o bin/webserver cmd/webserver/webserver.go

bin/collectfwdata: cmd/collectfwdata/collectfwdata.go pkg/sharedlib/parse.go pkg/sharedlib/database.go pkg/sharedlib/report.go
	go build -o bin/collectfwdata cmd/collectfwdata/collectfwdata.go

run:
	(cd bin; ./collectfwdata; ./compare_fw_listeners)

clean:
	rm -f bin/*
