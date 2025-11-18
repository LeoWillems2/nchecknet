
all: bin/webserver bin/collector bin/utils bin/testers

bin/utils: cmd/utils/utils.go pkg/sharedlib/parse.go pkg/sharedlib/database.go pkg/sharedlib/report.go
	go build -o bin/utils cmd/utils/utils.go

bin/testers: cmd/testers/testers.go pkg/sharedlib/parse.go pkg/sharedlib/database.go pkg/sharedlib/report.go
	go build -o bin/testers cmd/testers/testers.go

bin/webserver: cmd/webserver/webserver.go pkg/sharedlib/parse.go pkg/sharedlib/database.go pkg/sharedlib/report.go
	go build -o bin/webserver cmd/webserver/webserver.go

bin/collector: cmd/collector/collector.go pkg/sharedlib/parse.go pkg/sharedlib/database.go
	go build -o bin/collector cmd/collector/collector.go

clean:
	rm -f bin/*
