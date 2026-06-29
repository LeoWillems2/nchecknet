
all: bin/webserver bin/collector bin/utils bin/testers

bin/utils: cmd/utils/utils.go pkg/sharedlib/parse.go pkg/sharedlib/database.go pkg/sharedlib/report.go pkg/sharedlib/yaml.go
	go build -o bin/utils cmd/utils/utils.go

bin/testers: cmd/testers/testers.go pkg/sharedlib/parse.go pkg/sharedlib/database.go pkg/sharedlib/report.go pkg/sharedlib/yaml.go
	go build -o bin/testers cmd/testers/testers.go

bin/webserver: cmd/webserver/webserver.go pkg/sharedlib/parse.go pkg/sharedlib/database.go pkg/sharedlib/report.go pkg/sharedlib/yaml.go
	go build -o bin/webserver cmd/webserver/webserver.go

bin/collector: cmd/collector/collector.go pkg/sharedlib/parse.go pkg/sharedlib/database.go pkg/sharedlib/yaml.go pkg/sharedlib/report.go
	go build -o bin/collector cmd/collector/collector.go

installbin:
	sudo systemctl stop nchecknet
	sudo systemctl stop webnchecknet
	sleep 3
	sudo cp bin/collector /usr/local/bin/nchecknetcollector
	sudo cp bin/webserver /usr/local/bin/nchecknetwebserver
	sudo cp bin/utils /usr/local/bin/nchecknet_utils
	sudo systemctl start nchecknet
	sudo systemctl start webnchecknet

installweb:
	sudo pax -pe  -rw webroot /usr/local/share
	sudo rm -rf /usr/local/share/nchecknetwebroot
	sudo mv /usr/local/share/webroot /usr/local/share/nchecknetwebroot

clean:
	rm -f bin/*
