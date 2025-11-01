
all: execute/collectfwdata execute/compare_fw_listeners execute/nmapscanner

execute/collectfwdata: cmd/collectfwdata/collectfwdata.go pkg/sharedlib/funcs.go
	go build -o execute/collectfwdata cmd/collectfwdata/collectfwdata.go

execute/compare_fw_listeners: cmd/compare_fw_listeners/compare_fw_listeners.go pkg/sharedlib/funcs.go
	go build -o execute/compare_fw_listeners cmd/compare_fw_listeners/compare_fw_listeners.go

execute/nmapscanner: cmd/nmapscanner/nmapscanner.go pkg/sharedlib/funcs.go
	go build -o execute/nmapscanner cmd/nmapscanner/nmapscanner.go

run:
	(cd execute; ./collectfwdata; ./compare_fw_listeners)

clean:
	rm -f execute/*
