module github.com/LeoWillems2/nchecknet/v2

replace (
	github.com/LeoWillems2/nchecknet/pkg/sharedlib => ./pkg/sharedlib

)

go 1.23.4

require github.com/LeoWillems2/nchecknet/pkg/sharedlib v0.0.0-00010101000000-000000000000
