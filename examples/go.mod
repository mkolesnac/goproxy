module github.com/mkolesnac/goproxy/examples/goproxy-transparent

go 1.23rc2

require (
	github.com/elazarl/goproxy v0.0.0-20181111060418-2ce16c963a8a
	github.com/inconshreveable/go-vhost v0.0.0-20160627193104-06d84117953b
)

replace github.com/elazarl/goproxy => ../
